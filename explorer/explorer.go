package explorer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	BitcoinExplorer     = "bitcoin"
	pongInterval        = 60 * time.Second
	pingInterval        = (pongInterval * 9) / 10
	defaultPollInterval = 10 * time.Second
)

var (
	defaultExplorerUrls = utils.SupportedType[string]{
		arklib.Bitcoin.Name:        "https://mempool.space/api",
		arklib.BitcoinTestNet.Name: "https://mempool.space/testnet/api",
		//arklib.BitcoinTestNet4.Name: "https://mempool.space/testnet4/api", //TODO uncomment once supported
		arklib.BitcoinSigNet.Name:    "https://mempool.space/signet/api",
		arklib.BitcoinMutinyNet.Name: "https://mutinynet.com/api",
		arklib.BitcoinRegTest.Name:   "http://localhost:3000",
	}
)

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txs ...string) (string, error)
	GetTxs(addr string) ([]tx, error)
	GetTxOutspends(tx string) ([]spentStatus, error)
	GetUtxos(addr string) ([]Utxo, error)
	GetRedeemedVtxosBalance(
		addr string, unilateralExitDelay arklib.RelativeLocktime,
	) (uint64, map[int64]uint64, error)
	GetTxBlockTime(
		txid string,
	) (confirmed bool, blocktime int64, err error)
	BaseUrl() string
	GetFeeRate() (float64, error)
	GetAddressesEvents() <-chan types.OnchainAddressEvent
	SubscribeForAddresses(addresses []string) error
	UnsubscribeForAddresses(addresses []string) error
	Stop()
}

type addressData struct {
	hash  []byte
	utxos []Utxo
}

type explorerSvc struct {
	cache         *utils.Cache[string]
	baseUrl       string
	net           arklib.Network
	conn          *websocket.Conn
	subscribedMu  *sync.RWMutex
	subscribedMap map[string]addressData
	channel       chan types.OnchainAddressEvent
	stopTracking  func()
	pollInterval  time.Duration
}

type Option func(*explorerSvc)

func WithPollInterval(interval time.Duration) Option {
	return func(svc *explorerSvc) {
		svc.pollInterval = interval
	}
}

func NewExplorer(baseUrl string, net arklib.Network, opts ...Option) (Explorer, error) {
	if len(baseUrl) == 0 {
		baseUrl, ok := defaultExplorerUrls[net.Name]
		if !ok {
			return nil, fmt.Errorf(
				"cannot find default explorer url associated with network %s",
				net.Name,
			)
		}
		return NewExplorer(baseUrl, net, opts...)
	}

	wsURL, err := deriveWsURL(baseUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %s", err)
	}
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(context.Background(), wsURL, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"network": net.Name,
			"url":     wsURL,
		}).WithError(err).Warn("websocket dial failed, falling back to polling")
	}

	ctx, cancel := context.WithCancel(context.Background())
	svc := &explorerSvc{
		cache:         utils.NewCache[string](),
		baseUrl:       baseUrl,
		net:           net,
		conn:          conn,
		subscribedMu:  &sync.RWMutex{},
		subscribedMap: make(map[string]addressData),
		channel:       make(chan types.OnchainAddressEvent, 100),
		stopTracking:  cancel,
		pollInterval:  defaultPollInterval,
	}

	for _, opt := range opts {
		opt(svc)
	}

	if svc.conn == nil {
		log.Debugf(
			"starting explorer background tracking with polling interval %s",
			svc.pollInterval,
		)
	} else {
		log.Debugf("starting explorer background tracking with websocket")
	}
	go svc.startTracking(ctx)

	return svc, nil
}

func (e *explorerSvc) Stop() {
	e.stopTracking()
	if e.conn != nil {
		if err := e.conn.Close(); err != nil {
			log.WithError(err).Error("failed to close websocket connection")
		}
	}
	close(e.channel)
}

func (e *explorerSvc) BaseUrl() string {
	return e.baseUrl
}

func (e *explorerSvc) GetNetwork() arklib.Network {
	return e.net
}

func (e *explorerSvc) GetFeeRate() (float64, error) {
	endpoint, err := url.JoinPath(e.baseUrl, "fee-estimates")
	if err != nil {
		return 0, err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return 0, err
	}
	// nolint:all
	defer resp.Body.Close()

	var response map[string]float64

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("error getting fee rate: %s", resp.Status)
	}

	if len(response) == 0 {
		return 1, nil
	}

	return response["1"], nil
}

func (e *explorerSvc) GetAddressesEvents() <-chan types.OnchainAddressEvent {
	return e.channel
}

func (e *explorerSvc) GetTxHex(txid string) (string, error) {
	if hex, ok := e.cache.Get(txid); ok {
		return hex, nil
	}

	txHex, err := e.getTxHex(txid)
	if err != nil {
		return "", err
	}

	e.cache.Set(txid, txHex)

	return txHex, nil
}

func (e *explorerSvc) Broadcast(txs ...string) (string, error) {
	if len(txs) == 0 {
		return "", fmt.Errorf("no txs to broadcast")
	}

	for _, tx := range txs {
		txStr, txid, err := parseBitcoinTx(tx)
		if err != nil {
			return "", err
		}

		e.cache.Set(txid, txStr)
	}

	if len(txs) == 1 {
		txid, err := e.broadcast(txs[0])
		if err != nil {
			if strings.Contains(
				strings.ToLower(err.Error()), "transaction already in block chain",
			) {
				return txid, nil
			}

			return "", err
		}

		return txid, nil
	}

	// package
	return e.broadcastPackage(txs...)
}

func (e *explorerSvc) broadcastPackage(txs ...string) (string, error) {
	url := fmt.Sprintf("%s/txs/package", e.baseUrl)

	// body is a json array of txs hex
	body := bytes.NewBuffer(nil)
	if err := json.NewEncoder(body).Encode(txs); err != nil {
		return "", err
	}

	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return "", err
	}
	// nolint
	defer resp.Body.Close()

	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to broadcast package: %s", string(bodyResponse))
	}

	return string(bodyResponse), nil
}

func (e *explorerSvc) GetTxs(addr string) ([]tx, error) {
	resp, err := http.Get(fmt.Sprintf("%s/address/%s/txs", e.baseUrl, addr))
	if err != nil {
		return nil, err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}
	payload := []tx{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *explorerSvc) SubscribeForAddresses(addresses []string) error {
	e.subscribedMu.Lock()
	defer e.subscribedMu.Unlock()

	addressesToSubscribe := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if _, ok := e.subscribedMap[addr]; ok {
			continue
		}
		addressesToSubscribe = append(addressesToSubscribe, addr)
	}

	if len(addressesToSubscribe) == 0 {
		return nil
	}

	if e.conn != nil {
		// When adding new addresses we have to resubscribe for the whole new total list of
		// addresses.
		trackAddresses := append([]string{}, addressesToSubscribe...)
		for addr := range e.subscribedMap {
			trackAddresses = append(trackAddresses, addr)
		}
		payload := map[string][]string{"track-addresses": trackAddresses}

		if err := e.conn.WriteJSON(payload); err != nil {
			return fmt.Errorf("failed to subscribe for addresses %s: %s", addressesToSubscribe, err)
		}
	}

	return nil
}

func (e *explorerSvc) UnsubscribeForAddresses(addresses []string) error {
	e.subscribedMu.Lock()
	defer e.subscribedMu.Unlock()

	for _, addr := range addresses {
		delete(e.subscribedMap, addr)
	}

	if e.conn != nil {
		// When unsubscribing we have to resubscribe for the remaining addresses.
		trackAddresses := make([]string, 0, len(e.subscribedMap))
		for addr := range e.subscribedMap {
			trackAddresses = append(trackAddresses, addr)
		}
		payload := map[string][]string{"track-addresses": trackAddresses}

		if err := e.conn.WriteJSON(payload); err != nil {
			return fmt.Errorf("failed to unsubscribe for addresses %s: %s", addresses, err)
		}
	}

	return nil
}

func (e *explorerSvc) GetTxOutspends(txid string) ([]spentStatus, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/outspends", e.baseUrl, txid))
	if err != nil {
		return nil, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}

	spentStatuses := make([]spentStatus, 0)
	if err := json.Unmarshal(body, &spentStatuses); err != nil {
		return nil, err
	}
	return spentStatuses, nil
}

func (e *explorerSvc) GetUtxos(addr string) ([]Utxo, error) {
	decoded, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}

	outputScript, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}

	resp, err := http.Get(fmt.Sprintf("%s/address/%s/utxo", e.baseUrl, addr))
	if err != nil {
		return nil, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get utxos: %s", string(body))
	}
	utxos := []Utxo{}
	if err := json.Unmarshal(body, &utxos); err != nil {
		return nil, err
	}

	for i := range utxos {
		utxos[i].Script = hex.EncodeToString(outputScript)
	}

	return utxos, nil
}

func (e *explorerSvc) GetRedeemedVtxosBalance(
	addr string, unilateralExitDelay arklib.RelativeLocktime,
) (spendableBalance uint64, lockedBalance map[int64]uint64, err error) {
	utxos, err := e.GetUtxos(addr)
	if err != nil {
		return
	}

	lockedBalance = make(map[int64]uint64, 0)
	now := time.Now()
	for _, utxo := range utxos {
		blocktime := now
		if utxo.Status.Confirmed {
			blocktime = time.Unix(utxo.Status.BlockTime, 0)
		}

		delay := time.Duration(unilateralExitDelay.Seconds()) * time.Second
		availableAt := blocktime.Add(delay)
		if availableAt.After(now) {
			if _, ok := lockedBalance[availableAt.Unix()]; !ok {
				lockedBalance[availableAt.Unix()] = 0
			}

			lockedBalance[availableAt.Unix()] += utxo.Amount
		} else {
			spendableBalance += utxo.Amount
		}
	}

	return
}

func (e *explorerSvc) GetTxBlockTime(
	txid string,
) (confirmed bool, blocktime int64, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s", e.baseUrl, txid))
	if err != nil {
		return false, 0, err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("failed to get block time: %s", string(body))
	}

	var tx struct {
		Status struct {
			Confirmed bool  `json:"confirmed"`
			Blocktime int64 `json:"block_time"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &tx); err != nil {
		return false, 0, err
	}

	if !tx.Status.Confirmed {
		return false, -1, nil
	}

	return true, tx.Status.Blocktime, nil
}

func (e *explorerSvc) startTracking(ctx context.Context) {
	// If the ws endpoint is avaialble (mempool.space url), read from websocket and eventually
	// send notifications and periodically send a ping message to keep the connection alive.
	if e.conn != nil {
		// Go routine to listen for addresses updates from websocket.
		go func(ctx context.Context) {
			if err := e.conn.SetReadDeadline(time.Now().Add(pongInterval)); err != nil {
				log.WithError(err).Error("failed to set read deadline")
				return
			}
			e.conn.SetPongHandler(func(string) error {
				return e.conn.SetReadDeadline(time.Now().Add(pongInterval))
			})
			for {
				var payload addressNotification
				if err := e.conn.ReadJSON(&payload); err != nil {
					if websocket.IsCloseError(
						err,
						websocket.CloseNormalClosure,
						websocket.CloseGoingAway,
					) ||
						errors.Is(err, net.ErrClosed) {
						return
					}
					log.WithError(err).Error("failed to read address notification")
					continue
				}
				// Skip handling the received message if it's not an address update.
				if len(payload.MultiAddrTx) == 0 {
					continue
				}

				go e.sendAddressEventFromWs(ctx, payload)
			}
		}(ctx)

		// Go routine to periodically send ping messages and keep the connection alive.
		go func(ctx context.Context) {
			ticker := time.NewTicker(pingInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					deadline := time.Now().Add(10 * time.Second)
					if err := e.conn.WriteControl(
						websocket.PingMessage, nil, deadline,
					); err != nil {
						log.WithError(err).Error("failed to ping explorer")
						return
					}
				}
			}
		}(ctx)

		return
	}

	// Otherwise (esplora url), poll the explorer every 10s and manually send notifications of
	// spent, new and confirmed utxos.
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.subscribedMu.RLock()
			// make a snapshot copy of the map to avoid race conditions
			subscribedMap := make(map[string]addressData, len(e.subscribedMap))
			for addr, data := range e.subscribedMap {
				hashCopy := make([]byte, len(data.hash))
				copy(hashCopy, data.hash)
				utxosCopy := make([]Utxo, len(data.utxos))
				copy(utxosCopy, data.utxos)

				subscribedMap[addr] = addressData{
					hash:  hashCopy,
					utxos: utxosCopy,
				}
			}
			e.subscribedMu.RUnlock()

			if len(subscribedMap) == 0 {
				continue
			}
			for addr, oldUtxos := range subscribedMap {
				newUtxos, err := e.GetUtxos(addr)
				if err != nil {
					log.WithError(err).Error("failed to poll explorer")
				}
				buf, _ := json.Marshal(newUtxos)
				hashedResp := sha256.Sum256(buf)
				if !bytes.Equal(oldUtxos.hash, hashedResp[:]) {
					go e.sendAddressEventFromPolling(ctx, oldUtxos.utxos, newUtxos)
					e.subscribedMu.Lock()
					e.subscribedMap[addr] = addressData{
						hash:  hashedResp[:],
						utxos: newUtxos,
					}
					e.subscribedMu.Unlock()
				}

			}
		case <-ctx.Done():
			return
		}
	}
}

func (e *explorerSvc) sendAddressEventFromWs(ctx context.Context, payload addressNotification) {
	spentUtxos := make([]types.OnchainOutput, 0)
	newUtxos := make([]types.OnchainOutput, 0)
	confirmedUtxos := make([]types.OnchainOutput, 0)
	replacements := make(map[string]string)
	for addr, data := range payload.MultiAddrTx {
		if len(data.Removed) > 0 {
			for _, tx := range data.Removed {
				if len(data.Mempool) > 0 {
					replacementTxid := data.Mempool[0].Txid
					replacements[tx.Txid] = replacementTxid
				}
			}
			continue
		}
		if len(data.Mempool) > 0 {
			for _, tx := range data.Mempool {
				for _, in := range tx.Inputs {
					if in.Prevout.Address == addr {
						spentUtxos = append(spentUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: in.Txid,
								VOut: uint32(in.Vout),
							},
							SpentBy: tx.Txid,
							Spent:   true,
						})
					}
				}
				for i, out := range tx.Outputs {
					if out.Address == addr {
						var createdAt time.Time
						if tx.Status.Confirmed {
							createdAt = time.Unix(tx.Status.BlockTime, 0)
						}
						newUtxos = append(newUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: tx.Txid,
								VOut: uint32(i),
							},
							Script:    out.Script,
							Amount:    out.Amount,
							CreatedAt: createdAt,
						})
					}
				}
			}
		}
		if len(data.Confirmed) > 0 {
			for _, tx := range data.Confirmed {
				for i, out := range tx.Outputs {
					if out.Address == addr {
						confirmedUtxos = append(confirmedUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: tx.Txid,
								VOut: uint32(i),
							},
							Script:    out.Script,
							Amount:    out.Amount,
							CreatedAt: time.Unix(tx.Status.BlockTime, 0),
						})
					}
				}
			}
		}
	}

	e.sendAddressEvent(ctx, types.OnchainAddressEvent{
		NewUtxos:       newUtxos,
		SpentUtxos:     spentUtxos,
		ConfirmedUtxos: confirmedUtxos,
		Replacements:   replacements,
	})
}

func (e *explorerSvc) sendAddressEventFromPolling(ctx context.Context, oldUtxos, newUtxos []Utxo) {
	indexedOldUtxos := make(map[string]Utxo, 0)
	indexedNewUtxos := make(map[string]Utxo, 0)
	for _, oldUtxo := range oldUtxos {
		indexedOldUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)] = oldUtxo
	}
	for _, newUtxo := range newUtxos {
		indexedNewUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)] = newUtxo
	}
	spentUtxos := make([]types.OnchainOutput, 0)
	for _, oldUtxo := range oldUtxos {
		if _, ok := indexedNewUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)]; !ok {
			var spentBy string
			spentStatus, _ := e.GetTxOutspends(oldUtxo.Txid)
			if len(spentStatus) > int(oldUtxo.Vout) {
				spentBy = spentStatus[oldUtxo.Vout].SpentBy
			}
			spentUtxos = append(spentUtxos, types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: oldUtxo.Txid,
					VOut: oldUtxo.Vout,
				},
				SpentBy: spentBy,
				Spent:   true,
			})
		}
	}
	receivedUtxos := make([]types.OnchainOutput, 0)
	confirmedUtxos := make([]types.OnchainOutput, 0)
	for _, newUtxo := range newUtxos {
		oldUtxo, ok := indexedOldUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)]
		if !ok {
			var createdAt time.Time
			if newUtxo.Status.Confirmed {
				createdAt = time.Unix(newUtxo.Status.BlockTime, 0)
			}
			utxo := types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: newUtxo.Txid,
					VOut: newUtxo.Vout,
				},
				Script:    newUtxo.Script,
				Amount:    newUtxo.Amount,
				CreatedAt: createdAt,
			}
			receivedUtxos = append(receivedUtxos, utxo)
			if newUtxo.Status.Confirmed {
				confirmedUtxos = append(confirmedUtxos, utxo)
			}
			continue
		}
		if !oldUtxo.Status.Confirmed && newUtxo.Status.Confirmed {
			confirmedUtxos = append(confirmedUtxos, types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: newUtxo.Txid,
					VOut: newUtxo.Vout,
				},
				Script:    newUtxo.Script,
				Amount:    newUtxo.Amount,
				CreatedAt: time.Unix(newUtxo.Status.BlockTime, 0),
			})
		}
	}

	e.sendAddressEvent(ctx, types.OnchainAddressEvent{
		SpentUtxos:     spentUtxos,
		NewUtxos:       receivedUtxos,
		ConfirmedUtxos: confirmedUtxos,
	})
}

func (e *explorerSvc) getTxHex(txid string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/hex", e.baseUrl, txid))
	if err != nil {
		return "", err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get tx hex: %s", string(body))
	}

	hex := string(body)
	e.cache.Set(txid, hex)
	return hex, nil
}

func (e *explorerSvc) broadcast(txHex string) (string, error) {
	body := bytes.NewBuffer([]byte(txHex))

	resp, err := http.Post(fmt.Sprintf("%s/tx", e.baseUrl), "text/plain", body)
	if err != nil {
		return "", err
	}
	// nolint:all
	defer resp.Body.Close()
	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to broadcast: %s", string(bodyResponse))
	}

	return string(bodyResponse), nil
}

func (e *explorerSvc) sendAddressEvent(ctx context.Context, event types.OnchainAddressEvent) {
	select {
	case <-ctx.Done():
		return
	case e.channel <- event:
	}
}

func parseBitcoinTx(txStr string) (string, string, error) {
	var tx wire.MsgTx

	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txStr))); err != nil {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(txStr), true)
		if err != nil {
			return "", "", err
		}

		txFromPartial, err := psbt.Extract(ptx)
		if err != nil {
			return "", "", err
		}

		tx = *txFromPartial
	}

	var txBuf bytes.Buffer

	if err := tx.Serialize(&txBuf); err != nil {
		return "", "", err
	}

	txhex := hex.EncodeToString(txBuf.Bytes())
	txid := tx.TxHash().String()

	return txhex, txid, nil
}

func newUtxo(explorerUtxo Utxo, delay arklib.RelativeLocktime, tapscripts []string) types.Utxo {
	utxoTime := explorerUtxo.Status.BlockTime
	createdAt := time.Unix(utxoTime, 0)
	if utxoTime == 0 {
		createdAt = time.Time{}
		utxoTime = time.Now().Unix()
	}

	return types.Utxo{
		Outpoint: types.Outpoint{
			Txid: explorerUtxo.Txid,
			VOut: explorerUtxo.Vout,
		},
		Amount:      explorerUtxo.Amount,
		Delay:       delay,
		SpendableAt: time.Unix(utxoTime, 0).Add(time.Duration(delay.Seconds()) * time.Second),
		CreatedAt:   createdAt,
		Tapscripts:  tapscripts,
	}
}

func deriveWsURL(baseUrl string) (string, error) {
	var wsUrl string

	parsedUrl, err := url.Parse(baseUrl)
	if err != nil {
		return "", err
	}

	scheme := "ws"
	if parsedUrl.Scheme == "https" {
		scheme = "wss"
	}
	parsedUrl.Scheme = scheme
	wsUrl = strings.TrimRight(parsedUrl.String(), "/")

	wsUrl = fmt.Sprintf("%s/v1/ws", wsUrl)

	return wsUrl, nil
}
