package explorer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	BitcoinExplorer = "bitcoin"
	pongInterval    = 60 * time.Second
	pingInterval    = (pongInterval * 9) / 10
)

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txs ...string) (string, error)
	GetTxs(addr string) ([]tx, error)
	GetTxOutspends(tx string) ([]spentStatus, error)
	GetUtxos(addr string) ([]Utxo, error)
	GetBalance(addr string) (uint64, error)
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
}

func NewExplorer(baseUrl string, net arklib.Network) (Explorer, error) {
	wsURL, err := deriveWsURL(baseUrl, net)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %s", err)
	}
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}

	conn, resp, err := dialer.DialContext(context.Background(), wsURL, nil)
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusNotFound {
			if resp != nil {
				return nil, fmt.Errorf("dial failed: %v (http status %d)", err, resp.StatusCode)
			}
		}
		return nil, fmt.Errorf("dial failed: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	svc := &explorerSvc{
		cache:         utils.NewCache[string](),
		baseUrl:       baseUrl,
		net:           net,
		conn:          conn,
		subscribedMu:  &sync.RWMutex{},
		subscribedMap: make(map[string]addressData),
		channel:       make(chan types.OnchainAddressEvent),
		stopTracking:  cancel,
	}
	if conn != nil {
		svc.startTracking(ctx)
	}

	return svc, nil
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
		payload := map[string][]string{"track-addresses": addressesToSubscribe}

		if err := e.conn.WriteJSON(payload); err != nil {
			return fmt.Errorf("failed to subscribe for addresses %s: %s", addressesToSubscribe, err)
		}
	}

	for _, addr := range addressesToSubscribe {
		e.subscribedMap[addr] = addressData{}
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

	outScript := hex.EncodeToString(decoded.ScriptAddress())
	for i := range utxos {
		utxos[i].Script = outScript
	}

	return utxos, nil
}

func (e *explorerSvc) GetBalance(addr string) (uint64, error) {
	utxos, err := e.GetUtxos(addr)
	if err != nil {
		return 0, err
	}

	balance := uint64(0)
	for _, p := range utxos {
		balance += p.Amount
	}
	return balance, nil
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
			blocktime = time.Unix(utxo.Status.BlockHeight, 0)
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
		// .
		go func(ctx context.Context) {
			e.conn.SetReadDeadline(time.Now().Add(pongInterval))
			e.conn.SetPongHandler(func(string) error {
				e.conn.SetReadDeadline(time.Now().Add(pongInterval))
				return nil
			})
			for {
				var payload addressNotification
				if err := e.conn.ReadJSON(&payload); err != nil {
					log.WithError(err).Error("failed to read address notification")
					continue
				}

				go e.sendAddressEventFromWs(payload)
			}
		}(ctx)

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
						log.Fatalf("failed to ping explorer: %s", err)
						return
					}
				}
			}
		}(ctx)

		return
	}

	// Otherwise (esplora url), poll the explorer every 10s and manually send notifications of
	// spent, new and confirmed utxos.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.subscribedMu.RLock()
			subscribedMap := e.subscribedMap
			e.subscribedMu.RUnlock()
			if len(subscribedMap) == 0 {
				continue
			}
			for addr, data := range subscribedMap {
				utxos, err := e.GetUtxos(addr)
				if err != nil {
					log.WithError(err).Error("failed to poll explorer")
				}
				buf, _ := json.Marshal(utxos)
				hashedResp := sha256.Sum256(buf)
				if !bytes.Equal(data.hash, hashedResp[:]) {
					go e.sendAddressEventFromPolling(data.utxos, utxos)
					e.subscribedMu.Lock()
					e.subscribedMap[addr] = addressData{
						hash:  hashedResp[:],
						utxos: utxos,
					}
					e.subscribedMu.Unlock()
				}

			}
		case <-ctx.Done():
			return
		}
	}
}

func (e *explorerSvc) sendAddressEventFromWs(payload addressNotification) {
	spentUtxos := make([]types.UtxoNotification, 0)
	newUtxos := make([]types.UtxoNotification, 0)
	confirmedUtxos := make([]types.UtxoNotification, 0)
	replacements := make(map[string]string)
	for addr, data := range payload.MultiAddrTx {
		if len(data.Removed) > 0 {
			for _, tx := range data.Removed {
				replacements[tx.Txid] = data.Mempool[0].Txid
			}
			continue
		}
		if len(data.Mempool) > 0 {
			for _, tx := range data.Mempool {
				for _, in := range tx.Inputs {
					if in.Prevout.Address == addr {
						spentUtxos = append(spentUtxos, types.UtxoNotification{
							Txid: in.Txid,
							VOut: uint32(in.Vout),
						})
					}
				}
				for i, out := range tx.Outputs {
					if out.Address == addr {
						newUtxos = append(newUtxos, types.UtxoNotification{
							Txid:   tx.Txid,
							VOut:   uint32(i),
							Script: out.Script,
							Amount: out.Amount,
						})
					}
				}
			}
		}
		if len(data.Confirmed) > 0 {
			for _, tx := range data.Confirmed {
				for i, out := range tx.Outputs {
					if out.Address == addr {
						confirmedUtxos = append(confirmedUtxos, types.UtxoNotification{
							Txid: tx.Txid,
							VOut: uint32(i),
						})
					}
				}
			}
		}
	}
	e.channel <- types.OnchainAddressEvent{
		NewUtxos:       newUtxos,
		SpentUtxos:     spentUtxos,
		ConfirmedUtxos: confirmedUtxos,
		Replacements:   replacements,
	}
}

func (e *explorerSvc) sendAddressEventFromPolling(oldUtxos, newUtxos []Utxo) {
	indexedOldUtxos := make(map[string]Utxo, 0)
	indexedNewUtxos := make(map[string]Utxo, 0)
	for _, oldUtxo := range oldUtxos {
		indexedOldUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)] = oldUtxo
	}
	for _, newUtxo := range newUtxos {
		indexedNewUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)] = newUtxo
	}
	spentUtxos := make([]types.UtxoNotification, 0)
	for _, oldUtxo := range oldUtxos {
		if _, ok := indexedNewUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)]; !ok {
			spentUtxos = append(spentUtxos, types.UtxoNotification{
				Txid: oldUtxo.Txid,
				VOut: oldUtxo.Vout,
			})
		}
	}
	receivedUtxos := make([]types.UtxoNotification, 0)
	confirmedUtxos := make([]types.UtxoNotification, 0)
	for _, newUtxo := range newUtxos {
		oldUtxo, ok := indexedOldUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)]
		if !ok {
			var confirmedAt int64
			if newUtxo.Status.Confirmed {
				confirmedAt = newUtxo.Status.BlockHeight
			}
			receivedUtxos = append(receivedUtxos, types.UtxoNotification{
				Txid:        newUtxo.Txid,
				VOut:        newUtxo.Vout,
				Script:      newUtxo.Script,
				Amount:      newUtxo.Amount,
				ConfirmedAt: confirmedAt,
			})
			continue
		}
		if !oldUtxo.Status.Confirmed && newUtxo.Status.Confirmed {
			confirmedUtxos = append(confirmedUtxos, types.UtxoNotification{
				Txid:        newUtxo.Txid,
				VOut:        newUtxo.Vout,
				Script:      newUtxo.Script,
				Amount:      newUtxo.Amount,
				ConfirmedAt: newUtxo.Status.BlockHeight,
			})
		}
	}
	e.channel <- types.OnchainAddressEvent{
		SpentUtxos:     spentUtxos,
		NewUtxos:       receivedUtxos,
		ConfirmedUtxos: confirmedUtxos,
	}
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
	utxoTime := explorerUtxo.Status.BlockHeight
	createdAt := time.Unix(utxoTime, 0)
	if utxoTime == 0 {
		createdAt = time.Time{}
		utxoTime = time.Now().Unix()
	}

	return types.Utxo{
		Txid:        explorerUtxo.Txid,
		VOut:        explorerUtxo.Vout,
		Amount:      explorerUtxo.Amount,
		Delay:       delay,
		SpendableAt: time.Unix(utxoTime, 0).Add(time.Duration(delay.Seconds()) * time.Second),
		CreatedAt:   createdAt,
		Tapscripts:  tapscripts,
	}
}

func deriveWsURL(baseUrl string, network arklib.Network) (string, error) {
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
