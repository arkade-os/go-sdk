package explorer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
)

const (
	BitcoinExplorer = "bitcoin"
)

type Explorer interface {
	GetTxHex(txid string) (string, error)
	Broadcast(txs ...string) (string, error)
	GetTxs(addr string) ([]tx, error)
	GetRBFReplacementTx(txid, txHex string) (bool, string, int64, error)
	GetRBFReplacedTxns(txid string) (bool, []string, int64, error)
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
	GetAddressesEvents() (<-chan StreamUtxoUpdate, error)
	SubscribeForAddresses(addresses []string) error
}

type AddrTracker struct {
	conn          *websocket.Conn
	subscribedMu  sync.Mutex
	subscribedMap map[string]struct{}
	channel       chan StreamUtxoUpdate
}

type explorerSvc struct {
	cache       *utils.Cache[string]
	baseUrl     string
	net         arklib.Network
	addrTracker *AddrTracker
}

func NewExplorer(baseUrl string, net arklib.Network) Explorer {

	return &explorerSvc{
		cache:       utils.NewCache[string](),
		baseUrl:     baseUrl,
		net:         net,
		addrTracker: nil,
	}
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

func (e *explorerSvc) GetAddressesEvents() (<-chan StreamUtxoUpdate, error) {
	if e.addrTracker == nil {
		return nil, fmt.Errorf(
			"address tracker is not initialized, call SubscribeForAddresses first",
		)
	}

	return e.addrTracker.channel, nil
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

func (e *explorerSvc) SubscribeForAddresses(addressList []string) error {
	if e.net == arklib.BitcoinRegTest {
		log.Printf("address tracking is not supported for %s network", e.net)
		return nil
	}

	if e.addrTracker == nil {
		wsUrl, err := utils.DeriveWsURl(e.baseUrl, e.net)
		if err != nil {
			return fmt.Errorf("failed to derive WebSocket URL: %w", err)
		}

		tracker, err := NewAddrTracker(wsUrl)
		if err != nil {
			return fmt.Errorf(
				"failed to create address tracker: %w", err,
			)
		}
		e.addrTracker = tracker
	}

	for _, address := range addressList {
		err := e.addrTracker.TrackAddress(address)
		if err != nil {
			log.Printf("failed to subscribe to address %s: %v", address, err)
		}
	}

	return nil
}

func (e explorerSvc) GetRBFReplacedTxns(txid string) (bool, []string, int64, error) {
	isRbf, replacedBy, timestamp, err := e.getMempoolRBFReplacedTx(
		fmt.Sprintf("%s/v1/fullrbf/replaced", e.baseUrl), txid,
	)
	if err != nil {
		return false, nil, -1, err
	}
	if isRbf {
		return isRbf, replacedBy, timestamp, nil
	}

	return e.getMempoolRBFReplacedTx(fmt.Sprintf("%s/v1/replaced", e.baseUrl), txid)
}

func (e explorerSvc) GetRBFReplacementTx(txid, txHex string) (bool, string, int64, error) {
	isRbf, replacedBy, timestamp, err := e.getMempoolRBFReplacementTx(
		fmt.Sprintf("%s/v1/fullrbf/replacements", e.baseUrl), txid,
	)
	if err != nil {
		return false, "", -1, err
	}
	if isRbf {
		return isRbf, replacedBy, timestamp, nil
	}

	isRbf, replacementTxid, timestamp, err := e.getMempoolRBFReplacementTx(
		fmt.Sprintf("%s/v1/replacements", e.baseUrl),
		txid,
	)
	if err != nil {
		return e.getEsploraRBFReplacementTx(txid, txHex)
	}

	return isRbf, replacementTxid, timestamp, nil
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
	payload := []Utxo{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *explorerSvc) GetBalance(addr string) (uint64, error) {
	payload, err := e.GetUtxos(addr)
	if err != nil {
		return 0, err
	}

	balance := uint64(0)
	for _, p := range payload {
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
			blocktime = time.Unix(utxo.Status.Blocktime, 0)
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

func (e *explorerSvc) getMempoolRBFReplacementTx(url, txid string) (bool, string, int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return false, "", -1, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", -1, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, "", -1, fmt.Errorf("%s", string(body))
	}

	replacements := make([]replacement, 0)
	if err := json.Unmarshal(body, &replacements); err != nil {
		return false, "", -1, err
	}

	for _, r := range replacements {
		for _, rr := range r.Replaces {
			if rr.Tx.Txid == txid {
				return true, r.Tx.Txid, r.Timestamp, nil
			}
		}
	}
	return false, "", 0, nil
}

func (e *explorerSvc) getMempoolRBFReplacedTx(url, txid string) (bool, []string, int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return false, nil, -1, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, -1, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, nil, -1, fmt.Errorf("%s", string(body))
	}

	replacements := make([]replacement, 0)
	if err := json.Unmarshal(body, &replacements); err != nil {
		return false, nil, -1, err
	}

	for _, r := range replacements {
		if r.Tx.Txid == txid {
			replacedTxIds := make([]string, 0, len(r.Replaces))
			for _, rr := range r.Replaces {
				replacedTxIds = append(replacedTxIds, rr.Tx.Txid)
			}
			return true, replacedTxIds, r.Timestamp, nil
		}
	}

	return false, nil, 0, nil
}

func (e *explorerSvc) getEsploraRBFReplacementTx(txid, txHex string) (bool, string, int64, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/hex", e.baseUrl, txid))
	if err != nil {
		return false, "", -1, err
	}
	if resp.StatusCode == http.StatusNotFound {
		var tx wire.MsgTx

		if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txHex))); err != nil {
			return false, "", -1, err
		}
		spentBy, err := e.GetTxOutspends(tx.TxIn[0].PreviousOutPoint.Hash.String())
		if err != nil {
			return false, "", -1, err
		}
		if len(spentBy) <= 0 {
			return false, "", -1, nil
		}
		rbfTx := spentBy[0].SpentBy

		confirmed, timestamp, err := e.GetTxBlockTime(rbfTx)
		if err != nil {
			return false, "", -1, err
		}
		if !confirmed {
			timestamp = 0
		}

		return true, rbfTx, timestamp, nil
	}

	return false, "", -1, nil
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
	utxoTime := explorerUtxo.Status.Blocktime
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

func NewAddrTracker(
	wsURL string,
) (*AddrTracker, error) {
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}

	conn, resp, err := dialer.DialContext(context.Background(), wsURL, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("dial failed: %v (http status %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	t := &AddrTracker{
		conn:          conn,
		subscribedMap: make(map[string]struct{}),
	}

	return t, nil
}

func (t *AddrTracker) TrackAddress(addr string) error {
	t.subscribedMu.Lock()
	defer t.subscribedMu.Unlock()

	if _, already := t.subscribedMap[addr]; already {
		return nil
	}

	payload := struct {
		Addr string `json:"track-address"`
	}{
		Addr: addr,
	}

	if err := t.conn.WriteJSON(payload); err != nil {
		return fmt.Errorf("failed to write subscribe for %s: %w", addr, err)
	}

	t.subscribedMap[addr] = struct{}{}
	return nil
}

func (t *AddrTracker) SubscribeToUtxoEvent() {
	// Send ping every 25s to keep alive
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := t.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Println("Ping failed:", err)
				return
			}
		}
	}()

	deriveUtxos := func(trasactions []RawTx) []StreamUtxo {
		utxos := make([]StreamUtxo, 0, len(t.subscribedMap))
		for _, rawTransaction := range trasactions {

			for index, out := range rawTransaction.Vout {
				if _, ok := t.subscribedMap[out.ScriptPubKeyAddr]; ok {
					utxos = append(utxos, StreamUtxo{
						Txid:             rawTransaction.Txid,
						VoutIndex:        index,
						ScriptPubAddress: out.ScriptPubKeyAddr,
						Value:            out.Value,
					})
				}
			}
		}

		return utxos
	}

	events := make(chan StreamUtxoUpdate)

	go func() {

		for {
			var payload StreamTransactions
			err := t.conn.ReadJSON(&payload)
			if err != nil {
				log.Println("read message failed:", err)
				continue
			}

			mempoolUtxoList := deriveUtxos(payload.MempoolTransactions)
			confirmedUtxoList := deriveUtxos(payload.BlockTransactions)

			streamUtxoUpdate := StreamUtxoUpdate{
				MempoolUtxos:   mempoolUtxoList,
				ConfirmedUtxos: confirmedUtxoList,
			}

			events <- streamUtxoUpdate
		}
	}()

}
