package electrum_explorer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// parseRPCError interprets a JSON-RPC error value. ElectrumX sends a standard
// {"code": N, "message": "..."} object; electrs-esplora sends a plain string
// (e.g. "sendrawtransaction RPC error: {...}"). Both are accepted; nil is
// returned when raw is absent or null so callers can use a nil check.
func parseRPCError(raw json.RawMessage) *jsonRPCError {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var obj jsonRPCError
	if err := json.Unmarshal(raw, &obj); err == nil {
		return &obj
	}
	// electrs-esplora: error is a plain string, possibly embedding JSON like
	// "sendrawtransaction RPC error: {\"code\":-22,\"message\":\"...\"}".
	var msg string
	if err := json.Unmarshal(raw, &msg); err == nil {
		if i := strings.Index(msg, "{"); i >= 0 {
			var inner jsonRPCError
			if err := json.Unmarshal([]byte(msg[i:]), &inner); err == nil && inner.Code != 0 {
				return &inner
			}
		}
		return &jsonRPCError{Message: msg}
	}
	return &jsonRPCError{Message: string(raw)}
}

// addressToScripthash converts a Bitcoin address to the ElectrumX scripthash format:
// SHA256(outputScript) with bytes reversed (little-endian), hex-encoded.
func addressToScripthash(addr string, params *chaincfg.Params) (string, error) {
	decoded, err := btcutil.DecodeAddress(addr, params)
	if err != nil {
		return "", err
	}
	script, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(script)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		hash[i], hash[j] = hash[j], hash[i]
	}
	return hex.EncodeToString(hash[:]), nil
}

// scriptToScripthash converts a raw script (hex-encoded) to the ElectrumX scripthash format.
func scriptToScripthash(scriptHex string) (string, error) {
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(script)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		hash[i], hash[j] = hash[j], hash[i]
	}
	return hex.EncodeToString(hash[:]), nil
}

// scriptToAddress converts a hex-encoded output script to a Bitcoin address string.
// Returns empty string for unrecognised or non-standard scripts.
func scriptToAddress(scriptHex string, params *chaincfg.Params) string {
	if scriptHex == "" {
		return ""
	}
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		return ""
	}
	pkScript, err := txscript.ParsePkScript(script)
	if err != nil {
		return ""
	}
	addr, err := pkScript.Address(params)
	if err != nil {
		return ""
	}
	return addr.EncodeAddress()
}

func parseBitcoinTx(txStr string) (string, string, error) {
	var tx wire.MsgTx
	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txStr))); err != nil {
		// Witness deserialization can misread a 0-input tx as a bad segwit
		// marker; try non-witness before falling back to PSBT.
		tx = wire.MsgTx{}
		if err2 := tx.DeserializeNoWitness(hex.NewDecoder(strings.NewReader(txStr))); err2 != nil {
			ptx, err3 := psbt.NewFromRawBytes(strings.NewReader(txStr), true)
			if err3 != nil {
				return "", "", err3
			}
			txFromPartial, err3 := psbt.Extract(ptx)
			if err3 != nil {
				return "", "", err3
			}
			tx = *txFromPartial
		}
	}
	var txBuf bytes.Buffer
	if err := tx.Serialize(&txBuf); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(txBuf.Bytes()), tx.TxHash().String(), nil
}

// listeners is a non-blocking broadcast hub for OnchainAddressEvent.
// Slow or blocked listeners are removed automatically.
type listeners struct {
	mu        sync.RWMutex
	listeners map[chan types.OnchainAddressEvent]int
	index     int
}

func newListeners() *listeners {
	return &listeners{
		listeners: make(map[chan types.OnchainAddressEvent]int),
	}
}

func (l *listeners) add(ch chan types.OnchainAddressEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.listeners[ch] = l.index
	l.index++
}

func (l *listeners) broadcast(event types.OnchainAddressEvent) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var toRemove []chan types.OnchainAddressEvent
	var ids []int
	for ch, id := range l.listeners {
		select {
		case ch <- event:
		default:
			toRemove = append(toRemove, ch)
			ids = append(ids, id)
		}
	}
	if len(toRemove) > 0 {
		go func() {
			l.remove(toRemove)
			log.WithFields(log.Fields{
				"ids":   ids,
				"event": event,
			}).Warn("electrum explorer: slow listener(s) removed")
		}()
	}
}

func (l *listeners) remove(chs []chan types.OnchainAddressEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ch := range chs {
		if _, ok := l.listeners[ch]; !ok {
			continue
		}
		close(ch)
		delete(l.listeners, ch)
	}
}

func (l *listeners) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ch := range l.listeners {
		close(ch)
	}
	l.listeners = make(map[chan types.OnchainAddressEvent]int)
}
