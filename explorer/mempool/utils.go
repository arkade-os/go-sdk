package mempool_explorer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

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
