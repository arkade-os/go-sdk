package explorer

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/types"
)

type spentStatus struct {
	Spent   bool   `json:"spent"`
	SpentBy string `json:"txid,omitempty"`
}

type tx struct {
	Txid string `json:"txid"`
	Vout []struct {
		Address string `json:"scriptpubkey_address"`
		Amount  uint64 `json:"value"`
	} `json:"vout"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type rbfTx struct {
	Txid    string `json:"txid"`
	RBF     bool   `json:"rbf"`
	FullRBF bool   `json:"fullRbf"`
}

type replacement struct {
	Tx        rbfTx         `json:"tx"`
	Timestamp int64         `json:"time"`
	FullRBF   bool          `json:"fullRbf"`
	Mined     bool          `json:"mined"`
	Replaces  []replacement `json:"replaces"`
}

type Utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset,omitempty"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

func (e Utxo) ToUtxo(delay arklib.RelativeLocktime, tapscripts []string) types.Utxo {
	return newUtxo(e, delay, tapscripts)
}

type StreamTransactions struct {
	BlockTransactions   []RawTx `json:"block-transactions,omitempty"`
	MempoolTransactions []RawTx `json:"address-transactions,omitempty"`
}

type RbfTxId struct {
	TxId string `json:"txid"`
}

type RawTx struct {
	Txid string      `json:"txid"`
	Vout []VoutEntry `json:"vout"`
}

type VoutEntry struct {
	ScriptPubKey     string `json:"scriptpubkey"`
	ScriptPubKeyAddr string `json:"scriptpubkey_address"`
	Value            uint64 `json:"value"`
}

type StreamUtxo struct {
	Txid             string
	VoutIndex        int
	ScriptPubAddress string
	Value            uint64
}

type StreamUtxoUpdate struct {
	MempoolUtxos   []StreamUtxo
	ConfirmedUtxos []StreamUtxo
}

type RBFTxn struct {
	TxId       string
	ReplacedBy string
}
