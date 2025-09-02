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
	Vin  []struct {
		Txid    string `json:"txid"`
		Vout    uint32 `json:"vout"`
		Prevout struct {
			Address string `json:"scriptpubkey_address"`
			Amount  uint64 `json:"value"`
		} `json:"prevout"`
	} `json:"vin"`
	Vout []struct {
		Script  string `json:"scriptpubkey"`
		Address string `json:"scriptpubkey_address"`
		Amount  uint64 `json:"value"`
	} `json:"vout"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		Blocktime int64 `json:"block_time"`
	} `json:"status"`
}

type Utxo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Amount uint64 `json:"value"`
	Asset  string `json:"asset,omitempty"`
	Status struct {
		Confirmed bool  `json:"confirmed"`
		BlockTime int64 `json:"block_time"`
	} `json:"status"`
	Script string
}

func (e Utxo) ToUtxo(delay arklib.RelativeLocktime, tapscripts []string) types.Utxo {
	return newUtxo(e, delay, tapscripts)
}

type addressNotification struct {
	MultiAddrTx map[string]txNotificationSet `json:"multi-address-transactions"`
}

type txNotificationSet struct {
	Mempool   []txNotification `json:"mempool"`
	Confirmed []txNotification `json:"confirmed"`
	Removed   []txNotification `json:"removed"`
}

type txNotification struct {
	Txid    string                  `json:"txid"`
	Version uint32                  `json:"version"`
	Inputs  []txNotificationInput   `json:"vin"`
	Outputs []txNotificationPrevout `json:"vout"`
	Status  struct {
		Confirmed bool  `json:"confirmed"`
		BlockTime int64 `json:"block_time"`
	} `json:"status"`
}

type txNotificationInput struct {
	Prevout txNotificationPrevout `json:"prevout"`
	Txid    string                `json:"txid"`
	Vout    int                   `json:"vout"`
}

type txNotificationPrevout struct {
	Script  string `json:"scriptpubkey"`
	Address string `json:"scriptpubkey_address"`
	Amount  uint64 `json:"value"`
}

type RbfTxId struct {
	TxId string `json:"txid"`
}

type RBFTxn struct {
	TxId       string
	ReplacedBy string
}
