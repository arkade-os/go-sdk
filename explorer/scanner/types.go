package scanner

import (
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/types"
)

// Common types shared between scanner implementations.
// These types match the explorer package's public API types.

type SpentStatus struct {
	Spent   bool
	SpentBy string
}

type Output struct {
	Script  string
	Address string
	Amount  uint64
}

type Input struct {
	Output
	Txid string
	Vout uint32
}

type Tx struct {
	Txid   string
	Vin    []Input
	Vout   []Output
	Status ConfirmedStatus
}

type ConfirmedStatus struct {
	Confirmed bool
	BlockTime int64
}

// Utxo represents an unspent transaction output from the blockchain explorer.
type Utxo struct {
	Txid   string
	Vout   uint32
	Amount uint64
	Script string
	Status ConfirmedStatus
}

// ToUtxo converts the scanner UTXO to the internal types.Utxo format
// with the specified relative locktime delay and tapscripts.
func (u Utxo) ToUtxo(delay arklib.RelativeLocktime, tapscripts []string) types.Utxo {
	utxoTime := u.Status.BlockTime
	createdAt := time.Unix(utxoTime, 0)
	if utxoTime == 0 {
		createdAt = time.Time{}
		utxoTime = time.Now().Unix()
	}

	return types.Utxo{
		Outpoint: types.Outpoint{
			Txid: u.Txid,
			VOut: u.Vout,
		},
		Amount:      u.Amount,
		Delay:       delay,
		SpendableAt: time.Unix(utxoTime, 0).Add(time.Duration(delay.Seconds()) * time.Second),
		CreatedAt:   createdAt,
		Tapscripts:  tapscripts,
	}
}
