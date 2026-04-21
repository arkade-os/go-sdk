package contract

import (
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/txscript"
)

type State string

const (
	StateActive   State = "active"
	StateInactive State = "inactive"
)

// Contract holds all address facets derived from a single wallet key.
// For the "default" type, one contract per key yields three address facets:
//   - Address:  Arkade bech32m offchain address (canonical)
//   - Boarding: P2TR boarding address (longer exit delay)
//   - Onchain:  plain P2TR key-path address
type Contract struct {
	Type      string
	Label     string
	Params    map[string]string
	Script    string // hex pkScript of the Arkade taproot output (primary key)
	Address   string // Arkade bech32m address
	Boarding  string // P2TR boarding address
	Onchain   string // plain P2TR address (key-path only)
	State     State
	CreatedAt time.Time
	ExpiresAt *time.Time
	Metadata  map[string]any

	Tapscripts         []string                // offchain script leaves (for VTXO matching)
	BoardingTapscripts []string                // boarding script leaves
	Delay              arklib.RelativeLocktime // unilateral exit delay
	BoardingDelay      arklib.RelativeLocktime // boarding exit delay
}

type Filter struct {
	Type   *string
	State  *string
	Script *string
}

type Event struct {
	Type     string
	Contract Contract
	Vtxos    []clientTypes.Vtxo // non-nil for vtxo_received / vtxo_spent events
}

// PathContext carries the spend-time state needed to select a tapscript path.
type PathContext struct {
	Collaborative bool
	CurrentTime   time.Time
	BlockHeight   *uint32
	WalletPubKey  []byte
	Preimage      []byte // preimage for HTLC-style claim paths
}

// PathSelection describes which tapscript leaf to use and any extra witness data.
type PathSelection struct {
	Leaf         txscript.TapLeaf
	ExtraWitness [][]byte // e.g. preimage pushed before signatures
	Sequence     *uint32  // non-nil when the input must set nSequence (CSV)
	Locktime     *uint32  // non-nil when the tx must set nLocktime (CLTV)
}
