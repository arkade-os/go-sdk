package contract

import (
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
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
	Type    string
	Label   string
	Params  map[string]string
	Script  string // hex pkScript of the Arkade taproot output (primary key)
	Address string // Arkade bech32m address
	Boarding string // P2TR boarding address
	Onchain  string // plain P2TR address (key-path only)
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

type CreateParams struct {
	Type   string
	Params map[string]string
	Label  string
}

type Event struct {
	Type     string
	Contract Contract
}
