package contract

import (
	"encoding/json"
	"fmt"
	"strings"
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

// Contract type constants.
const (
	TypeDefault         = "default"          // offchain VTXO; IsOnchain=false
	TypeDefaultBoarding = "default_boarding" // boarding P2TR; IsOnchain=true
	TypeDefaultOnchain  = "default_onchain"  // bare key-path P2TR; IsOnchain=true
	TypeDelegate        = "delegate"         // offchain VTXO with delegate key; IsOnchain=false
)

// Param key constants stored in Contract.Params.
const (
	ParamKeyID       = "keyId"       // wallet key ID
	ParamSignerKey   = "signerKey"   // hex-encoded server signer public key
	ParamDelegateKey = "delegateKey" // hex-encoded schnorr delegate public key
	ParamTapscripts  = "tapscripts"  // JSON-encoded []string of hex tapscript leaves
	ParamExitDelay   = "exitDelay"   // "block:N" or "second:N"; empty means no delay
)

// Contract holds the params and derived address for one address type (offchain
// VTXO, boarding, or onchain) produced by a single wallet key. Script is the
// primary key. All contract params (tapscripts, exit delay, key references) are
// stored in Params so the struct remains generic across handler types.
type Contract struct {
	Type      string
	Label     string
	Params    map[string]string // all contract params; see Param* constants
	Script    string            // hex pkScript (primary key)
	Address   string            // ark bech32m when IsOnchain=false, bitcoin P2TR otherwise
	IsOnchain bool              // false → ark address; true → bitcoin P2TR address
	State     State
	CreatedAt time.Time
	Metadata  map[string]any
}

// GetTapscripts decodes the tapscripts stored in Params.
func (c *Contract) GetTapscripts() []string {
	s := c.Params[ParamTapscripts]
	if s == "" || s == "[]" || s == "null" {
		return nil
	}
	var ts []string
	if err := json.Unmarshal([]byte(s), &ts); err != nil {
		return nil
	}
	return ts
}

// GetDelay decodes the exit delay stored in Params.
// Returns an error if the param is missing or malformed; callers must not
// proceed with a zero locktime as it would bypass the CSV timelock.
func (c *Contract) GetDelay() (arklib.RelativeLocktime, error) {
	return parseDelay(c.Params[ParamExitDelay])
}

// parseDelay parses an exit delay string of the form "block:N" or "second:N"
// where N is a non-negative integer. Any prefix other than "second" is treated
// as block-based. Empty string is an error; use serializeDelay to produce
// the canonical form written into Params[ParamExitDelay].
func parseDelay(s string) (arklib.RelativeLocktime, error) {
	if s == "" {
		return arklib.RelativeLocktime{}, fmt.Errorf("exit delay param is empty")
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return arklib.RelativeLocktime{}, fmt.Errorf("invalid exit delay format %q", s)
	}
	var val uint32
	if _, err := fmt.Sscanf(s[idx+1:], "%d", &val); err != nil {
		return arklib.RelativeLocktime{}, fmt.Errorf("invalid exit delay value in %q", s)
	}
	t := arklib.LocktimeTypeBlock
	if s[:idx] == "second" {
		t = arklib.LocktimeTypeSecond
	}
	return arklib.RelativeLocktime{Type: t, Value: val}, nil
}

func serializeDelay(d arklib.RelativeLocktime) string {
	if d.Value == 0 {
		return ""
	}
	typStr := "block"
	if d.Type == arklib.LocktimeTypeSecond {
		typStr = "second"
	}
	return fmt.Sprintf("%s:%d", typStr, d.Value)
}

func serializeTapscripts(ts []string) string {
	if len(ts) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(ts)
	return string(b)
}

type Filter struct {
	Type      *string
	State     *string
	Script    *string
	IsOnchain *bool
	KeyID     *string // matches Params[ParamKeyID]
}

// FilterOption configures a Filter for Manager query methods.
// Pass no options to return all contracts.
type FilterOption func(*Filter)

func WithType(t string) FilterOption {
	return func(f *Filter) { f.Type = &t }
}

func WithState(s State) FilterOption {
	return func(f *Filter) { st := string(s); f.State = &st }
}

func WithScript(s string) FilterOption {
	return func(f *Filter) { f.Script = &s }
}

func WithIsOnchain(v bool) FilterOption {
	return func(f *Filter) { f.IsOnchain = &v }
}

func WithKeyID(id string) FilterOption {
	return func(f *Filter) { f.KeyID = &id }
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
