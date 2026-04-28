package contract

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

const (
	ParamKeyID       = "keyId"
	ParamOwnerKey    = "ownerKey"
	ParamSignerKey   = "signerKey"
	ParamDelegateKey = "delegateKey"
	ParamTapscripts  = "tapscripts"
	ParamExitDelay   = "exitDelay"
)

// DelegateConfig holds the server parameters needed to derive a delegate contract.
type DelegateConfig struct {
	SignerKey *btcec.PublicKey
	Network   arklib.Network
	ExitDelay arklib.RelativeLocktime
}

// PathContext describes how the caller intends to spend a contract.
type PathContext struct {
	Collaborative   bool
	UseDelegatePath bool
	// VHTLC / HTLC fields.
	WalletPubKey []byte    // 32-byte Schnorr pubkey of the spending wallet
	Preimage     []byte    // preimage for hash-locked claim paths
	BlockHeight  *uint32   // current chain tip block height (for CLTV checks)
	CurrentTime  time.Time // current time (for time-based CLTV checks)
}

// PathSelection describes a chosen tapscript spending path.
type PathSelection struct {
	Leaf         txscript.TapLeaf
	ExtraWitness [][]byte // extra witness elements pushed before signatures (e.g. preimage)
	Sequence     *uint32
	Locktime     *uint32
}

// DelegateHandler derives offchain Ark VTXO contracts that add a 3-of-3 delegate
// spending path alongside the standard forfeit and unilateral-exit paths.
//
// Tapscript leaf order:
//
//	[0] exit:     CSVMultisigClosure{[owner], UnilateralExitDelay}
//	[1] forfeit:  MultisigClosure{[owner, server]}
//	[2] delegate: MultisigClosure{[owner, delegate, server]}
type DelegateHandler struct{}

var _ handlers.Handler = (*DelegateHandler)(nil)

// DeriveContract derives the delegate VTXO contract. Only an offchain contract is
// produced; no boarding or onchain facets are derived for delegate contracts.
//
// Closure ordering is load-bearing: the arkd client-lib uses forfeitClosures[0]
// to build forfeit transactions, and ForfeitClosures() matches all *MultisigClosure
// values regardless of key count. The 2-of-2 forfeit MUST remain at index [1] so
// it is picked ahead of the 3-of-3 delegate at index [2]. Do not reorder.
func (h *DelegateHandler) DeriveContract(
	_ context.Context,
	key wallet.KeyRef,
	cfg DelegateConfig,
	delegateKey *btcec.PublicKey,
) (*types.Contract, error) {
	if delegateKey == nil {
		return nil, fmt.Errorf("delegate key must not be nil")
	}
	if delegateKey.IsEqual(key.PubKey) {
		return nil, fmt.Errorf("delegate key must differ from owner key")
	}
	if delegateKey.IsEqual(cfg.SignerKey) {
		return nil, fmt.Errorf("delegate key must differ from signer key")
	}

	vtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			// [0] exit: owner unilateral after CSV timelock
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{key.PubKey},
				},
				Locktime: cfg.ExitDelay,
			},
			// [1] forfeit: owner + server cooperative, no delay
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, cfg.SignerKey},
			},
			// [2] delegate: owner + delegate + server 3-of-3, no delay
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, delegateKey, cfg.SignerKey},
			},
		},
	}

	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("delegate tap tree: %w", err)
	}

	arkAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerKey,
		VtxoTapKey: vtxoTapKey,
	}
	encodedArkAddr, err := arkAddr.EncodeV0()
	if err != nil {
		return nil, fmt.Errorf("encode ark address: %w", err)
	}

	tapscripts, err := vtxoScript.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode tapscripts: %w", err)
	}

	pkScript, err := txscript.PayToTaprootScript(vtxoTapKey)
	if err != nil {
		return nil, fmt.Errorf("pkScript: %w", err)
	}

	return &types.Contract{
		Type: types.ContractTypeDelegate,
		Params: map[string]string{
			ParamKeyID:       key.Id,
			ParamOwnerKey:    hex.EncodeToString(schnorr.SerializePubKey(key.PubKey)),
			ParamSignerKey:   hex.EncodeToString(schnorr.SerializePubKey(cfg.SignerKey)),
			ParamDelegateKey: hex.EncodeToString(delegateKey.SerializeCompressed()),
			ParamTapscripts:  serializeTapscripts(tapscripts),
			ParamExitDelay:   serializeDelay(cfg.ExitDelay),
		},
		Script:    hex.EncodeToString(pkScript),
		Address:   encodedArkAddr,
		State:     types.ContractStateActive,
		CreatedAt: time.Now(),
	}, nil
}

// NewContract returns an error: delegate contracts require a delegate key.
// Use Manager.NewDelegate instead.
func (h *DelegateHandler) NewContract(_ context.Context, _ wallet.KeyRef) (*types.Contract, error) {
	return nil, fmt.Errorf("delegate contracts require a delegate key: use Manager.NewDelegate")
}

func (h *DelegateHandler) GetKeyRef(c types.Contract) (*wallet.KeyRef, error) {
	if len(c.Params) == 0 {
		return nil, fmt.Errorf("contract %s has no parameters", c.Script)
	}
	keyId, ok := c.Params[ParamKeyID]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing key ID", c.Script)
	}
	ownerKeyHex, ok := c.Params[ParamOwnerKey]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing owner key", c.Script)
	}
	buf, err := hex.DecodeString(ownerKeyHex)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid owner key format", c.Script)
	}
	ownerKey, err := schnorr.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid owner key: %w", c.Script, err)
	}
	return &wallet.KeyRef{Id: keyId, PubKey: ownerKey}, nil
}

func (h *DelegateHandler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	keyRef, err := h.GetKeyRef(c)
	if err != nil {
		return nil, err
	}
	return map[string]string{c.Script: keyRef.Id}, nil
}

func (h *DelegateHandler) GetSignerKey(c types.Contract) (*btcec.PublicKey, error) {
	if len(c.Params) == 0 {
		return nil, fmt.Errorf("contract %s has no parameters", c.Script)
	}
	signerKeyHex, ok := c.Params[ParamSignerKey]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing signer key", c.Script)
	}
	buf, err := hex.DecodeString(signerKeyHex)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid signer key format", c.Script)
	}
	signerKey, err := schnorr.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid signer key: %w", c.Script, err)
	}
	return signerKey, nil
}

func (h *DelegateHandler) GetExitDelay(c types.Contract) (*arklib.RelativeLocktime, error) {
	if len(c.Params) == 0 {
		return nil, fmt.Errorf("contract %s has no parameters", c.Script)
	}
	s, ok := c.Params[ParamExitDelay]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing exit delay", c.Script)
	}
	lt, err := parseDelay(s)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid exit delay: %w", c.Script, err)
	}
	return &lt, nil
}

func (h *DelegateHandler) GetTapscripts(c types.Contract) ([]string, error) {
	if len(c.Params) == 0 {
		return nil, fmt.Errorf("contract %s has no parameters", c.Script)
	}
	s, ok := c.Params[ParamTapscripts]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing tapscripts", c.Script)
	}
	return parseTapscripts(s)
}

// SelectPath returns the forfeit leaf (2-of-2) for a standard collaborative spend,
// the delegate leaf (3-of-3) when pctx.UseDelegatePath is set, or the exit leaf
// for a unilateral spend.
func (h *DelegateHandler) SelectPath(
	_ context.Context, c types.Contract, pctx PathContext,
) (*PathSelection, error) {
	tapscripts, err := h.GetTapscripts(c)
	if err != nil {
		return nil, err
	}
	if len(tapscripts) < 3 {
		return nil, fmt.Errorf("delegate contract requires 3 tapscripts, got %d", len(tapscripts))
	}
	if pctx.Collaborative {
		if pctx.UseDelegatePath {
			return tapLeafSelection(tapscripts[2], nil, nil)
		}
		return tapLeafSelection(tapscripts[1], nil, nil)
	}
	delay, err := h.GetExitDelay(c)
	if err != nil {
		return nil, fmt.Errorf("exit delay: %w", err)
	}
	seq, err := arklib.BIP68Sequence(*delay)
	if err != nil {
		return nil, fmt.Errorf("BIP68 sequence: %w", err)
	}
	s := uint32(seq)
	return tapLeafSelection(tapscripts[0], &s, nil)
}

// GetSpendablePaths returns exit always; forfeit and delegate when collaborative.
func (h *DelegateHandler) GetSpendablePaths(
	_ context.Context, c types.Contract, pctx PathContext,
) ([]PathSelection, error) {
	tapscripts, err := h.GetTapscripts(c)
	if err != nil {
		return nil, err
	}
	if len(tapscripts) < 3 {
		return nil, fmt.Errorf("delegate contract requires 3 tapscripts, got %d", len(tapscripts))
	}
	delay, err := h.GetExitDelay(c)
	if err != nil {
		return nil, fmt.Errorf("exit delay: %w", err)
	}
	seq, err := arklib.BIP68Sequence(*delay)
	if err != nil {
		return nil, fmt.Errorf("BIP68 sequence: %w", err)
	}
	s := uint32(seq)

	exit, err := tapLeafSelection(tapscripts[0], &s, nil)
	if err != nil {
		return nil, err
	}
	paths := []PathSelection{*exit}

	if pctx.Collaborative {
		forfeit, err := tapLeafSelection(tapscripts[1], nil, nil)
		if err != nil {
			return nil, err
		}
		delegate, err := tapLeafSelection(tapscripts[2], nil, nil)
		if err != nil {
			return nil, err
		}
		paths = append(paths, *forfeit, *delegate)
	}
	return paths, nil
}

func tapLeafSelection(
	tapscriptHex string,
	sequence *uint32,
	locktime *uint32,
) (*PathSelection, error) {
	sc, err := hex.DecodeString(tapscriptHex)
	if err != nil {
		return nil, fmt.Errorf("invalid tapscript hex: %w", err)
	}
	return &PathSelection{
		Leaf:     txscript.NewBaseTapLeaf(sc),
		Sequence: sequence,
		Locktime: locktime,
	}, nil
}

func serializeTapscripts(ts []string) string {
	b, _ := json.Marshal(ts)
	return string(b)
}

func parseTapscripts(s string) ([]string, error) {
	var ts []string
	if err := json.Unmarshal([]byte(s), &ts); err != nil {
		return nil, fmt.Errorf("invalid tapscripts format: %w", err)
	}
	return ts, nil
}

func serializeDelay(lt arklib.RelativeLocktime) string {
	if lt.Type == arklib.LocktimeTypeBlock {
		return fmt.Sprintf("block:%d", lt.Value)
	}
	return fmt.Sprintf("second:%d", lt.Value)
}

func parseDelay(s string) (arklib.RelativeLocktime, error) {
	if after, ok := strings.CutPrefix(s, "block:"); ok {
		var v uint32
		if _, err := fmt.Sscanf(after, "%d", &v); err != nil {
			return arklib.RelativeLocktime{}, fmt.Errorf(
				"invalid block delay value in %q: %w",
				s,
				err,
			)
		}
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: v}, nil
	}
	if after, ok := strings.CutPrefix(s, "second:"); ok {
		var v uint32
		if _, err := fmt.Sscanf(after, "%d", &v); err != nil {
			return arklib.RelativeLocktime{}, fmt.Errorf(
				"invalid second delay value in %q: %w",
				s,
				err,
			)
		}
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: v}, nil
	}
	return arklib.RelativeLocktime{}, fmt.Errorf(
		"invalid delay format %q: expected \"block:N\" or \"second:N\"",
		s,
	)
}
