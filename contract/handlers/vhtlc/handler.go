package vhtlcHandler

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// Param keys stored in Contract.Params.
const (
	paramOwnerKeyID                      = "ownerKeyId"
	paramOwnerKey                        = "ownerKey"
	paramSender                          = "sender"
	paramReceiver                        = "receiver"
	paramServer                          = "server"
	paramPreimageHash                    = "preimageHash"
	paramRefundLocktime                  = "refundLocktime"
	paramClaimDelayType                  = "claimDelayType"
	paramClaimDelayValue                 = "claimDelayValue"
	paramRefundDelayType                 = "refundDelayType"
	paramRefundDelayValue                = "refundDelayValue"
	paramRefundWithoutReceiverDelayType  = "refundWithoutReceiverDelayType"
	paramRefundWithoutReceiverDelayValue = "refundWithoutReceiverDelayValue"
	paramNICReceiverPkScript             = "nicReceiverPkScript"
	paramNICIntrospectorPubKey           = "nicIntrospectorPubKey"
	paramCheckpointExitPath              = "checkpointExitPath"
)

const (
	locktimeTagBlock  = "block"
	locktimeTagSecond = "second"
)

// Handler is a stateless contract handler for VHTLC scripts.
// All VHTLC parameters are stored in Contract.Params, so the handler
// can rebuild the full tapscript tree from any persisted contract.
type Handler struct {
	network arklib.Network
	client  client.Client
}

// NewHandler returns a VHTLC contract handler ready to be registered via
// the contract manager built-in handler registry.
func NewHandler(c client.Client, network arklib.Network) *Handler {
	return &Handler{
		network: network,
		client:  c,
	}
}

// Derivable returns false — VHTLC contracts require counterparty data
// (pubkeys, preimage hash, locktimes) and cannot be derived from an HD key alone.
// Callers must provide WithParams(*vhtlc.Opts) when calling Manager.NewContract.
func (h *Handler) Derivable() bool { return false }

// NewContract builds a VHTLC contract from the caller-provided key and params.
// params must be *vhtlc.Opts; returns an error otherwise.
func (h *Handler) NewContract(
	ctx context.Context, keyRef identity.KeyRef, params any,
) (*types.Contract, error) {
	p, ok := params.(*vhtlc.Opts)
	if !ok || p == nil {
		return nil, fmt.Errorf(
			"vhtlc handler requires *vhtlc.Opts, got %T", params,
		)
	}
	checkpointExitPath, err := h.resolveCheckpointExitPath(ctx)
	if err != nil {
		return nil, err
	}
	return createContract(*p, keyRef, h.network, checkpointExitPath)
}

func (h *Handler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	keyID, err := requireParam(c, paramOwnerKeyID)
	if err != nil {
		return nil, err
	}
	pubHex, err := requireParam(c, paramOwnerKey)
	if err != nil {
		return nil, err
	}
	buf, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("vhtlc contract %s: invalid owner key hex: %w", c.Script, err)
	}
	pub, err := schnorr.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("vhtlc contract %s: invalid owner key: %w", c.Script, err)
	}
	return &identity.KeyRef{Id: keyID, PubKey: pub}, nil
}

func (h *Handler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	keyRef, err := h.GetKeyRef(c)
	if err != nil {
		return nil, err
	}

	keys := map[string]string{c.Script: keyRef.Id}

	checkpointExitPath, err := h.getCheckpointExitPath(c)
	if err != nil {
		return nil, err
	}

	opts, err := OptsFromContract(c)
	if err != nil {
		return nil, err
	}
	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("vhtlc contract %s: rebuild script: %w", c.Script, err)
	}

	exitPath := &script.CSVMultisigClosure{}
	valid, err := exitPath.Decode(checkpointExitPath)
	if err != nil {
		return nil, fmt.Errorf("vhtlc contract %s: decode checkpoint exit path: %w", c.Script, err)
	}
	if !valid {
		return nil, fmt.Errorf("vhtlc contract %s: invalid checkpoint exit path", c.Script)
	}

	for _, closure := range []script.Closure{
		vhtlcScript.ClaimClosure,
		vhtlcScript.RefundClosure,
		vhtlcScript.RefundWithoutReceiverClosure,
	} {
		if err := addCheckpointKeyRef(keys, exitPath, closure, keyRef); err != nil {
			return nil, fmt.Errorf("vhtlc contract %s: checkpoint key ref: %w", c.Script, err)
		}
	}

	return keys, nil
}

func (h *Handler) GetSignerKey(c types.Contract) (*btcec.PublicKey, error) {
	return parseCompressedParam(c, paramServer)
}

// GetExitDelay returns the conservative (longest) exit delay:
// refundWithoutReceiverDelay. This is always safe regardless of
// whether the wallet is the sender or receiver.
func (h *Handler) GetExitDelay(c types.Contract) (*arklib.RelativeLocktime, error) {
	delay, err := parseRelativeLocktime(
		c, paramRefundWithoutReceiverDelayType, paramRefundWithoutReceiverDelayValue,
	)
	if err != nil {
		return nil, err
	}
	return &delay, nil
}

func (h *Handler) GetTapscripts(c types.Contract) ([]string, error) {
	opts, err := OptsFromContract(c)
	if err != nil {
		return nil, err
	}
	s, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("vhtlc contract %s: rebuild script: %w", c.Script, err)
	}
	return s.Encode()
}

// Compile-time check.
var _ handlers.Handler = (*Handler)(nil)

// createContract builds a VHTLC contract entry. ownerKeyRef is the wallet's
// identity key — stored so GetKeyRef can return it for signing.
func createContract(
	opts vhtlc.Opts,
	ownerKeyRef identity.KeyRef,
	network arklib.Network,
	checkpointExitPath string,
) (*types.Contract, error) {
	s, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("build vhtlc script: %w", err)
	}
	tapKey, _, err := s.TapTree()
	if err != nil {
		return nil, fmt.Errorf("compute vhtlc tap tree: %w", err)
	}
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("compute vhtlc pkScript: %w", err)
	}
	addr, err := s.Address(network.Addr)
	if err != nil {
		return nil, fmt.Errorf("encode vhtlc address: %w", err)
	}

	params := map[string]string{
		paramOwnerKeyID: ownerKeyRef.Id,
		paramOwnerKey: hex.EncodeToString(
			schnorr.SerializePubKey(ownerKeyRef.PubKey),
		),
		paramSender: hex.EncodeToString(opts.Sender.SerializeCompressed()),
		paramReceiver: hex.EncodeToString(
			opts.Receiver.SerializeCompressed(),
		),
		paramServer:         hex.EncodeToString(opts.Server.SerializeCompressed()),
		paramPreimageHash:   hex.EncodeToString(opts.PreimageHash),
		paramRefundLocktime: strconv.FormatUint(uint64(opts.RefundLocktime), 10),
		paramClaimDelayType: locktimeTypeName(opts.UnilateralClaimDelay.Type),
		paramClaimDelayValue: strconv.FormatUint(
			uint64(opts.UnilateralClaimDelay.Value),
			10,
		),
		paramRefundDelayType: locktimeTypeName(opts.UnilateralRefundDelay.Type),
		paramRefundDelayValue: strconv.FormatUint(
			uint64(opts.UnilateralRefundDelay.Value),
			10,
		),
		paramRefundWithoutReceiverDelayType: locktimeTypeName(
			opts.UnilateralRefundWithoutReceiverDelay.Type,
		),
		paramRefundWithoutReceiverDelayValue: strconv.FormatUint(
			uint64(opts.UnilateralRefundWithoutReceiverDelay.Value),
			10,
		),
	}

	if opts.NonInteractiveClaim != nil {
		params[paramNICReceiverPkScript] = hex.EncodeToString(
			opts.NonInteractiveClaim.ReceiverPkScript,
		)
		params[paramNICIntrospectorPubKey] = hex.EncodeToString(
			opts.NonInteractiveClaim.IntrospectorPubKey.SerializeCompressed(),
		)
	}
	params[paramCheckpointExitPath] = checkpointExitPath

	return &types.Contract{
		Type:      types.ContractTypeVHTLC,
		Script:    hex.EncodeToString(pkScript),
		Address:   addr,
		Params:    params,
		State:     types.ContractStateActive,
		CreatedAt: time.Now(),
	}, nil
}

// OptsFromContract reconstructs vhtlc.Opts from a persisted contract's params.
func OptsFromContract(c types.Contract) (vhtlc.Opts, error) {
	sender, err := parseCompressedParam(c, paramSender)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	receiver, err := parseCompressedParam(c, paramReceiver)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	server, err := parseCompressedParam(c, paramServer)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	preimageHashHex, err := requireParam(c, paramPreimageHash)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	preimageHash, err := hex.DecodeString(preimageHashHex)
	if err != nil {
		return vhtlc.Opts{}, fmt.Errorf(
			"vhtlc contract %s: invalid preimage hash: %w",
			c.Script,
			err,
		)
	}
	refundLockStr, err := requireParam(c, paramRefundLocktime)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	refundLock, err := strconv.ParseUint(refundLockStr, 10, 32)
	if err != nil {
		return vhtlc.Opts{}, fmt.Errorf(
			"vhtlc contract %s: invalid refund locktime: %w",
			c.Script,
			err,
		)
	}
	claimDelay, err := parseRelativeLocktime(c, paramClaimDelayType, paramClaimDelayValue)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	refundDelay, err := parseRelativeLocktime(c, paramRefundDelayType, paramRefundDelayValue)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	refundWithoutReceiverDelay, err := parseRelativeLocktime(
		c, paramRefundWithoutReceiverDelayType, paramRefundWithoutReceiverDelayValue,
	)
	if err != nil {
		return vhtlc.Opts{}, err
	}

	opts := vhtlc.Opts{
		Sender:                               sender,
		Receiver:                             receiver,
		Server:                               server,
		PreimageHash:                         preimageHash,
		RefundLocktime:                       arklib.AbsoluteLocktime(refundLock),
		UnilateralClaimDelay:                 claimDelay,
		UnilateralRefundDelay:                refundDelay,
		UnilateralRefundWithoutReceiverDelay: refundWithoutReceiverDelay,
	}

	// Non-interactive claim params are optional.
	if recvHex, ok := c.Params[paramNICReceiverPkScript]; ok && recvHex != "" {
		recv, err := hex.DecodeString(recvHex)
		if err != nil {
			return vhtlc.Opts{}, fmt.Errorf(
				"vhtlc contract %s: invalid NIC receiver pkScript: %w",
				c.Script,
				err,
			)
		}
		introspector, err := parseCompressedParam(c, paramNICIntrospectorPubKey)
		if err != nil {
			return vhtlc.Opts{}, err
		}
		opts.NonInteractiveClaim = &vhtlc.NonInteractiveClaimOpts{
			ReceiverPkScript:   recv,
			IntrospectorPubKey: introspector,
		}
	}

	return opts, nil
}

// --- helpers ---

func (h *Handler) resolveCheckpointExitPath(ctx context.Context) (string, error) {
	if h.client == nil {
		return "", fmt.Errorf("missing client")
	}
	info, err := h.client.GetInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get server info: %w", err)
	}
	return info.CheckpointTapscript, nil
}

func (h *Handler) getCheckpointExitPath(c types.Contract) ([]byte, error) {
	checkpointExitPath, err := requireParam(c, paramCheckpointExitPath)
	if err != nil {
		return nil, err
	}

	buf, err := hex.DecodeString(checkpointExitPath)
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint exit path hex: %w", err)
	}
	return buf, nil
}

func addCheckpointKeyRef(
	keys map[string]string,
	exitPath *script.CSVMultisigClosure,
	spendPath script.Closure,
	keyRef *identity.KeyRef,
) error {
	if !closureContainsKey(spendPath, keyRef.PubKey) {
		return nil
	}

	rawCheckpointScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{exitPath, spendPath},
	}
	taprootKey, _, err := rawCheckpointScript.TapTree()
	if err != nil {
		return fmt.Errorf("compute checkpoint taproot key: %w", err)
	}

	checkpointScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return fmt.Errorf("compute checkpoint script: %w", err)
	}

	keys[hex.EncodeToString(checkpointScript)] = keyRef.Id
	return nil
}

func closureContainsKey(closure script.Closure, pubkey *btcec.PublicKey) bool {
	if pubkey == nil {
		return false
	}

	xOnlyPubkey := schnorr.SerializePubKey(pubkey)
	for _, candidate := range closurePubKeys(closure) {
		if bytes.Equal(schnorr.SerializePubKey(candidate), xOnlyPubkey) {
			return true
		}
	}
	return false
}

func closurePubKeys(closure script.Closure) []*btcec.PublicKey {
	switch c := closure.(type) {
	case *script.MultisigClosure:
		return c.PubKeys
	case *script.CLTVMultisigClosure:
		return c.PubKeys
	case *script.ConditionMultisigClosure:
		return c.PubKeys
	default:
		return nil
	}
}

func requireParam(c types.Contract, key string) (string, error) {
	if c.Params == nil {
		return "", fmt.Errorf("vhtlc contract %s: no params", c.Script)
	}
	v, ok := c.Params[key]
	if !ok || v == "" {
		return "", fmt.Errorf("vhtlc contract %s: missing param %q", c.Script, key)
	}
	return v, nil
}

func parseCompressedParam(c types.Contract, key string) (*btcec.PublicKey, error) {
	raw, err := requireParam(c, key)
	if err != nil {
		return nil, err
	}
	buf, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("vhtlc contract %s: invalid %s hex: %w", c.Script, key, err)
	}
	pub, err := btcec.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("vhtlc contract %s: invalid %s: %w", c.Script, key, err)
	}
	return pub, nil
}

func parseRelativeLocktime(
	c types.Contract, typeKey, valueKey string,
) (arklib.RelativeLocktime, error) {
	typeStr, err := requireParam(c, typeKey)
	if err != nil {
		return arklib.RelativeLocktime{}, err
	}
	valueStr, err := requireParam(c, valueKey)
	if err != nil {
		return arklib.RelativeLocktime{}, err
	}
	value, err := strconv.ParseUint(valueStr, 10, 32)
	if err != nil {
		return arklib.RelativeLocktime{}, fmt.Errorf(
			"vhtlc contract %s: invalid %s: %w", c.Script, valueKey, err,
		)
	}
	var locktimeType arklib.RelativeLocktimeType
	switch typeStr {
	case locktimeTagBlock:
		locktimeType = arklib.LocktimeTypeBlock
	case locktimeTagSecond:
		locktimeType = arklib.LocktimeTypeSecond
	default:
		return arklib.RelativeLocktime{}, fmt.Errorf(
			"vhtlc contract %s: unknown locktime type %q for %s", c.Script, typeStr, typeKey,
		)
	}
	return arklib.RelativeLocktime{Type: locktimeType, Value: uint32(value)}, nil
}

func locktimeTypeName(t arklib.RelativeLocktimeType) string {
	switch t {
	case arklib.LocktimeTypeBlock:
		return locktimeTagBlock
	case arklib.LocktimeTypeSecond:
		return locktimeTagSecond
	default:
		return ""
	}
}
