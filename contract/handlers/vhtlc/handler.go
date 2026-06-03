package vhtlcHandler

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// ContractTypeVHTLC is the contract type for VHTLC contracts.
const ContractTypeVHTLC types.ContractType = "vhtlc"

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
}

// NewHandler returns a VHTLC contract handler ready to be registered via
// WithContractHandler(ContractTypeVHTLC, vhtlcHandler.NewHandler()).
func NewHandler(network arklib.Network) *Handler {
	return &Handler{
		network: network,
	}
}

// Derivable returns false — VHTLC contracts require counterparty data
// (pubkeys, preimage hash, locktimes) and cannot be derived from an HD key alone.
// Callers must provide WithParams(*ContractParams) when calling Manager.NewContract.
func (h *Handler) Derivable() bool { return false }

// NewContract builds a VHTLC contract from the caller-provided key and params.
// params must be *ContractParams; returns an error otherwise.
func (h *Handler) NewContract(
	_ context.Context, keyRef identity.KeyRef, params any,
) (*types.Contract, error) {
	p, ok := params.(*vhtlc.Opts)
	if !ok || p == nil {
		return nil, fmt.Errorf(
			"vhtlc handler requires *vhtlc.Opts, got %T", params,
		)
	}
	return createContract(*p, keyRef, h.network)
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
	return map[string]string{c.Script: keyRef.Id}, nil
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

	return &types.Contract{
		Type:      ContractTypeVHTLC,
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
