package contract

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// TypeVHTLC is the contract type string for virtual HTLC offchain contracts.
const TypeVHTLC = "vhtlc"

// VHTLC param keys — names match the ts-sdk for cross-SDK compatibility.
const (
	ParamVHTLCSender                = "sender"
	ParamVHTLCReceiver              = "receiver"
	ParamVHTLCServer                = "server"
	ParamVHTLCHash                  = "hash"
	ParamVHTLCRefundLocktime        = "refundLocktime"
	ParamVHTLCClaimDelay            = "claimDelay"
	ParamVHTLCRefundDelay           = "refundDelay"
	ParamVHTLCRefundNoReceiverDelay = "refundNoReceiverDelay"
)

// cltvHeightThreshold is the BIP65 boundary: absolute locktimes below this
// are block heights; at or above are Unix timestamps.
const cltvHeightThreshold = uint32(500_000_000)

// VHTLCHandler derives a Virtual Hash Time-Locked Contract.
//
// Tapscript leaf order (matches ts-sdk VHTLC.Script):
//
//	[0] claim                        ConditionMultisig     hash160 + [receiver, server]
//	[1] refund                       Multisig              [sender, receiver, server]
//	[2] refundWithoutReceiver        CLTVMultisig          refundLocktime + [sender, server]
//	[3] unilateralClaim              ConditionCSVMultisig  hash160 + claimDelay + [receiver]
//	[4] unilateralRefund             CSVMultisig           refundDelay + [sender, receiver]
//	[5] unilateralRefundWithoutRcvr  CSVMultisig           refundNoReceiverDelay + [sender]
type VHTLCHandler struct{}

// DeriveContract derives a VHTLC contract from the provided raw params.
//
// Required rawParams keys:
//
//	"sender"                — 32-byte Schnorr pubkey hex
//	"receiver"              — 32-byte Schnorr pubkey hex
//	"hash"                  — 20-byte HASH160 hex
//	"refundLocktime"        — absolute locktime as decimal uint32 string
//	"claimDelay"            — BIP68 sequence number as decimal string
//	"refundDelay"           — BIP68 sequence number as decimal string
//	"refundNoReceiverDelay" — BIP68 sequence number as decimal string
//
// The server pubkey is taken from cfg.SignerKey. An optional "keyId" entry
// in rawParams is stored as-is for caller tracking.
func (h *VHTLCHandler) DeriveContract(
	_ context.Context,
	rawParams map[string]string,
	cfg DelegateConfig,
) (*types.Contract, error) {
	if rawParams == nil {
		return nil, fmt.Errorf("vhtlc handler: rawParams is required")
	}

	opts, err := parseVHTLCOpts(rawParams, cfg.SignerKey)
	if err != nil {
		return nil, err
	}

	vtxoScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("vhtlc script: %w", err)
	}

	arkAddr, err := vtxoScript.Address(cfg.Network.Addr)
	if err != nil {
		return nil, fmt.Errorf("encode ark address: %w", err)
	}

	tapscripts := vtxoScript.GetRevealedTapscripts()

	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("vhtlc tap tree: %w", err)
	}

	pkScript, err := txscript.PayToTaprootScript(vtxoTapKey)
	if err != nil {
		return nil, fmt.Errorf("pkScript: %w", err)
	}

	params := serializeVHTLCOpts(opts)
	if keyID, ok := rawParams[ParamKeyID]; ok && keyID != "" {
		params[ParamKeyID] = keyID
	}
	params[ParamTapscripts] = serializeTapscripts(tapscripts)

	return &types.Contract{
		Type:      types.ContractTypeVHTLC,
		Params:    params,
		Script:    hex.EncodeToString(pkScript),
		Address:   arkAddr,
		State:     types.ContractStateActive,
		CreatedAt: time.Now(),
	}, nil
}

// SelectPath returns the best spending path for the given context.
//
// Role is resolved by comparing PathContext.WalletPubKey against stored sender/receiver.
// Returns nil (no error) when the wallet has no eligible path for the given context.
func (h *VHTLCHandler) SelectPath(
	_ context.Context, c *types.Contract, pctx PathContext,
) (*PathSelection, error) {
	tapscripts, err := parseTapscripts(c.Params[ParamTapscripts])
	if err != nil {
		return nil, err
	}
	if len(tapscripts) < 6 {
		return nil, fmt.Errorf("vhtlc contract requires 6 tapscripts, got %d", len(tapscripts))
	}

	role, err := resolveVHTLCRole(c.Params, pctx.WalletPubKey)
	if err != nil || role == "" {
		return nil, err
	}

	hasPreimage := len(pctx.Preimage) > 0

	if pctx.Collaborative {
		if role == "receiver" && hasPreimage {
			sel, err := tapLeafSelection(tapscripts[0], nil, nil)
			if err != nil {
				return nil, err
			}
			sel.ExtraWitness = [][]byte{pctx.Preimage}
			return sel, nil
		}
		if role == "sender" && isVHTLCCltvSatisfied(c.Params, pctx) {
			lt, _ := vhtlcRefundLocktime(c.Params)
			return tapLeafSelection(tapscripts[2], nil, &lt)
		}
		return nil, nil
	}

	// Unilateral paths.
	if role == "receiver" && hasPreimage {
		seq, err := vhtlcBIP68SeqFromParam(c.Params[ParamVHTLCClaimDelay])
		if err != nil {
			return nil, err
		}
		sel, err := tapLeafSelection(tapscripts[3], &seq, nil)
		if err != nil {
			return nil, err
		}
		sel.ExtraWitness = [][]byte{pctx.Preimage}
		return sel, nil
	}
	if role == "sender" {
		seq, err := vhtlcBIP68SeqFromParam(c.Params[ParamVHTLCRefundNoReceiverDelay])
		if err != nil {
			return nil, err
		}
		return tapLeafSelection(tapscripts[5], &seq, nil)
	}
	return nil, nil
}

// GetSpendablePaths returns all paths available to the wallet's role.
// CSV timelocks are not checked (vtxo block height is unavailable in PathContext).
func (h *VHTLCHandler) GetSpendablePaths(
	_ context.Context, c *types.Contract, pctx PathContext,
) ([]PathSelection, error) {
	tapscripts, err := parseTapscripts(c.Params[ParamTapscripts])
	if err != nil {
		return nil, err
	}
	if len(tapscripts) < 6 {
		return nil, fmt.Errorf("vhtlc contract requires 6 tapscripts, got %d", len(tapscripts))
	}

	role, err := resolveVHTLCRole(c.Params, pctx.WalletPubKey)
	if err != nil || role == "" {
		return nil, err
	}

	hasPreimage := len(pctx.Preimage) > 0
	var paths []PathSelection

	if pctx.Collaborative {
		if role == "receiver" && hasPreimage {
			sel, err := tapLeafSelection(tapscripts[0], nil, nil)
			if err != nil {
				return nil, err
			}
			sel.ExtraWitness = [][]byte{pctx.Preimage}
			paths = append(paths, *sel)
		}
		if role == "sender" {
			lt, _ := vhtlcRefundLocktime(c.Params)
			sel, err := tapLeafSelection(tapscripts[2], nil, &lt)
			if err != nil {
				return nil, err
			}
			paths = append(paths, *sel)
		}
		return paths, nil
	}

	// Unilateral paths.
	if role == "receiver" && hasPreimage {
		seq, err := vhtlcBIP68SeqFromParam(c.Params[ParamVHTLCClaimDelay])
		if err != nil {
			return nil, err
		}
		sel, err := tapLeafSelection(tapscripts[3], &seq, nil)
		if err != nil {
			return nil, err
		}
		sel.ExtraWitness = [][]byte{pctx.Preimage}
		paths = append(paths, *sel)
	}
	if role == "sender" {
		seq, err := vhtlcBIP68SeqFromParam(c.Params[ParamVHTLCRefundNoReceiverDelay])
		if err != nil {
			return nil, err
		}
		sel, err := tapLeafSelection(tapscripts[5], &seq, nil)
		if err != nil {
			return nil, err
		}
		paths = append(paths, *sel)
	}
	return paths, nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

func parseVHTLCOpts(raw map[string]string, defaultServer *btcec.PublicKey) (vhtlc.Opts, error) {
	senderBytes, err := vhtlcParsePubKeyBytes(raw, ParamVHTLCSender)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	sender, err := schnorr.ParsePubKey(senderBytes)
	if err != nil {
		return vhtlc.Opts{}, fmt.Errorf("vhtlc handler: invalid sender pubkey: %w", err)
	}

	receiverBytes, err := vhtlcParsePubKeyBytes(raw, ParamVHTLCReceiver)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	receiver, err := schnorr.ParsePubKey(receiverBytes)
	if err != nil {
		return vhtlc.Opts{}, fmt.Errorf("vhtlc handler: invalid receiver pubkey: %w", err)
	}

	hashHex, ok := raw[ParamVHTLCHash]
	if !ok || hashHex == "" {
		return vhtlc.Opts{}, fmt.Errorf("vhtlc handler: missing required param %q", ParamVHTLCHash)
	}
	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return vhtlc.Opts{}, fmt.Errorf("vhtlc handler: invalid hash hex: %w", err)
	}
	if len(hash) != 20 {
		return vhtlc.Opts{}, fmt.Errorf(
			"vhtlc handler: hash must be 20 bytes (HASH160), got %d",
			len(hash),
		)
	}

	refundLT, err := vhtlcParseAbsoluteLocktime(raw, ParamVHTLCRefundLocktime)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	claimDelay, err := vhtlcParseBIP68Delay(raw, ParamVHTLCClaimDelay)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	refundDelay, err := vhtlcParseBIP68Delay(raw, ParamVHTLCRefundDelay)
	if err != nil {
		return vhtlc.Opts{}, err
	}
	noRcvrDelay, err := vhtlcParseBIP68Delay(raw, ParamVHTLCRefundNoReceiverDelay)
	if err != nil {
		return vhtlc.Opts{}, err
	}

	// Prefer the stored "server" param for round-trip deserialization; fall
	// back to cfg.SignerKey on initial creation.
	server := defaultServer
	if serverHex, ok := raw[ParamVHTLCServer]; ok && serverHex != "" {
		b, err := hex.DecodeString(serverHex)
		if err == nil {
			if parsed, err := schnorr.ParsePubKey(b); err == nil {
				server = parsed
			}
		}
	}
	if server == nil {
		return vhtlc.Opts{}, fmt.Errorf("vhtlc handler: server pubkey is required")
	}

	return vhtlc.Opts{
		Sender:                               sender,
		Receiver:                             receiver,
		Server:                               server,
		PreimageHash:                         hash,
		RefundLocktime:                       refundLT,
		UnilateralClaimDelay:                 claimDelay,
		UnilateralRefundDelay:                refundDelay,
		UnilateralRefundWithoutReceiverDelay: noRcvrDelay,
	}, nil
}

func serializeVHTLCOpts(opts vhtlc.Opts) map[string]string {
	claimSeq, _ := arklib.BIP68Sequence(opts.UnilateralClaimDelay)
	refundSeq, _ := arklib.BIP68Sequence(opts.UnilateralRefundDelay)
	noRcvrSeq, _ := arklib.BIP68Sequence(opts.UnilateralRefundWithoutReceiverDelay)

	return map[string]string{
		ParamVHTLCSender:                hex.EncodeToString(schnorr.SerializePubKey(opts.Sender)),
		ParamVHTLCReceiver:              hex.EncodeToString(schnorr.SerializePubKey(opts.Receiver)),
		ParamVHTLCServer:                hex.EncodeToString(schnorr.SerializePubKey(opts.Server)),
		ParamVHTLCHash:                  hex.EncodeToString(opts.PreimageHash),
		ParamVHTLCRefundLocktime:        strconv.FormatUint(uint64(opts.RefundLocktime), 10),
		ParamVHTLCClaimDelay:            strconv.FormatUint(uint64(claimSeq), 10),
		ParamVHTLCRefundDelay:           strconv.FormatUint(uint64(refundSeq), 10),
		ParamVHTLCRefundNoReceiverDelay: strconv.FormatUint(uint64(noRcvrSeq), 10),
	}
}

func vhtlcParsePubKeyBytes(raw map[string]string, key string) ([]byte, error) {
	hexVal, ok := raw[key]
	if !ok || hexVal == "" {
		return nil, fmt.Errorf("vhtlc handler: missing required param %q", key)
	}
	b, err := hex.DecodeString(hexVal)
	if err != nil {
		return nil, fmt.Errorf("vhtlc handler: invalid %s hex: %w", key, err)
	}
	return b, nil
}

func vhtlcParseAbsoluteLocktime(
	raw map[string]string,
	key string,
) (arklib.AbsoluteLocktime, error) {
	s, ok := raw[key]
	if !ok || s == "" {
		return 0, fmt.Errorf("vhtlc handler: missing required param %q", key)
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("vhtlc handler: invalid %s: %w", key, err)
	}
	return arklib.AbsoluteLocktime(v), nil
}

func vhtlcParseBIP68Delay(raw map[string]string, key string) (arklib.RelativeLocktime, error) {
	s, ok := raw[key]
	if !ok || s == "" {
		return arklib.RelativeLocktime{}, fmt.Errorf(
			"vhtlc handler: missing required param %q",
			key,
		)
	}
	return vhtlcDecodeBIP68(s)
}

// vhtlcDecodeBIP68 decodes a BIP68 sequence number (decimal string) back to a
// RelativeLocktime. Mirrors the ts-sdk sequenceToTimelock helper.
func vhtlcDecodeBIP68(s string) (arklib.RelativeLocktime, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return arklib.RelativeLocktime{}, fmt.Errorf("invalid BIP68 sequence %q: %w", s, err)
	}
	seq := uint32(v)
	const (
		seqLocktimeTypeFlagBit = uint32(1 << 22)
		seqLocktimeMask        = uint32(0x0000ffff)
		seqLocktimeGranularity = 9
	)
	if seq&seqLocktimeTypeFlagBit != 0 {
		value := (seq & seqLocktimeMask) << seqLocktimeGranularity
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: value}, nil
	}
	return arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeBlock,
		Value: seq & seqLocktimeMask,
	}, nil
}

// vhtlcBIP68SeqFromParam parses a BIP68 sequence number param as a raw uint32
// suitable for use as PathSelection.Sequence.
func vhtlcBIP68SeqFromParam(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid BIP68 sequence param %q: %w", s, err)
	}
	return uint32(v), nil
}

// resolveVHTLCRole returns "sender", "receiver", or "" if walletPubKey does
// not match either role. walletPubKey must be a 32-byte Schnorr pubkey.
func resolveVHTLCRole(params map[string]string, walletPubKey []byte) (string, error) {
	if len(walletPubKey) == 0 {
		return "", nil
	}
	for _, role := range []string{ParamVHTLCSender, ParamVHTLCReceiver} {
		stored, ok := params[role]
		if !ok {
			continue
		}
		b, err := hex.DecodeString(stored)
		if err != nil {
			return "", fmt.Errorf("invalid %s param: %w", role, err)
		}
		if bytes.Equal(walletPubKey, b) {
			return role, nil
		}
	}
	return "", nil
}

// isVHTLCCltvSatisfied returns true when the stored refundLocktime has been
// reached by the current block height or timestamp in pctx.
func isVHTLCCltvSatisfied(params map[string]string, pctx PathContext) bool {
	lt, err := vhtlcRefundLocktime(params)
	if err != nil {
		return false
	}
	if lt < cltvHeightThreshold {
		return pctx.BlockHeight != nil && *pctx.BlockHeight >= lt
	}
	return uint32(pctx.CurrentTime.Unix()) >= lt
}

func vhtlcRefundLocktime(params map[string]string) (uint32, error) {
	s, ok := params[ParamVHTLCRefundLocktime]
	if !ok {
		return 0, fmt.Errorf("missing %s param", ParamVHTLCRefundLocktime)
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid refundLocktime %q: %w", s, err)
	}
	return uint32(v), nil
}
