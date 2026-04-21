package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

const TypeVHTLC = "vhtlc"

// cltvHeightThreshold is the BIP65 boundary: absolute locktimes below this are
// interpreted as block heights; at or above are Unix timestamps (seconds).
const cltvHeightThreshold = uint32(500_000_000)

// VHTLCHandler derives a Virtual Hash Time-Locked Contract.
//
// Required rawParams keys (names match the ts-sdk for cross-SDK compatibility):
//
//	"sender"              — 32-byte Schnorr pubkey hex (sending party)
//	"receiver"            — 32-byte Schnorr pubkey hex (receiving party)
//	"hash"                — 20-byte HASH160 hex (preimage hash)
//	"refundLocktime"      — absolute locktime (uint32 decimal string)
//	"claimDelay"          — BIP68 sequence number for unilateral claim (decimal string)
//	"refundDelay"         — BIP68 sequence number for unilateral refund (decimal string)
//	"refundNoReceiverDelay" — BIP68 sequence number for sender-only unilateral refund
//
// The Ark server pubkey is taken from cfg.SignerPubKey (not a rawParam).
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

func (h *VHTLCHandler) Type() string { return TypeVHTLC }

func (h *VHTLCHandler) DeriveContract(
	_ context.Context,
	key wallet.KeyRef,
	cfg *clientTypes.Config,
	rawParams map[string]string,
) (*contract.Contract, error) {
	p, err := parseVHTLCParams(rawParams, cfg.SignerPubKey)
	if err != nil {
		return nil, err
	}

	condScript, err := preimageConditionScript(p.hash)
	if err != nil {
		return nil, fmt.Errorf("condition script: %w", err)
	}

	vtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			// [0] claim: receiver + server with preimage
			&script.ConditionMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{p.receiver, p.server},
				},
				Condition: condScript,
			},
			// [1] refund: sender + receiver + server (3-of-3)
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{p.sender, p.receiver, p.server},
			},
			// [2] refundWithoutReceiver: sender + server after CLTV
			&script.CLTVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{p.sender, p.server},
				},
				Locktime: p.refundLocktime,
			},
			// [3] unilateralClaim: receiver with preimage after CSV
			&script.ConditionCSVMultisigClosure{
				CSVMultisigClosure: script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{p.receiver},
					},
					Locktime: p.claimDelay,
				},
				Condition: condScript,
			},
			// [4] unilateralRefund: sender + receiver after CSV
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{p.sender, p.receiver},
				},
				Locktime: p.refundDelay,
			},
			// [5] unilateralRefundWithoutReceiver: sender alone after CSV
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{p.sender},
				},
				Locktime: p.refundNoReceiverDelay,
			},
		},
	}

	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("vhtlc tap tree: %w", err)
	}

	arkAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerPubKey,
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

	serialized, err := h.SerializeParams(p)
	if err != nil {
		return nil, err
	}
	serialized["keyId"] = key.Id

	return &contract.Contract{
		Type:       TypeVHTLC,
		Params:     serialized,
		Script:     hex.EncodeToString(pkScript),
		Address:    encodedArkAddr,
		State:      contract.StateActive,
		CreatedAt:  time.Now(),
		Tapscripts: tapscripts,
	}, nil
}

// SelectPath returns the best spending path for the given context.
// Role is resolved by comparing PathContext.WalletPubKey against sender/receiver.
func (h *VHTLCHandler) SelectPath(
	_ context.Context, c *contract.Contract, pctx contract.PathContext,
) (*contract.PathSelection, error) {
	if len(c.Tapscripts) < 6 {
		return nil, fmt.Errorf("vhtlc contract requires 6 tapscripts, got %d", len(c.Tapscripts))
	}

	role, err := resolveVHTLCRole(c.Params, pctx.WalletPubKey)
	if err != nil || role == "" {
		return nil, err
	}

	hasPreimage := len(pctx.Preimage) > 0

	if pctx.Collaborative {
		if role == "receiver" && hasPreimage {
			sel, err := tapLeafSelection(c.Tapscripts[0], nil, nil)
			if err != nil {
				return nil, err
			}
			sel.ExtraWitness = [][]byte{pctx.Preimage}
			return sel, nil
		}
		if role == "sender" && isCltvSatisfied(c.Params, pctx) {
			return tapLeafSelection(c.Tapscripts[2], nil, nil)
		}
		return nil, nil
	}

	// Unilateral paths.
	if role == "receiver" && hasPreimage {
		seq, err := bip68SequenceFromParam(c.Params["claimDelay"])
		if err != nil {
			return nil, err
		}
		sel, err := tapLeafSelection(c.Tapscripts[3], &seq, nil)
		if err != nil {
			return nil, err
		}
		sel.ExtraWitness = [][]byte{pctx.Preimage}
		return sel, nil
	}
	if role == "sender" {
		seq, err := bip68SequenceFromParam(c.Params["refundNoReceiverDelay"])
		if err != nil {
			return nil, err
		}
		return tapLeafSelection(c.Tapscripts[5], &seq, nil)
	}
	return nil, nil
}

// GetSpendablePaths returns all paths available to the wallet's role.
// CSV timelocks are not checked (vtxo block height is not in PathContext).
func (h *VHTLCHandler) GetSpendablePaths(
	_ context.Context, c *contract.Contract, pctx contract.PathContext,
) ([]contract.PathSelection, error) {
	if len(c.Tapscripts) < 6 {
		return nil, fmt.Errorf("vhtlc contract requires 6 tapscripts, got %d", len(c.Tapscripts))
	}

	role, err := resolveVHTLCRole(c.Params, pctx.WalletPubKey)
	if err != nil || role == "" {
		return nil, err
	}

	hasPreimage := len(pctx.Preimage) > 0
	var paths []contract.PathSelection

	if pctx.Collaborative {
		if role == "receiver" && hasPreimage {
			sel, err := tapLeafSelection(c.Tapscripts[0], nil, nil)
			if err != nil {
				return nil, err
			}
			sel.ExtraWitness = [][]byte{pctx.Preimage}
			paths = append(paths, *sel)
		}
		if role == "sender" && isCltvSatisfied(c.Params, pctx) {
			sel, err := tapLeafSelection(c.Tapscripts[2], nil, nil)
			if err != nil {
				return nil, err
			}
			paths = append(paths, *sel)
		}
		return paths, nil
	}

	// Unilateral paths.
	if role == "receiver" && hasPreimage {
		seq, err := bip68SequenceFromParam(c.Params["claimDelay"])
		if err != nil {
			return nil, err
		}
		sel, err := tapLeafSelection(c.Tapscripts[3], &seq, nil)
		if err != nil {
			return nil, err
		}
		sel.ExtraWitness = [][]byte{pctx.Preimage}
		paths = append(paths, *sel)
	}
	if role == "sender" {
		seq, err := bip68SequenceFromParam(c.Params["refundNoReceiverDelay"])
		if err != nil {
			return nil, err
		}
		sel, err := tapLeafSelection(c.Tapscripts[5], &seq, nil)
		if err != nil {
			return nil, err
		}
		paths = append(paths, *sel)
	}
	return paths, nil
}

func (h *VHTLCHandler) SerializeParams(params any) (map[string]string, error) {
	p, ok := params.(*vhtlcParams)
	if !ok {
		return nil, fmt.Errorf("VHTLCHandler: params must be *vhtlcParams")
	}

	claimSeq, err := arklib.BIP68Sequence(p.claimDelay)
	if err != nil {
		return nil, fmt.Errorf("serialize claimDelay: %w", err)
	}
	refundSeq, err := arklib.BIP68Sequence(p.refundDelay)
	if err != nil {
		return nil, fmt.Errorf("serialize refundDelay: %w", err)
	}
	noRcvrSeq, err := arklib.BIP68Sequence(p.refundNoReceiverDelay)
	if err != nil {
		return nil, fmt.Errorf("serialize refundNoReceiverDelay: %w", err)
	}

	return map[string]string{
		"sender":                hex.EncodeToString(schnorr.SerializePubKey(p.sender)),
		"receiver":              hex.EncodeToString(schnorr.SerializePubKey(p.receiver)),
		"server":                hex.EncodeToString(schnorr.SerializePubKey(p.server)),
		"hash":                  hex.EncodeToString(p.hash),
		"refundLocktime":        strconv.FormatUint(uint64(p.refundLocktime), 10),
		"claimDelay":            strconv.FormatUint(uint64(claimSeq), 10),
		"refundDelay":           strconv.FormatUint(uint64(refundSeq), 10),
		"refundNoReceiverDelay": strconv.FormatUint(uint64(noRcvrSeq), 10),
	}, nil
}

func (h *VHTLCHandler) DeserializeParams(params map[string]string) (any, error) {
	return parseVHTLCParamsFromSerialized(params)
}

// ── internal types and helpers ────────────────────────────────────────────────

type vhtlcParams struct {
	sender                *btcec.PublicKey
	receiver              *btcec.PublicKey
	server                *btcec.PublicKey
	hash                  []byte
	refundLocktime        arklib.AbsoluteLocktime
	claimDelay            arklib.RelativeLocktime
	refundDelay           arklib.RelativeLocktime
	refundNoReceiverDelay arklib.RelativeLocktime
}

func parseVHTLCParams(raw map[string]string, serverPubKey *btcec.PublicKey) (*vhtlcParams, error) {
	if raw == nil {
		return nil, fmt.Errorf("vhtlc handler: rawParams is required")
	}

	sender, err := parsePubKey(raw, "sender")
	if err != nil {
		return nil, err
	}
	receiver, err := parsePubKey(raw, "receiver")
	if err != nil {
		return nil, err
	}

	server := serverPubKey
	if server == nil {
		server, err = parsePubKey(raw, "server")
		if err != nil {
			return nil, err
		}
	}

	hashHex, ok := raw["hash"]
	if !ok || hashHex == "" {
		return nil, fmt.Errorf("vhtlc handler: missing required param \"hash\"")
	}
	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("vhtlc handler: invalid hash hex: %w", err)
	}
	if len(hash) != 20 {
		return nil, fmt.Errorf("vhtlc handler: hash must be 20 bytes (HASH160), got %d", len(hash))
	}

	refundLT, err := parseAbsoluteLocktime(raw, "refundLocktime")
	if err != nil {
		return nil, err
	}
	claimDelay, err := parseBIP68Delay(raw, "claimDelay")
	if err != nil {
		return nil, err
	}
	refundDelay, err := parseBIP68Delay(raw, "refundDelay")
	if err != nil {
		return nil, err
	}
	noRcvrDelay, err := parseBIP68Delay(raw, "refundNoReceiverDelay")
	if err != nil {
		return nil, err
	}

	return &vhtlcParams{
		sender:                sender,
		receiver:              receiver,
		server:                server,
		hash:                  hash,
		refundLocktime:        refundLT,
		claimDelay:            claimDelay,
		refundDelay:           refundDelay,
		refundNoReceiverDelay: noRcvrDelay,
	}, nil
}

func parseVHTLCParamsFromSerialized(m map[string]string) (*vhtlcParams, error) {
	return parseVHTLCParams(m, nil)
}

func parsePubKey(raw map[string]string, key string) (*btcec.PublicKey, error) {
	hexVal, ok := raw[key]
	if !ok || hexVal == "" {
		return nil, fmt.Errorf("vhtlc handler: missing required param %q", key)
	}
	b, err := hex.DecodeString(hexVal)
	if err != nil {
		return nil, fmt.Errorf("vhtlc handler: invalid %s hex: %w", key, err)
	}
	pub, err := schnorr.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("vhtlc handler: invalid %s pubkey: %w", key, err)
	}
	return pub, nil
}

func parseAbsoluteLocktime(raw map[string]string, key string) (arklib.AbsoluteLocktime, error) {
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

// parseBIP68Delay decodes a BIP68 sequence number stored as a decimal string
// back into a RelativeLocktime.
func parseBIP68Delay(raw map[string]string, key string) (arklib.RelativeLocktime, error) {
	s, ok := raw[key]
	if !ok || s == "" {
		return arklib.RelativeLocktime{}, fmt.Errorf(
			"vhtlc handler: missing required param %q",
			key,
		)
	}
	return bip68DecodeString(s)
}

func bip68SequenceFromParam(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid BIP68 sequence param %q: %w", s, err)
	}
	return uint32(v), nil
}

// bip68DecodeString decodes a BIP68 sequence number (as decimal string) back
// to a RelativeLocktime, mirroring the ts-sdk sequenceToTimelock helper.
func bip68DecodeString(s string) (arklib.RelativeLocktime, error) {
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

// resolveVHTLCRole matches walletPubKey (32-byte Schnorr) against the stored
// sender/receiver params. Returns "sender", "receiver", or "".
func resolveVHTLCRole(params map[string]string, walletPubKey []byte) (string, error) {
	if len(walletPubKey) == 0 {
		return "", nil
	}
	for _, role := range []string{"sender", "receiver"} {
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

// isCltvSatisfied mirrors the ts-sdk isCltvSatisfied helper.
func isCltvSatisfied(params map[string]string, pctx contract.PathContext) bool {
	s, ok := params["refundLocktime"]
	if !ok {
		return false
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return false
	}
	locktime := uint32(v)
	if locktime < cltvHeightThreshold {
		if pctx.BlockHeight == nil {
			return false
		}
		return *pctx.BlockHeight >= locktime
	}
	return uint32(pctx.CurrentTime.Unix()) >= locktime
}
