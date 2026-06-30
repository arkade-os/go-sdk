package htlcHandler

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

const (
	paramClaimKeyID     = "claimKeyId"
	paramRefundKeyID    = "refundKeyId"
	paramClaimKey       = "claimKey"
	paramRefundKey      = "refundKey"
	paramServerKey      = "serverKey"
	paramPreimageHash   = "preimageHash"
	paramRefundLocktime = "refundLocktime"
)

type Opts = htlc.Opts

// Handler creates Bitcoin HTLC lockup contracts for chain swaps.
type Handler struct {
	network arklib.Network
}

func NewHandler(network arklib.Network) handlers.Handler {
	return &Handler{network: network}
}

// Derivable returns false because BTC HTLC contracts require the Boltz swap
// tree and server key. They cannot be discovered from the wallet key alone.
func (h *Handler) Derivable() bool { return false }

func (h *Handler) NewContract(
	_ context.Context, keyRef identity.KeyRef, params any,
) (*types.Contract, error) {
	p, ok := params.(*htlc.Opts)
	if !ok || p == nil {
		return nil, fmt.Errorf("htlc handler requires *htlc.Opts, got %T", params)
	}

	return createContract(*p, keyRef, h.network)
}

func (h *Handler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	optionalParam := func(c types.Contract, name string) (string, bool, error) {
		if c.Params == nil {
			return "", false, fmt.Errorf("htlc contract %s: no params", c.Script)
		}
		v, ok := c.Params[name]
		if !ok || v == "" {
			return "", false, nil
		}
		return v, true, nil
	}

	claimKeyID, hasClaimKeyID, err := optionalParam(c, paramClaimKeyID)
	if err != nil {
		return nil, err
	}
	refundKeyID, hasRefundKeyID, err := optionalParam(c, paramRefundKeyID)
	if err != nil {
		return nil, err
	}
	if hasClaimKeyID == hasRefundKeyID {
		if hasClaimKeyID {
			return nil, fmt.Errorf(
				"htlc contract %s: expected exactly one of %q or %q",
				c.Script, paramClaimKeyID, paramRefundKeyID,
			)
		}
		return nil, fmt.Errorf(
			"htlc contract %s: missing wallet key ID: expected %q or %q",
			c.Script, paramClaimKeyID, paramRefundKeyID,
		)
	}

	if hasClaimKeyID {
		pub, err := parseCompressedParam(c, paramClaimKey)
		if err != nil {
			return nil, err
		}
		return &identity.KeyRef{Id: claimKeyID, PubKey: pub}, nil
	}
	pub, err := parseCompressedParam(c, paramRefundKey)
	if err != nil {
		return nil, err
	}
	return &identity.KeyRef{Id: refundKeyID, PubKey: pub}, nil
}

func (h *Handler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	keyRef, err := h.GetKeyRef(c)
	if err != nil {
		return nil, err
	}

	return map[string]string{c.Script: keyRef.Id}, nil
}

func (h *Handler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}

// GetExitDelay returns nil because BTC HTLC has no Ark relative exit delay.
// Its refund timeout is an absolute CLTV stored in RefundLocktime.
func (h *Handler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}

func (h *Handler) GetTapscripts(c types.Contract) ([]string, error) {
	keyRef, err := h.GetKeyRef(c)
	if err != nil {
		return nil, err
	}
	opts, err := OptsFromContract(c)
	if err != nil {
		return nil, err
	}
	htlcScript, err := htlc.NewHTLCScriptFromOpts(opts, keyRef.PubKey)
	if err != nil {
		return nil, fmt.Errorf("htlc contract %s: rebuild script: %w", c.Script, err)
	}

	return []string{
		hex.EncodeToString(htlcScript.ClaimScript),
		hex.EncodeToString(htlcScript.RefundScript),
	}, nil
}

func createContract(
	p htlc.Opts,
	keyRef identity.KeyRef,
	network arklib.Network,
) (*types.Contract, error) {
	opts, claimKeyID, refundKeyID, err := prepareOwnedOpts(p, keyRef)
	if err != nil {
		return nil, err
	}

	htlcScript, err := htlc.NewHTLCScriptFromOpts(opts, keyRef.PubKey)
	if err != nil {
		return nil, err
	}

	outputScript, err := txscript.PayToTaprootScript(htlcScript.TaprootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTLC output script: %w", err)
	}

	btcNetwork := utils.ToBitcoinNetwork(network)
	address, err := btcutil.NewAddressTaproot(
		htlcScript.TaprootKey.SerializeCompressed()[1:],
		&btcNetwork,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTLC address: %w", err)
	}

	params := map[string]string{
		paramClaimKey:       hex.EncodeToString(opts.ClaimKey.SerializeCompressed()),
		paramRefundKey:      hex.EncodeToString(opts.RefundKey.SerializeCompressed()),
		paramServerKey:      hex.EncodeToString(opts.ServerKey.SerializeCompressed()),
		paramPreimageHash:   hex.EncodeToString(opts.PreimageHash),
		paramRefundLocktime: strconv.FormatUint(uint64(opts.RefundLocktime), 10),
	}
	if claimKeyID != "" {
		params[paramClaimKeyID] = claimKeyID
	}
	if refundKeyID != "" {
		params[paramRefundKeyID] = refundKeyID
	}

	return &types.Contract{
		Type:      types.ContractTypeHTLC,
		Params:    params,
		Script:    hex.EncodeToString(outputScript),
		Address:   address.EncodeAddress(),
		State:     types.ContractStateActive,
		CreatedAt: time.Now(),
	}, nil
}

func prepareOwnedOpts(
	opts htlc.Opts,
	keyRef identity.KeyRef,
) (htlc.Opts, string, string, error) {
	if keyRef.Id == "" {
		return htlc.Opts{}, "", "", fmt.Errorf("missing wallet key ID")
	}
	if keyRef.PubKey == nil {
		return htlc.Opts{}, "", "", fmt.Errorf("missing wallet pubkey")
	}
	if opts.ClaimKey == nil && opts.RefundKey == nil {
		return htlc.Opts{}, "", "", fmt.Errorf("missing counterparty HTLC key")
	}
	if opts.RefundLocktime == 0 {
		return htlc.Opts{}, "", "", fmt.Errorf("missing refund locktime")
	}

	var claimKeyID, refundKeyID string
	if opts.ClaimKey == nil {
		opts.ClaimKey = keyRef.PubKey
		claimKeyID = keyRef.Id
	} else if sameKey(opts.ClaimKey, keyRef.PubKey) {
		opts.ClaimKey = keyRef.PubKey
		claimKeyID = keyRef.Id
	}
	if opts.RefundKey == nil {
		opts.RefundKey = keyRef.PubKey
		refundKeyID = keyRef.Id
	} else if sameKey(opts.RefundKey, keyRef.PubKey) {
		opts.RefundKey = keyRef.PubKey
		refundKeyID = keyRef.Id
	}

	switch {
	case claimKeyID != "" && refundKeyID != "":
		return htlc.Opts{}, "", "", fmt.Errorf("wallet key matches both HTLC roles")
	case claimKeyID == "" && refundKeyID == "":
		return htlc.Opts{}, "", "", fmt.Errorf("wallet key is not present in HTLC opts")
	}

	return opts, claimKeyID, refundKeyID, nil
}

func OptsFromContract(c types.Contract) (htlc.Opts, error) {
	serverKey, err := parseCompressedParam(c, paramServerKey)
	if err != nil {
		return htlc.Opts{}, err
	}
	claimKey, err := parseCompressedParam(c, paramClaimKey)
	if err != nil {
		return htlc.Opts{}, err
	}
	refundKey, err := parseCompressedParam(c, paramRefundKey)
	if err != nil {
		return htlc.Opts{}, err
	}
	preimageHashHex, err := requireParam(c, paramPreimageHash)
	if err != nil {
		return htlc.Opts{}, err
	}
	preimageHash, err := hex.DecodeString(preimageHashHex)
	if err != nil {
		return htlc.Opts{}, fmt.Errorf("htlc contract %s: invalid preimage hash: %w", c.Script, err)
	}
	refundLocktimeStr, err := requireParam(c, paramRefundLocktime)
	if err != nil {
		return htlc.Opts{}, err
	}
	refundLocktime, err := strconv.ParseUint(refundLocktimeStr, 10, 32)
	if err != nil {
		return htlc.Opts{}, fmt.Errorf(
			"htlc contract %s: invalid refund locktime: %w",
			c.Script,
			err,
		)
	}

	return htlc.Opts{
		ServerKey:      serverKey,
		ClaimKey:       claimKey,
		RefundKey:      refundKey,
		PreimageHash:   preimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(refundLocktime),
	}, nil
}

func requireParam(c types.Contract, name string) (string, error) {
	if len(c.Params) == 0 {
		return "", fmt.Errorf("htlc contract %s has no params", c.Script)
	}
	value, ok := c.Params[name]
	if !ok {
		return "", fmt.Errorf("htlc contract %s is missing %s", c.Script, name)
	}
	if value == "" {
		return "", fmt.Errorf("htlc contract %s has empty %s", c.Script, name)
	}
	return value, nil
}

func parseCompressedParam(c types.Contract, name string) (*btcec.PublicKey, error) {
	pubHex, err := requireParam(c, name)
	if err != nil {
		return nil, err
	}
	pub, err := parseStoredPubKey(pubHex)
	if err != nil {
		return nil, fmt.Errorf("htlc contract %s: invalid %s: %w", c.Script, name, err)
	}
	return pub, nil
}

func parseStoredPubKey(pubHex string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key hex: %w", err)
	}
	const compressedPubKeyLen = 33
	if len(buf) != compressedPubKeyLen {
		return nil, fmt.Errorf(
			"expected compressed key length %d, got %d", compressedPubKeyLen, len(buf),
		)
	}
	if buf[0] != 0x02 && buf[0] != 0x03 {
		return nil, fmt.Errorf("expected compressed key prefix 0x02 or 0x03, got 0x%02x", buf[0])
	}
	return btcec.ParsePubKey(buf)
}

func sameKey(a, b *btcec.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
}
