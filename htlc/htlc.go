package htlc

import (
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

const (
	hash160Len = 20
)

// HTLCScript represents a Bitcoin Hash Time-Locked Contract as a tapscript tree.
// It contains 2 spending paths: claim with preimage reveal, and refund after the
// locktime expires.
type HTLCScript struct {
	ClaimKey       *btcec.PublicKey
	RefundKey      *btcec.PublicKey
	PreimageHash   []byte
	RefundLocktime arklib.AbsoluteLocktime

	claimLeafScript  []byte
	refundLeafScript []byte
}

// NewHTLCScriptFromOpts creates a Bitcoin HTLC script from the given options.
func NewHTLCScriptFromOpts(opts Opts) (*HTLCScript, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	claimScript, err := opts.claimLeafScript()
	if err != nil {
		return nil, fmt.Errorf("create claim leaf script: %w", err)
	}
	refundScript, err := opts.refundLeafScript()
	if err != nil {
		return nil, fmt.Errorf("create refund leaf script: %w", err)
	}

	return &HTLCScript{
		ClaimKey:         opts.ClaimKey,
		RefundKey:        opts.RefundKey,
		PreimageHash:     opts.PreimageHash,
		RefundLocktime:   opts.RefundLocktime,
		claimLeafScript:  claimScript,
		refundLeafScript: refundScript,
	}, nil
}

// NewHtlcScript reconstructs an HTLCScript from raw tapscript leaves.
// This is used to recover the HTLC parameters from a Boltz swap tree.
func NewHtlcScript(claimLeaf, refundLeaf string) (*HTLCScript, error) {
	claimScript, err := hex.DecodeString(claimLeaf)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claim leaf hex: %w", err)
	}
	refundScript, err := hex.DecodeString(refundLeaf)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refund leaf hex: %w", err)
	}

	claimKey, preimageHash, err := parseClaimLeafScript(claimScript)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claim leaf: %w", err)
	}
	refundKey, refundLocktime, err := parseRefundLeafScript(refundScript)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refund leaf: %w", err)
	}

	return &HTLCScript{
		ClaimKey:         claimKey,
		RefundKey:        refundKey,
		PreimageHash:     preimageHash,
		RefundLocktime:   arklib.AbsoluteLocktime(refundLocktime),
		claimLeafScript:  claimScript,
		refundLeafScript: refundScript,
	}, nil
}

// GetRevealedTapscripts returns all available scripts as hex-encoded strings.
func (h *HTLCScript) GetRevealedTapscripts() []string {
	return []string{
		hex.EncodeToString(h.claimLeafScript),
		hex.EncodeToString(h.refundLeafScript),
	}
}

// TapTree returns the taproot script tree composed of the claim and refund leaves.
func (h *HTLCScript) TapTree() *txscript.IndexedTapScriptTree {
	return txscript.AssembleTaprootScriptTree(
		txscript.NewBaseTapLeaf(h.claimLeafScript),
		txscript.NewBaseTapLeaf(h.refundLeafScript),
	)
}

// MerkleRoot returns the merkle root of the HTLC taptree, used as taproot tweak
// and as message for MuSig2 cooperative signing.
func (h *HTLCScript) MerkleRoot() []byte {
	root := h.TapTree().RootNode.TapHash()
	return root[:]
}

// Address encodes the HTLC as a taproot address. senderFirst tells whether the sender
// (refund) key comes first in the MuSig2 aggregation of the internal key.
func (h *HTLCScript) Address(net *chaincfg.Params, senderFirst bool) (string, error) {
	tapKey, err := h.taprootOutputKey(senderFirst)
	if err != nil {
		return "", err
	}

	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), net)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// PkScript returns the taproot output script locking the HTLC. senderFirst tells whether
// the sender (refund) key comes first in the MuSig2 aggregation of the internal key.
func (h *HTLCScript) PkScript(senderFirst bool) ([]byte, error) {
	tapKey, err := h.taprootOutputKey(senderFirst)
	if err != nil {
		return nil, err
	}
	return txscript.PayToTaprootScript(tapKey)
}

// ClaimTapscript computes the necessary script and control block to spend the claim leaf.
// senderFirst tells whether the sender (refund) key comes first in the MuSig2 aggregation
// of the internal key.
func (h *HTLCScript) ClaimTapscript(senderFirst bool) (*waddrmgr.Tapscript, error) {
	return h.tapscript(h.claimLeafScript, senderFirst)
}

// RefundTapscript computes the necessary script and control block to spend the refund leaf.
// senderFirst tells whether the sender (refund) key comes first in the MuSig2 aggregation
// of the internal key.
func (h *HTLCScript) RefundTapscript(senderFirst bool) (*waddrmgr.Tapscript, error) {
	return h.tapscript(h.refundLeafScript, senderFirst)
}

// Opts returns the options that were used to build this script.
func (h *HTLCScript) Opts() Opts {
	return Opts{
		ClaimKey:       h.ClaimKey,
		RefundKey:      h.RefundKey,
		PreimageHash:   h.PreimageHash,
		RefundLocktime: h.RefundLocktime,
	}
}

// internalKey returns the taproot internal key of the HTLC, ie. the MuSig2 aggregate of the
// sender (refund) and receiver (claim) keys enabling the cooperative key-spend path.
// The aggregation is not commutative, senderFirst must reflect the order used by the
// counterparty when building the HTLC.
func (h *HTLCScript) internalKey(senderFirst bool) (*btcec.PublicKey, error) {
	keys := []*btcec.PublicKey{h.ClaimKey, h.RefundKey}
	if senderFirst {
		keys = []*btcec.PublicKey{h.RefundKey, h.ClaimKey}
	}
	aggKey, _, _, err := musig2.AggregateKeys(keys, false)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate keys: %w", err)
	}
	return aggKey.FinalKey, nil
}

func (h *HTLCScript) taprootOutputKey(senderFirst bool) (*btcec.PublicKey, error) {
	internalKey, err := h.internalKey(senderFirst)
	if err != nil {
		return nil, err
	}
	return txscript.ComputeTaprootOutputKey(internalKey, h.MerkleRoot()), nil
}

func (h *HTLCScript) tapscript(leafScript []byte, senderFirst bool) (*waddrmgr.Tapscript, error) {
	internalKey, err := h.internalKey(senderFirst)
	if err != nil {
		return nil, err
	}

	tapTree := h.TapTree()

	idx, ok := tapTree.LeafProofIndex[txscript.NewBaseTapLeaf(leafScript).TapHash()]
	if !ok {
		return nil, fmt.Errorf("leaf not found in taptree")
	}
	ctrlBlock := tapTree.LeafMerkleProofs[idx].ToControlBlock(internalKey)

	return &waddrmgr.Tapscript{
		RevealedScript: leafScript,
		ControlBlock:   &ctrlBlock,
	}, nil
}
