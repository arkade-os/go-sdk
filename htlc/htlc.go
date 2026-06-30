package htlc

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/txscript"
)

const (
	Hash160Len = 20
)

// Opts are the raw parameters needed to build a Bitcoin HTLC tapscript tree.
//
// ServerKey is the Boltz/server key used with the wallet key for the taproot
// internal key. ClaimKey and RefundKey are the script-path keys. A nil
// ClaimKey or RefundKey means that side is owned by the wallet key supplied
// by the contract manager.
type Opts struct {
	ServerKey      *btcec.PublicKey
	ClaimKey       *btcec.PublicKey
	RefundKey      *btcec.PublicKey
	PreimageHash   []byte
	RefundLocktime arklib.AbsoluteLocktime
}

// HTLCScript represents the Bitcoin HTLC tapscript tree and cooperative key.
type HTLCScript struct {
	Opts

	InternalKey  *btcec.PublicKey
	TaprootKey   *btcec.PublicKey
	ClaimScript  []byte
	RefundScript []byte
}

// NewHTLCScriptFromOpts creates a Bitcoin HTLC tapscript tree from raw opts.
func NewHTLCScriptFromOpts(opts Opts, walletKey *btcec.PublicKey) (*HTLCScript, error) {
	if walletKey == nil {
		return nil, fmt.Errorf("missing wallet key")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	walletClaims := false
	if opts.ClaimKey == nil {
		opts.ClaimKey = walletKey
		walletClaims = true
	} else if sameScriptKey(walletKey, opts.ClaimKey) {
		opts.ClaimKey = walletKey
		walletClaims = true
	}

	walletRefunds := false
	if opts.RefundKey == nil {
		opts.RefundKey = walletKey
		walletRefunds = true
	} else if sameScriptKey(walletKey, opts.RefundKey) {
		opts.RefundKey = walletKey
		walletRefunds = true
	}

	switch {
	case walletClaims && walletRefunds:
		return nil, fmt.Errorf("wallet key matches both HTLC roles")
	case !walletClaims && !walletRefunds:
		return nil, fmt.Errorf("wallet key is not present in HTLC opts")
	}

	claimScript, refundScript, err := NewHTLCLeafScriptsFromOpts(opts)
	if err != nil {
		return nil, err
	}

	aggregateKey, _, _, err := musig2.AggregateKeys(
		[]*btcec.PublicKey{opts.ServerKey, walletKey},
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("aggregate HTLC keys: %w", err)
	}

	tree := txscript.AssembleTaprootScriptTree(
		txscript.NewBaseTapLeaf(claimScript),
		txscript.NewBaseTapLeaf(refundScript),
	)
	merkleRoot := tree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(aggregateKey.FinalKey, merkleRoot[:])

	return &HTLCScript{
		Opts:         opts,
		InternalKey:  aggregateKey.FinalKey,
		TaprootKey:   taprootKey,
		ClaimScript:  claimScript,
		RefundScript: refundScript,
	}, nil
}

func (o Opts) validate() error {
	if o.ServerKey == nil {
		return fmt.Errorf("missing server key")
	}
	if o.ClaimKey == nil && o.RefundKey == nil {
		return fmt.Errorf("missing claim or refund key")
	}
	if len(o.PreimageHash) != Hash160Len {
		return fmt.Errorf(
			"preimage hash must be %d bytes, got %d", Hash160Len, len(o.PreimageHash),
		)
	}
	if o.RefundLocktime == 0 {
		return fmt.Errorf("refund locktime must be greater than 0")
	}
	return nil
}

// NewHTLCLeafScriptsFromOpts builds the claim and refund leaves from complete
// HTLC opts without applying wallet ownership semantics.
func NewHTLCLeafScriptsFromOpts(opts Opts) ([]byte, []byte, error) {
	if err := opts.validate(); err != nil {
		return nil, nil, err
	}
	if opts.ClaimKey == nil {
		return nil, nil, fmt.Errorf("missing claim key")
	}
	if opts.RefundKey == nil {
		return nil, nil, fmt.Errorf("missing refund key")
	}

	claimScript, err := claimLeafScript(opts.PreimageHash, opts.ClaimKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create claim leaf script: %w", err)
	}
	refundScript, err := refundLeafScript(opts.RefundKey, opts.RefundLocktime)
	if err != nil {
		return nil, nil, fmt.Errorf("create refund leaf script: %w", err)
	}

	return claimScript, refundScript, nil
}

func claimLeafScript(preimageHash []byte, claimKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddData([]byte{0x20}).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(claimKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
}

func refundLeafScript(
	refundKey *btcec.PublicKey,
	refundLocktime arklib.AbsoluteLocktime,
) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(refundKey)).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(int64(refundLocktime)).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
}

func sameScriptKey(a, b *btcec.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
}
