package vhtlc

import (
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck
)

const (
	hash160Len              = 20
	sha256Len               = 32
	minSecondsTimelock      = 512
	secondsTimelockMultiple = 512
)

type VHTLCScript struct {
	script.TapscriptsVtxoScript

	Sender                                 *btcec.PublicKey
	Receiver                               *btcec.PublicKey
	Server                                 *btcec.PublicKey
	ClaimClosure                           *script.ConditionMultisigClosure
	RefundClosure                          *script.MultisigClosure
	RefundWithoutReceiverClosure           *script.CLTVMultisigClosure
	UnilateralClaimClosure                 *script.ConditionCSVMultisigClosure
	UnilateralRefundClosure                *script.CSVMultisigClosure
	UnilateralRefundWithoutReceiverClosure *script.CSVMultisigClosure

	preimageConditionScript []byte
}

// NewVHTLCScriptFromOpts creates a VHTLC VtxoScript from typed parameters.
func NewVHTLCScriptFromOpts(opts Opts) (*VHTLCScript, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	preimageCondition, err := makePreimageConditionScript(opts.PreimageHash)
	if err != nil {
		return nil, err
	}

	claimClosure := opts.claimClosure(preimageCondition)
	refundClosure := opts.refundClosure()
	refundWithoutReceiverClosure := opts.refundWithoutReceiverClosure()
	unilateralClaimClosure := opts.unilateralClaimClosure(preimageCondition)
	unilateralRefundClosure := opts.unilateralRefundClosure()
	unilateralRefundWithoutReceiverClosure := opts.unilateralRefundWithoutReceiverClosure()

	return &VHTLCScript{
		TapscriptsVtxoScript: script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				claimClosure,
				refundClosure,
				refundWithoutReceiverClosure,
				unilateralClaimClosure,
				unilateralRefundClosure,
				unilateralRefundWithoutReceiverClosure,
			},
		},
		Sender:                                 opts.Sender,
		Receiver:                               opts.Receiver,
		Server:                                 opts.Server,
		ClaimClosure:                           claimClosure,
		RefundClosure:                          refundClosure,
		RefundWithoutReceiverClosure:           refundWithoutReceiverClosure,
		UnilateralClaimClosure:                 unilateralClaimClosure,
		UnilateralRefundClosure:                unilateralRefundClosure,
		UnilateralRefundWithoutReceiverClosure: unilateralRefundWithoutReceiverClosure,
		preimageConditionScript:                preimageCondition,
	}, nil
}

// NewVhtlcScript reconstructs a VHTLCScript from a preimage hash and the six
// hex-encoded tapscript leaf scripts (in leaf order).
func NewVhtlcScript(
	preimageHash,
	claimLeaf, refundLeaf, refundWithoutReceiverLeaf,
	unilateralClaimLeaf, unilateralRefundLeaf, unilateralRefundWithoutReceiverLeaf string,
) (*VHTLCScript, error) {
	decodedPreimageHash, err := hex.DecodeString(preimageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode preimage hash: %w", err)
	}
	// If the caller provided a SHA-256 hash, convert it to HASH160.
	if len(decodedPreimageHash) == sha256Len {
		hasher := ripemd160.New()
		hasher.Write(decodedPreimageHash)
		decodedPreimageHash = hasher.Sum(nil)
	}
	if len(decodedPreimageHash) != hash160Len {
		return nil, fmt.Errorf(
			"invalid preimage hash length: expected %d, got %d",
			hash160Len,
			len(decodedPreimageHash),
		)
	}
	preimageCondition, err := makePreimageConditionScript(decodedPreimageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to build condition script: %w", err)
	}

	claimClosure, err := parseClaimClosure(claimLeaf)
	if err != nil {
		return nil, err
	}
	refundClosure, err := parseRefundClosure(refundLeaf)
	if err != nil {
		return nil, err
	}
	refundWithoutReceiverClosure, err := parseRefundWithoutReceiverClosure(
		refundWithoutReceiverLeaf,
	)
	if err != nil {
		return nil, err
	}
	unilateralClaimClosure, err := parseUnilateralClaimClosure(unilateralClaimLeaf)
	if err != nil {
		return nil, err
	}
	unilateralRefundClosure, err := parseUnilateralRefundClosure(unilateralRefundLeaf)
	if err != nil {
		return nil, err
	}
	unilateralRefundWithoutReceiverClosure, err := parseUnilateralRefundWithoutReceiverClosure(
		unilateralRefundWithoutReceiverLeaf,
	)
	if err != nil {
		return nil, err
	}

	receiver := unilateralClaimClosure.PubKeys[0]
	sender := unilateralRefundWithoutReceiverClosure.PubKeys[0]
	var server *btcec.PublicKey
	for _, pk := range claimClosure.PubKeys {
		if !pk.IsEqual(receiver) {
			server = pk
			break
		}
	}

	return &VHTLCScript{
		TapscriptsVtxoScript: script.TapscriptsVtxoScript{
			Closures: []script.Closure{
				claimClosure,
				refundClosure,
				refundWithoutReceiverClosure,
				unilateralClaimClosure,
				unilateralRefundClosure,
				unilateralRefundWithoutReceiverClosure,
			},
		},
		Sender:                                 sender,
		Receiver:                               receiver,
		Server:                                 server,
		ClaimClosure:                           claimClosure,
		RefundClosure:                          refundClosure,
		RefundWithoutReceiverClosure:           refundWithoutReceiverClosure,
		UnilateralClaimClosure:                 unilateralClaimClosure,
		UnilateralRefundClosure:                unilateralRefundClosure,
		UnilateralRefundWithoutReceiverClosure: unilateralRefundWithoutReceiverClosure,
		preimageConditionScript:                preimageCondition,
	}, nil
}

// GetRevealedTapscripts returns all six leaf scripts as hex-encoded strings.
func (v *VHTLCScript) GetRevealedTapscripts() ([]string, error) {
	var scripts []string
	for _, closure := range []script.Closure{
		v.ClaimClosure,
		v.RefundClosure,
		v.RefundWithoutReceiverClosure,
		v.UnilateralClaimClosure,
		v.UnilateralRefundClosure,
		v.UnilateralRefundWithoutReceiverClosure,
	} {
		s, err := closure.Script()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize closure script: %w", err)
		}
		scripts = append(scripts, hex.EncodeToString(s))
	}
	return scripts, nil
}

// Address returns the Ark bech32m address for this VHTLC.
func (v *VHTLCScript) Address(hrp string) (string, error) {
	tapKey, _, err := v.TapTree()
	if err != nil {
		return "", err
	}
	addr := &arklib.Address{
		HRP:        hrp,
		Signer:     v.Server,
		VtxoTapKey: tapKey,
	}
	return addr.EncodeV0()
}

// ClaimTapscript returns the tapscript proof needed to spend the claim leaf.
func (v *VHTLCScript) ClaimTapscript() (*waddrmgr.Tapscript, error) {
	claimScript, err := v.ClaimClosure.Script()
	if err != nil {
		return nil, err
	}
	_, tapTree, err := v.TapTree()
	if err != nil {
		return nil, err
	}
	leafProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(claimScript).TapHash(),
	)
	if err != nil {
		return nil, err
	}
	ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
	if err != nil {
		return nil, err
	}
	return &waddrmgr.Tapscript{
		RevealedScript: leafProof.Script,
		ControlBlock:   ctrlBlock,
	}, nil
}

// RefundTapscript returns the tapscript proof needed to spend the refund leaf.
// withReceiver=true selects the 3-of-3 refund; withReceiver=false selects
// the sender+server CLTV refund.
func (v *VHTLCScript) RefundTapscript(withReceiver bool) (*waddrmgr.Tapscript, error) {
	var closure script.Closure
	if withReceiver {
		closure = v.RefundClosure
	} else {
		closure = v.RefundWithoutReceiverClosure
	}
	refundScript, err := closure.Script()
	if err != nil {
		return nil, err
	}
	_, tapTree, err := v.TapTree()
	if err != nil {
		return nil, err
	}
	leafProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(refundScript).TapHash(),
	)
	if err != nil {
		return nil, err
	}
	ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
	if err != nil {
		return nil, err
	}
	return &waddrmgr.Tapscript{
		RevealedScript: leafProof.Script,
		ControlBlock:   ctrlBlock,
	}, nil
}

// Opts returns the parameters that define this VHTLC.
func (v *VHTLCScript) Opts() Opts {
	return Opts{
		Sender:                               v.Sender,
		Receiver:                             v.Receiver,
		Server:                               v.Server,
		PreimageHash:                         v.preimageConditionScript[2 : 2+hash160Len],
		RefundLocktime:                       v.RefundWithoutReceiverClosure.Locktime,
		UnilateralClaimDelay:                 v.UnilateralClaimClosure.Locktime,
		UnilateralRefundDelay:                v.UnilateralRefundClosure.Locktime,
		UnilateralRefundWithoutReceiverDelay: v.UnilateralRefundWithoutReceiverClosure.Locktime,
	}
}
