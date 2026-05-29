package vhtlc

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

const p2trPkScriptLen = 34

// NonInteractiveClaimOpts enables the non-interactive claim covenant closure
// on a VHTLC. When set, NewVHTLCScriptFromOpts appends a ConditionMultisigClosure
// that lets a solver bot claim the VHTLC on the receiver's behalf by revealing
// the preimage. The solver does not need any signature from the receiver — it
// satisfies the introspector-tweaked multisig via the EnforcePayTo arkade script.
type NonInteractiveClaimOpts struct {
	// ReceiverPkScript is the 34-byte P2TR pkScript of the VHTLC receiver.
	ReceiverPkScript []byte
	// IntrospectorPubKey is the solver's introspector signing key (compressed).
	// It will be tweaked with the non-interactive claim arkade script hash.
	IntrospectorPubKey *btcec.PublicKey
}

func (o NonInteractiveClaimOpts) validate() error {
	if len(o.ReceiverPkScript) != p2trPkScriptLen {
		return fmt.Errorf(
			"non-interactive claim: receiver pkScript must be %d bytes", p2trPkScriptLen,
		)
	}
	if o.ReceiverPkScript[0] != txscript.OP_1 || o.ReceiverPkScript[1] != txscript.OP_DATA_32 {
		return fmt.Errorf("non-interactive claim: receiver pkScript is not P2TR")
	}
	if o.IntrospectorPubKey == nil {
		return fmt.Errorf("non-interactive claim: introspector pubkey must not be nil")
	}
	return nil
}

// Arkade opcode constants used in the enforcement script.
// These are custom opcodes defined in the introspector VM (forked from btcd),
// NOT standard Bitcoin opcodes. They only execute inside the introspector process.
const (
	opPushCurrentInputIndex      = 0xcd
	opInspectOutputScriptPubKey  = 0xd1
	opInspectOutputValue         = 0xcf
	opInspectInputValue          = 0xc9
	opGreaterThanOrEqual         = 0xa2
)

// EnforcePayTo builds the arkade enforcement script pinning output[i] to
// receiverPkScript with output[i].value >= input[i].value.
func EnforcePayTo(receiverPkScript []byte) ([]byte, error) {
	if len(receiverPkScript) != p2trPkScriptLen {
		return nil, fmt.Errorf(
			"expected %d-byte P2TR pkScript, got %d", p2trPkScriptLen, len(receiverPkScript),
		)
	}
	witnessProgram := receiverPkScript[2:]
	b := txscript.NewScriptBuilder()
	b.AddOp(opPushCurrentInputIndex)
	b.AddOp(txscript.OP_DUP)
	b.AddOp(opInspectOutputScriptPubKey)
	b.AddOp(txscript.OP_1)
	b.AddOp(txscript.OP_EQUALVERIFY)
	b.AddData(witnessProgram)
	b.AddOp(txscript.OP_EQUALVERIFY)
	b.AddOp(opInspectOutputValue)
	b.AddOp(opPushCurrentInputIndex)
	b.AddOp(opInspectInputValue)
	b.AddOp(opGreaterThanOrEqual)
	return b.Script()
}

// ArkadeScriptHash computes the tagged hash of an arkade script.
// This is the canonical hash used for key tweaking.
var tagArkScriptHash = []byte("ArkScriptHash")

func ArkadeScriptHash(arkadeScript []byte) []byte {
	hash := chainhash.TaggedHash(tagArkScriptHash, arkadeScript)
	return hash[:]
}

// IntrospectorTweakedKey returns the introspector pubkey tweaked by the
// arkade script hash: tweakedPub = introPub + H(arkadeScript) * G.
func IntrospectorTweakedKey(
	arkadeScript []byte, introspectorPubKey *btcec.PublicKey,
) *btcec.PublicKey {
	scriptHash := ArkadeScriptHash(arkadeScript)
	tweakKey, _ := btcec.PrivKeyFromBytes(scriptHash)

	var (
		pubKeyJacobian btcec.JacobianPoint
		tweakJacobian  btcec.JacobianPoint
		resultJacobian btcec.JacobianPoint
	)

	// Normalize to even Y before adding.
	evenPub, _ := btcec.ParsePubKey(introspectorPubKey.SerializeCompressed())
	evenPub.AsJacobian(&pubKeyJacobian)
	btcec.ScalarBaseMultNonConst(&tweakKey.Key, &tweakJacobian)
	btcec.AddNonConst(&pubKeyJacobian, &tweakJacobian, &resultJacobian)
	resultJacobian.ToAffine()

	return btcec.NewPublicKey(&resultJacobian.X, &resultJacobian.Y)
}

// nonInteractiveClaimClosure builds the ConditionMultisigClosure used by the
// solver to claim the VHTLC unilaterally with the preimage.
func nonInteractiveClaimClosure(
	preimageCondition []byte,
	opts NonInteractiveClaimOpts,
	serverPubKey *btcec.PublicKey,
) (*script.ConditionMultisigClosure, error) {
	enforcement, err := EnforcePayTo(opts.ReceiverPkScript)
	if err != nil {
		return nil, err
	}
	tweaked := IntrospectorTweakedKey(enforcement, opts.IntrospectorPubKey)
	return &script.ConditionMultisigClosure{
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{serverPubKey, tweaked},
		},
		Condition: preimageCondition,
	}, nil
}
