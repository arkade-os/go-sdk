package handlers

import "github.com/btcsuite/btcd/txscript"

// preimageConditionScript returns the raw script bytes for a HASH160 preimage check:
//
//	OP_HASH160 <hash20> OP_EQUAL
//
// These bytes are passed as the Condition field of ConditionMultisigClosure and
// ConditionCSVMultisigClosure. The closures prepend OP_VERIFY themselves, so it
// must NOT be included here.
func preimageConditionScript(hash20 []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(hash20).
		AddOp(txscript.OP_EQUAL).
		Script()
}
