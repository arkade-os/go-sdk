package htlc

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// Opts contains all parameters needed to construct a Bitcoin HTLC tapscript tree.
// ClaimKey and RefundKey are the script-path keys.
type Opts struct {
	ClaimKey       *btcec.PublicKey
	RefundKey      *btcec.PublicKey
	PreimageHash   []byte
	RefundLocktime arklib.AbsoluteLocktime
}

func (o Opts) validate() error {
	if o.ClaimKey == nil {
		return fmt.Errorf("missing claim key")
	}
	if o.RefundKey == nil {
		return fmt.Errorf("missing refund key")
	}
	if len(o.PreimageHash) != hash160Len {
		return fmt.Errorf(
			"preimage hash must be %d bytes, got %d", hash160Len, len(o.PreimageHash),
		)
	}
	if o.RefundLocktime == 0 {
		return fmt.Errorf("refund locktime must be greater than 0")
	}
	return nil
}

// claimLeafScript = (Preimage + ClaimKey)
func (o Opts) claimLeafScript() ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddData([]byte{0x20}).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(o.PreimageHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(o.ClaimKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
}

// refundLeafScript = (RefundKey) at RefundLocktime
func (o Opts) refundLeafScript() ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(o.RefundKey)).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(int64(o.RefundLocktime)).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
}
