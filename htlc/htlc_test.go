package htlc

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func TestParseClaimLeafScript(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	xOnlyPub := schnorr.SerializePubKey(priv.PubKey())
	preimageHash := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10, 0x11, 0x12, 0x13,
	}

	leafScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddData([]byte{0x20}).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(xOnlyPub).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	components, err := ParseClaimLeafScript(leafScript)
	require.NoError(t, err)
	require.Equal(t, preimageHash, components.PreimageHash[:])
	require.True(t, bytes.Equal(xOnlyPub, components.ClaimPubKey[:]))
}

func TestParseRefundLeafScript(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	xOnlyPub := schnorr.SerializePubKey(priv.PubKey())

	leafScript, err := txscript.NewScriptBuilder().
		AddData(xOnlyPub).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(760).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
	require.NoError(t, err)

	components, err := ParseRefundLeafScript(leafScript)
	require.NoError(t, err)
	require.True(t, bytes.Equal(xOnlyPub, components.RefundPubKey[:]))
	require.EqualValues(t, 760, components.Timeout)
}

func TestParseRefundLeafScriptSmallIntLocktime(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	xOnlyPub := schnorr.SerializePubKey(priv.PubKey())

	leafScript, err := txscript.NewScriptBuilder().
		AddData(xOnlyPub).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(16).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
	require.NoError(t, err)

	components, err := ParseRefundLeafScript(leafScript)
	require.NoError(t, err)
	require.EqualValues(t, 16, components.Timeout)
}
