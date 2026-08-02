package htlc

import (
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

var testPreimageHash = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13,
}

func TestNewHTLCScriptFromOpts(t *testing.T) {
	claimKey, refundKey := newTestKey(t), newTestKey(t)

	htlcScript, err := NewHTLCScriptFromOpts(Opts{
		ClaimKey:       claimKey,
		RefundKey:      refundKey,
		PreimageHash:   testPreimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(760),
	})
	require.NoError(t, err)

	leaves := htlcScript.GetRevealedTapscripts()
	require.Len(t, leaves, 2)

	// Reconstructing from the revealed leaves must roundtrip to the same script.
	parsed, err := NewHtlcScript(leaves[0], leaves[1])
	require.NoError(t, err)
	require.Equal(
		t, schnorr.SerializePubKey(claimKey), schnorr.SerializePubKey(parsed.ClaimKey),
	)
	require.Equal(
		t, schnorr.SerializePubKey(refundKey), schnorr.SerializePubKey(parsed.RefundKey),
	)
	require.Equal(t, testPreimageHash, parsed.PreimageHash)
	require.EqualValues(t, 760, parsed.RefundLocktime)
	require.Equal(t, htlcScript.MerkleRoot(), parsed.MerkleRoot())
}

func TestNewHtlcScript(t *testing.T) {
	claimKey, refundKey := newTestKey(t), newTestKey(t)

	claimLeaf, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddData([]byte{0x20}).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(testPreimageHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(claimKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	fixtures := []struct {
		name     string
		locktime int64
	}{
		{name: "locktime", locktime: 760},
		{name: "small int locktime", locktime: 16},
	}

	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			refundLeaf, err := txscript.NewScriptBuilder().
				AddData(schnorr.SerializePubKey(refundKey)).
				AddOp(txscript.OP_CHECKSIGVERIFY).
				AddInt64(f.locktime).
				AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
				Script()
			require.NoError(t, err)

			htlcScript, err := NewHtlcScript(
				hex.EncodeToString(claimLeaf), hex.EncodeToString(refundLeaf),
			)
			require.NoError(t, err)
			require.Equal(
				t, schnorr.SerializePubKey(claimKey),
				schnorr.SerializePubKey(htlcScript.ClaimKey),
			)
			require.Equal(
				t, schnorr.SerializePubKey(refundKey),
				schnorr.SerializePubKey(htlcScript.RefundKey),
			)
			require.Equal(t, testPreimageHash, htlcScript.PreimageHash)
			require.EqualValues(t, f.locktime, htlcScript.RefundLocktime)
		})
	}
}

func newTestKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv.PubKey()
}
