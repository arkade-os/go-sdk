package htlcHandler

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

var testNetwork = arklib.BitcoinRegTest

func TestHTLCHandlerNewContract(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)
	opts := newTestOpts(t, keyRef.PubKey)

	got, err := h.NewContract(t.Context(), keyRef, opts)
	require.NoError(t, err)
	require.Equal(t, types.ContractTypeHTLC, got.Type)
	require.Equal(t, types.ContractStateActive, got.State)
	require.NotEmpty(t, got.Script)
	require.NotEmpty(t, got.Address)
	require.False(t, got.CreatedAt.IsZero())

	expectedScript := expectedHTLCOutputScript(t, opts.Server, keyRef.PubKey, opts)
	require.Equal(t, hex.EncodeToString(expectedScript), got.Script)

	addr, err := btcutil.DecodeAddress(got.Address, &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	addrScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	require.Equal(t, got.Script, hex.EncodeToString(addrScript))
	require.Equal(t, keyRef.Id, got.Params[paramOwnerKeyID])
	require.Equal(
		t,
		hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		got.Params[paramOwnerKey],
	)
	require.Equal(
		t,
		hex.EncodeToString(opts.Server.SerializeCompressed()),
		got.Params[paramServerKey],
	)
}

func TestHTLCHandlerGetters(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)
	opts := newTestOpts(t, keyRef.PubKey)
	c, err := h.NewContract(t.Context(), keyRef, opts)
	require.NoError(t, err)

	ref, err := h.GetKeyRef(*c)
	require.NoError(t, err)
	require.Equal(t, keyRef.Id, ref.Id)
	require.Equal(t, keyRef.PubKey.SerializeCompressed(), ref.PubKey.SerializeCompressed())

	keyRefs, err := h.GetKeyRefs(*c)
	require.NoError(t, err)
	require.Equal(t, map[string]string{c.Script: keyRef.Id}, keyRefs)

	signerKey, err := h.GetSignerKey(*c)
	require.NoError(t, err)
	require.Equal(t, opts.Server.SerializeCompressed(), signerKey.SerializeCompressed())

	delay, err := h.GetExitDelay(*c)
	require.NoError(t, err)
	require.Nil(t, delay)

	tapscripts, err := h.GetTapscripts(*c)
	require.NoError(t, err)
	require.Equal(t, []string{opts.ClaimLeaf.Output, opts.RefundLeaf.Output}, tapscripts)
}

func TestHTLCHandlerPreservesOwnerKeyParity(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := identity.KeyRef{Id: "m/0/1", PubKey: newTestOddPubKey(t)}
	opts := newTestOpts(t, keyRef.PubKey)

	c, err := h.NewContract(t.Context(), keyRef, opts)
	require.NoError(t, err)

	ref, err := h.GetKeyRef(*c)
	require.NoError(t, err)
	require.Equal(t, keyRef.PubKey.SerializeCompressed(), ref.PubKey.SerializeCompressed())

	expectedScript := expectedHTLCOutputScript(t, opts.Server, keyRef.PubKey, opts)
	restoredScript := expectedHTLCOutputScript(t, opts.Server, ref.PubKey, opts)
	require.Equal(t, expectedScript, restoredScript)
	require.Equal(t, hex.EncodeToString(expectedScript), c.Script)
}

func TestHTLCHandlerRejectsXOnlyStoredKeys(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)
	opts := newTestOpts(t, keyRef.PubKey)
	c, err := h.NewContract(t.Context(), keyRef, opts)
	require.NoError(t, err)

	c.Params[paramOwnerKey] = hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey))
	ref, err := h.GetKeyRef(*c)
	require.Error(t, err)
	require.ErrorContains(t, err, "expected compressed key length")
	require.Nil(t, ref)

	c.Params[paramOwnerKey] = hex.EncodeToString(keyRef.PubKey.SerializeCompressed())
	c.Params[paramServerKey] = hex.EncodeToString(schnorr.SerializePubKey(opts.Server))
	signer, err := h.GetSignerKey(*c)
	require.Error(t, err)
	require.ErrorContains(t, err, "expected compressed key length")
	require.Nil(t, signer)
}

func TestHTLCHandlerNewContractInvalid(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)

	t.Run("nil params", func(t *testing.T) {
		got, err := h.NewContract(t.Context(), keyRef, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "requires *htlcHandler.Opts")
		require.Nil(t, got)
	})

	t.Run("missing server", func(t *testing.T) {
		opts := newTestOpts(t, keyRef.PubKey)
		opts.Server = nil

		got, err := h.NewContract(t.Context(), keyRef, opts)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing server key")
		require.Nil(t, got)
	})

	t.Run("owner key absent from scripts", func(t *testing.T) {
		opts := newTestOpts(t, newTestPubKey(t))

		got, err := h.NewContract(t.Context(), keyRef, opts)
		require.Error(t, err)
		require.ErrorContains(t, err, "owner key is not present")
		require.Nil(t, got)
	})
}

func expectedHTLCOutputScript(
	t *testing.T, serverKey, ownerKey *btcec.PublicKey, opts *Opts,
) []byte {
	t.Helper()
	claimScript, err := hex.DecodeString(opts.ClaimLeaf.Output)
	require.NoError(t, err)
	refundScript, err := hex.DecodeString(opts.RefundLeaf.Output)
	require.NoError(t, err)

	aggregateKey, _, _, err := musig2.AggregateKeys(
		[]*btcec.PublicKey{serverKey, ownerKey},
		false,
	)
	require.NoError(t, err)
	claimHash := tapLeafHash(claimScript)
	refundHash := tapLeafHash(refundScript)
	root := merkleRoot(claimHash[:], refundHash[:])
	taprootKey := txscript.ComputeTaprootOutputKey(aggregateKey.FinalKey, root)
	outputScript, err := txscript.PayToTaprootScript(taprootKey)
	require.NoError(t, err)
	return outputScript
}

func newTestOpts(t *testing.T, ownerKey *btcec.PublicKey) *Opts {
	t.Helper()
	return &Opts{
		Server: newTestPubKey(t),
		ClaimLeaf: Leaf{
			Output: hex.EncodeToString(newTestClaimLeafScript(t, ownerKey)),
		},
		RefundLeaf: Leaf{
			Output: hex.EncodeToString(newTestRefundLeafScript(t, newTestPubKey(t))),
		},
	}
}

func newTestKeyRef(t *testing.T) identity.KeyRef {
	t.Helper()
	return identity.KeyRef{Id: "m/0/0", PubKey: newTestPubKey(t)}
}

func newTestPubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv.PubKey()
}

func newTestOddPubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	for {
		pub := newTestPubKey(t)
		if pub.SerializeCompressed()[0] == 0x03 {
			return pub
		}
	}
}

func newTestClaimLeafScript(t *testing.T, claimKey *btcec.PublicKey) []byte {
	t.Helper()
	preimageHash := make([]byte, 20)
	_, err := rand.Read(preimageHash)
	require.NoError(t, err)

	scriptBytes, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddData([]byte{0x20}).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(claimKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)
	return scriptBytes
}

func newTestRefundLeafScript(t *testing.T, refundKey *btcec.PublicKey) []byte {
	t.Helper()
	scriptBytes, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(refundKey)).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddData([]byte{0xf8, 0x02}).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
	require.NoError(t, err)
	return scriptBytes
}
