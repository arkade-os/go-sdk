package htlcHandler

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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

	expectedScript := expectedHTLCOutputScript(t, keyRef.PubKey, opts)
	require.Equal(t, hex.EncodeToString(expectedScript), got.Script)

	addr, err := btcutil.DecodeAddress(got.Address, &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	addrScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	require.Equal(t, got.Script, hex.EncodeToString(addrScript))
	require.Equal(
		t,
		hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		got.Params[paramClaimKey],
	)
	require.Equal(
		t,
		hex.EncodeToString(opts.ServerKey.SerializeCompressed()),
		got.Params[paramServerKey],
	)
	require.Equal(t, keyRef.Id, got.Params[paramClaimKeyID])
	require.NotContains(t, got.Params, paramRefundKeyID)
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
	require.Nil(t, signerKey)

	delay, err := h.GetExitDelay(*c)
	require.NoError(t, err)
	require.Nil(t, delay)

	tapscripts, err := h.GetTapscripts(*c)
	require.NoError(t, err)
	htlcScript, err := htlc.NewHTLCScriptFromOpts(*opts, keyRef.PubKey)
	require.NoError(t, err)
	require.Equal(t, []string{
		hex.EncodeToString(htlcScript.ClaimScript),
		hex.EncodeToString(htlcScript.RefundScript),
	}, tapscripts)
}

func TestHTLCHandlerFillsWalletRole(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)

	t.Run("wallet is claimer", func(t *testing.T) {
		opts := newTestOpts(t, newTestPubKey(t))
		opts.ClaimKey = nil

		c, err := h.NewContract(t.Context(), keyRef, opts)
		require.NoError(t, err)
		require.Equal(t, keyRef.Id, c.Params[paramClaimKeyID])
		require.NotContains(t, c.Params, paramRefundKeyID)
		require.Equal(
			t,
			hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
			c.Params[paramClaimKey],
		)
	})

	t.Run("wallet is refunder", func(t *testing.T) {
		opts := newTestOpts(t, newTestPubKey(t))
		opts.RefundKey = nil

		c, err := h.NewContract(t.Context(), keyRef, opts)
		require.NoError(t, err)
		require.Equal(t, keyRef.Id, c.Params[paramRefundKeyID])
		require.NotContains(t, c.Params, paramClaimKeyID)
		require.Equal(
			t,
			hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
			c.Params[paramRefundKey],
		)
	})
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

	expectedScript := expectedHTLCOutputScript(t, keyRef.PubKey, opts)
	restoredScript := expectedHTLCOutputScript(t, ref.PubKey, opts)
	require.Equal(t, expectedScript, restoredScript)
	require.Equal(t, hex.EncodeToString(expectedScript), c.Script)
}

func TestHTLCHandlerRejectsXOnlyStoredKeys(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)
	opts := newTestOpts(t, keyRef.PubKey)
	c, err := h.NewContract(t.Context(), keyRef, opts)
	require.NoError(t, err)

	c.Params[paramClaimKey] = hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey))
	ref, err := h.GetKeyRef(*c)
	require.Error(t, err)
	require.ErrorContains(t, err, "expected compressed key length")
	require.Nil(t, ref)

	c.Params[paramClaimKey] = hex.EncodeToString(keyRef.PubKey.SerializeCompressed())
	c.Params[paramServerKey] = hex.EncodeToString(schnorr.SerializePubKey(opts.ServerKey))
	signer, err := h.GetSignerKey(*c)
	require.NoError(t, err)
	require.Nil(t, signer)
}

func TestHTLCHandlerNewContractInvalid(t *testing.T) {
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)

	t.Run("nil params", func(t *testing.T) {
		got, err := h.NewContract(t.Context(), keyRef, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "requires *htlc.Opts")
		require.Nil(t, got)
	})

	t.Run("missing server", func(t *testing.T) {
		opts := newTestOpts(t, keyRef.PubKey)
		opts.ServerKey = nil

		got, err := h.NewContract(t.Context(), keyRef, opts)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing server key")
		require.Nil(t, got)
	})

	t.Run("owner key absent from scripts", func(t *testing.T) {
		opts := newTestOpts(t, newTestPubKey(t))

		got, err := h.NewContract(t.Context(), keyRef, opts)
		require.Error(t, err)
		require.ErrorContains(t, err, "wallet key is not present")
		require.Nil(t, got)
	})

	t.Run("missing counterparty key", func(t *testing.T) {
		opts := newTestOpts(t, keyRef.PubKey)
		opts.ClaimKey = nil
		opts.RefundKey = nil

		got, err := h.NewContract(t.Context(), keyRef, opts)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing counterparty HTLC key")
		require.Nil(t, got)
	})

	t.Run("missing refund locktime", func(t *testing.T) {
		opts := newTestOpts(t, keyRef.PubKey)
		opts.RefundLocktime = 0

		got, err := h.NewContract(t.Context(), keyRef, opts)
		require.Error(t, err)
		require.ErrorContains(t, err, "missing refund locktime")
		require.Nil(t, got)
	})
}

func expectedHTLCOutputScript(
	t *testing.T, ownerKey *btcec.PublicKey, opts *Opts,
) []byte {
	t.Helper()
	htlcScript, err := htlc.NewHTLCScriptFromOpts(*opts, ownerKey)
	require.NoError(t, err)

	outputScript, err := txscript.PayToTaprootScript(htlcScript.TaprootKey)
	require.NoError(t, err)
	return outputScript
}

func newTestOpts(t *testing.T, ownerKey *btcec.PublicKey) *Opts {
	t.Helper()
	preimageHash := make([]byte, htlc.Hash160Len)
	_, err := rand.Read(preimageHash)
	require.NoError(t, err)

	return &Opts{
		ServerKey:      newTestPubKey(t),
		ClaimKey:       ownerKey,
		RefundKey:      newTestPubKey(t),
		PreimageHash:   preimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(760),
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
