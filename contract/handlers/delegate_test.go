package handlers_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func delegatePubKeyParam(t *testing.T) (*btcec.PrivateKey, map[string]string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv, map[string]string{
		"delegatePubKey": hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey())),
	}
}

func TestDelegateHandler_Type(t *testing.T) {
	t.Parallel()
	h := &handlers.DelegateHandler{}
	require.Equal(t, handlers.TypeDelegate, h.Type())
}

func TestDelegateHandler_DeriveContract(t *testing.T) {
	t.Parallel()

	h := &handlers.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	delegatePriv, rawParams := delegatePubKeyParam(t)
	ctx := context.Background()

	c, err := h.DeriveContract(ctx, key, cfg, rawParams)
	require.NoError(t, err)
	require.NotNil(t, c)

	require.Equal(t, handlers.TypeDelegate, c.Type)
	require.Equal(t, "test-key", c.Params["keyId"])
	require.Equal(t, rawParams["delegatePubKey"], c.Params["delegatePubKey"])

	// Must produce exactly 3 tapscripts (exit, forfeit, delegate).
	require.Len(t, c.Tapscripts, 3)

	// No boarding/onchain facets for delegate contracts.
	require.Empty(t, c.Boarding)
	require.Empty(t, c.Onchain)

	// Address matches manual derivation.
	vtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{key.PubKey},
				},
				Locktime: cfg.UnilateralExitDelay,
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, cfg.SignerPubKey},
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, delegatePriv.PubKey(), cfg.SignerPubKey},
			},
		},
	}
	refTapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)

	refAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerPubKey,
		VtxoTapKey: refTapKey,
	}
	refEncoded, err := refAddr.EncodeV0()
	require.NoError(t, err)
	require.Equal(t, refEncoded, c.Address)

	// pkScript matches P2TR for the tap key.
	refPkScript, err := txscript.PayToTaprootScript(refTapKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(refPkScript), c.Script)
}

func TestDelegateHandler_MissingParam(t *testing.T) {
	t.Parallel()

	h := &handlers.DelegateHandler{}
	_, err := h.DeriveContract(context.Background(), testKey(t), testCfg(t), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "delegatePubKey")

	_, err = h.DeriveContract(context.Background(), testKey(t), testCfg(t), map[string]string{})
	require.Error(t, err)
	require.ErrorContains(t, err, "delegatePubKey")
}

func TestDelegateHandler_DeterministicOutput(t *testing.T) {
	t.Parallel()

	h := &handlers.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	_, rawParams := delegatePubKeyParam(t)
	ctx := context.Background()

	c1, err := h.DeriveContract(ctx, key, cfg, rawParams)
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, key, cfg, rawParams)
	require.NoError(t, err)

	require.Equal(t, c1.Script, c2.Script)
	require.Equal(t, c1.Address, c2.Address)
	require.Equal(t, c1.Tapscripts, c2.Tapscripts)
}

func TestDelegateHandler_DifferentDelegateDifferentScript(t *testing.T) {
	t.Parallel()

	h := &handlers.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	_, p1 := delegatePubKeyParam(t)
	_, p2 := delegatePubKeyParam(t)

	c1, err := h.DeriveContract(ctx, key, cfg, p1)
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, key, cfg, p2)
	require.NoError(t, err)

	require.NotEqual(t, c1.Script, c2.Script)
	require.NotEqual(t, c1.Address, c2.Address)
}

func TestDelegateHandler_SelectPath(t *testing.T) {
	t.Parallel()

	h := &handlers.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	_, rawParams := delegatePubKeyParam(t)

	c, err := h.DeriveContract(context.Background(), key, cfg, rawParams)
	require.NoError(t, err)

	t.Run("collaborative returns forfeit leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{Collaborative: true})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)

		// Forfeit leaf is Tapscripts[1].
		refScript, _ := hex.DecodeString(c.Tapscripts[1])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("unilateral returns exit leaf with sequence", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(
			context.Background(),
			c,
			contract.PathContext{Collaborative: false},
		)
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.NotNil(t, sel.Sequence)

		// Exit leaf is Tapscripts[0].
		refScript, _ := hex.DecodeString(c.Tapscripts[0])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})
}

func TestDelegateHandler_GetSpendablePaths(t *testing.T) {
	t.Parallel()

	h := &handlers.DelegateHandler{}
	_, rawParams := delegatePubKeyParam(t)
	c, err := h.DeriveContract(context.Background(), testKey(t), testCfg(t), rawParams)
	require.NoError(t, err)

	t.Run("unilateral returns only exit", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(
			context.Background(),
			c,
			contract.PathContext{Collaborative: false},
		)
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.NotNil(t, paths[0].Sequence)
	})

	t.Run("collaborative returns exit + forfeit + delegate", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(
			context.Background(),
			c,
			contract.PathContext{Collaborative: true},
		)
		require.NoError(t, err)
		require.Len(t, paths, 3)
		// First path is exit (has sequence), remaining are collaborative (no sequence).
		require.NotNil(t, paths[0].Sequence)
		require.Nil(t, paths[1].Sequence)
		require.Nil(t, paths[2].Sequence)
	})
}
