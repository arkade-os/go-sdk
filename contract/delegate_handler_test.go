package contract_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func testDelegateKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv
}

func TestDelegateHandler_DeriveContract(t *testing.T) {
	t.Parallel()

	h := &contract.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	delegatePriv := testDelegateKey(t)
	ctx := context.Background()

	c, err := h.DeriveContract(ctx, key, cfg, delegatePriv.PubKey())
	require.NoError(t, err)
	require.NotNil(t, c)

	require.Equal(t, contract.TypeDelegate, c.Type)
	require.False(t, c.IsOnchain)
	require.Equal(t, "test-key", c.Params[contract.ParamKeyID])
	require.Equal(t,
		hex.EncodeToString(schnorr.SerializePubKey(delegatePriv.PubKey())),
		c.Params[contract.ParamDelegateKey],
	)

	// Exactly 3 tapscripts: exit, forfeit, delegate.
	require.Len(t, c.GetTapscripts(), 3)

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

	refPkScript, err := txscript.PayToTaprootScript(refTapKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(refPkScript), c.Script)
}

func TestDelegateHandler_DeterministicOutput(t *testing.T) {
	t.Parallel()

	h := &contract.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	delegatePriv := testDelegateKey(t)
	ctx := context.Background()

	c1, err := h.DeriveContract(ctx, key, cfg, delegatePriv.PubKey())
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, key, cfg, delegatePriv.PubKey())
	require.NoError(t, err)

	require.Equal(t, c1.Script, c2.Script)
	require.Equal(t, c1.Address, c2.Address)
	require.Equal(t, c1.GetTapscripts(), c2.GetTapscripts())
}

func TestDelegateHandler_DifferentDelegateDifferentScript(t *testing.T) {
	t.Parallel()

	h := &contract.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	c1, err := h.DeriveContract(ctx, key, cfg, testDelegateKey(t).PubKey())
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, key, cfg, testDelegateKey(t).PubKey())
	require.NoError(t, err)

	require.NotEqual(t, c1.Script, c2.Script)
	require.NotEqual(t, c1.Address, c2.Address)
}

func TestDelegateHandler_SelectPath(t *testing.T) {
	t.Parallel()

	h := &contract.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	delegatePriv := testDelegateKey(t)

	c, err := h.DeriveContract(context.Background(), key, cfg, delegatePriv.PubKey())
	require.NoError(t, err)

	t.Run("collaborative returns forfeit leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{Collaborative: true})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)

		// Forfeit leaf is tapscripts[1].
		refScript, _ := hex.DecodeString(c.GetTapscripts()[1])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("unilateral returns exit leaf with BIP68 sequence", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(
			context.Background(),
			c,
			contract.PathContext{Collaborative: false},
		)
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.NotNil(t, sel.Sequence)
		require.Nil(t, sel.Locktime)

		// Exit leaf is tapscripts[0].
		refScript, _ := hex.DecodeString(c.GetTapscripts()[0])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("fewer than 3 tapscripts returns error", func(t *testing.T) {
		t.Parallel()
		bad := &contract.Contract{
			Params: map[string]string{
				contract.ParamTapscripts: `["aabb","ccdd"]`,
				contract.ParamExitDelay:  "block:144",
			},
		}
		_, err := h.SelectPath(context.Background(), bad, contract.PathContext{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "3 tapscripts")
	})
}

func TestDelegateHandler_GetSpendablePaths(t *testing.T) {
	t.Parallel()

	h := &contract.DelegateHandler{}
	delegatePriv := testDelegateKey(t)
	c, err := h.DeriveContract(context.Background(), testKey(t), testCfg(t), delegatePriv.PubKey())
	require.NoError(t, err)

	t.Run("unilateral returns only exit path", func(t *testing.T) {
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

	t.Run("collaborative returns exit, forfeit, delegate paths", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(
			context.Background(),
			c,
			contract.PathContext{Collaborative: true},
		)
		require.NoError(t, err)
		require.Len(t, paths, 3)
		require.NotNil(t, paths[0].Sequence) // exit has CSV sequence
		require.Nil(t, paths[1].Sequence)    // forfeit: no sequence
		require.Nil(t, paths[2].Sequence)    // delegate: no sequence
	})

	t.Run("fewer than 3 tapscripts returns error", func(t *testing.T) {
		t.Parallel()
		bad := &contract.Contract{
			Params: map[string]string{
				contract.ParamTapscripts: `["aabb","ccdd"]`,
				contract.ParamExitDelay:  "block:144",
			},
		}
		_, err := h.GetSpendablePaths(context.Background(), bad, contract.PathContext{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "3 tapscripts")
	})
}
