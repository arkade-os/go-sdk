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

	// Signer key and exit delay are stored in params.
	require.Equal(t,
		hex.EncodeToString(schnorr.SerializePubKey(cfg.SignerPubKey)),
		c.Params[contract.ParamSignerKey],
	)
	require.Equal(t, "block:144", c.Params[contract.ParamExitDelay])

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

func TestDelegateHandler_DeriveContract_Validation(t *testing.T) {
	t.Parallel()

	h := &contract.DelegateHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	t.Run("nil delegate key returns error", func(t *testing.T) {
		t.Parallel()
		_, err := h.DeriveContract(ctx, key, cfg, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("delegate key same as owner returns error", func(t *testing.T) {
		t.Parallel()
		_, err := h.DeriveContract(ctx, key, cfg, key.PubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "owner")
	})

	t.Run("delegate key same as signer returns error", func(t *testing.T) {
		t.Parallel()
		_, err := h.DeriveContract(ctx, key, cfg, cfg.SignerPubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signer")
	})
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

	t.Run("collaborative with UseDelegatePath returns delegate leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative:   true,
			UseDelegatePath: true,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)

		// Delegate leaf is tapscripts[2].
		refScript, _ := hex.DecodeString(c.GetTapscripts()[2])
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

	t.Run("UseDelegatePath without Collaborative returns exit leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative:   false,
			UseDelegatePath: true,
		})
		require.NoError(t, err)
		require.NotNil(t, sel.Sequence) // still an exit path

		refScript, _ := hex.DecodeString(c.GetTapscripts()[0])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("unilateral with missing exit delay returns error", func(t *testing.T) {
		t.Parallel()
		bad := &contract.Contract{
			Params: map[string]string{
				contract.ParamTapscripts: `["aabb","ccdd","eeff"]`,
				// no ParamExitDelay
			},
		}
		_, err := h.SelectPath(
			context.Background(),
			bad,
			contract.PathContext{Collaborative: false},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exit delay")
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

		tapscripts := c.GetTapscripts()

		exitScript, _ := hex.DecodeString(tapscripts[0])
		require.Equal(t, txscript.NewBaseTapLeaf(exitScript), paths[0].Leaf)
		require.NotNil(t, paths[0].Sequence)

		forfeitScript, _ := hex.DecodeString(tapscripts[1])
		require.Equal(t, txscript.NewBaseTapLeaf(forfeitScript), paths[1].Leaf)
		require.Nil(t, paths[1].Sequence)

		delegateScript, _ := hex.DecodeString(tapscripts[2])
		require.Equal(t, txscript.NewBaseTapLeaf(delegateScript), paths[2].Leaf)
		require.Nil(t, paths[2].Sequence)
	})

	t.Run("missing exit delay returns error", func(t *testing.T) {
		t.Parallel()
		bad := &contract.Contract{
			Params: map[string]string{
				contract.ParamTapscripts: `["aabb","ccdd","eeff"]`,
				// no ParamExitDelay
			},
		}
		_, err := h.GetSpendablePaths(context.Background(), bad, contract.PathContext{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "exit delay")
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
