package contract_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	sdktypes "github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) wallet.KeyRef {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return wallet.KeyRef{Id: "test-key", PubKey: priv.PubKey()}
}

func testCfg(t *testing.T) contract.DelegateConfig {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return contract.DelegateConfig{
		SignerKey: priv.PubKey(),
		Network:   arklib.BitcoinRegTest,
		ExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 144,
		},
	}
}

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

	require.Equal(t, sdktypes.ContractTypeDelegate, c.Type)
	require.Equal(t, "test-key", c.Params[contract.ParamKeyID])
	require.Equal(t,
		hex.EncodeToString(delegatePriv.PubKey().SerializeCompressed()),
		c.Params[contract.ParamDelegateKey],
	)

	// Exactly 3 tapscripts: exit, forfeit, delegate.
	tapscripts, err := h.GetTapscripts(*c)
	require.NoError(t, err)
	require.Len(t, tapscripts, 3)

	// Signer key and exit delay are stored in params.
	require.Equal(t,
		hex.EncodeToString(schnorr.SerializePubKey(cfg.SignerKey)),
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
				Locktime: cfg.ExitDelay,
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, cfg.SignerKey},
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, delegatePriv.PubKey(), cfg.SignerKey},
			},
		},
	}
	refTapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)

	refAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerKey,
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

	ts1, err := h.GetTapscripts(*c1)
	require.NoError(t, err)
	ts2, err := h.GetTapscripts(*c2)
	require.NoError(t, err)
	require.Equal(t, ts1, ts2)
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
		_, err := h.DeriveContract(ctx, key, cfg, cfg.SignerKey)
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
		sel, err := h.SelectPath(
			context.Background(),
			*c,
			contract.PathContext{Collaborative: true},
		)
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)

		// Forfeit leaf is tapscripts[1].
		ts, err := h.GetTapscripts(*c)
		require.NoError(t, err)
		refScript, _ := hex.DecodeString(ts[1])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("collaborative with UseDelegatePath returns delegate leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), *c, contract.PathContext{
			Collaborative:   true,
			UseDelegatePath: true,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)

		// Delegate leaf is tapscripts[2].
		ts, err := h.GetTapscripts(*c)
		require.NoError(t, err)
		refScript, _ := hex.DecodeString(ts[2])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("unilateral returns exit leaf with BIP68 sequence", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(
			context.Background(),
			*c,
			contract.PathContext{Collaborative: false},
		)
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.NotNil(t, sel.Sequence)
		require.Nil(t, sel.Locktime)

		// Exit leaf is tapscripts[0].
		ts, err := h.GetTapscripts(*c)
		require.NoError(t, err)
		refScript, _ := hex.DecodeString(ts[0])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("UseDelegatePath without Collaborative returns exit leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), *c, contract.PathContext{
			Collaborative:   false,
			UseDelegatePath: true,
		})
		require.NoError(t, err)
		require.NotNil(t, sel.Sequence) // still an exit path

		ts, err := h.GetTapscripts(*c)
		require.NoError(t, err)
		refScript, _ := hex.DecodeString(ts[0])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("unilateral with missing exit delay returns error", func(t *testing.T) {
		t.Parallel()
		bad := sdktypes.Contract{
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
		bad := sdktypes.Contract{
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
			*c,
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
			*c,
			contract.PathContext{Collaborative: true},
		)
		require.NoError(t, err)
		require.Len(t, paths, 3)

		tapscripts, err := h.GetTapscripts(*c)
		require.NoError(t, err)

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
		bad := sdktypes.Contract{
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
		bad := sdktypes.Contract{
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

func TestDelegateHandler_ClosureOrdering(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	cfg := testCfg(t)
	delegatePriv := testDelegateKey(t)

	// Mirror the closure layout used by DeriveContract so that ForfeitClosures()
	// behaviour is verified against the exact structure the handler produces.
	// ForfeitClosures() matches every *MultisigClosure in Closures order; downstream
	// code that builds forfeit transactions uses forfeitClosures[0]. If the 3-of-3
	// delegate closure were placed before the 2-of-2 forfeit closure the server could
	// not produce a valid forfeit signature without the delegate key.
	vtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			// [0] exit — CSVMultisigClosure; excluded from ForfeitClosures
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{key.PubKey},
				},
				Locktime: cfg.ExitDelay,
			},
			// [1] forfeit — 2-of-2; must be forfeitClosures[0]
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, cfg.SignerKey},
			},
			// [2] delegate — 3-of-3; must be forfeitClosures[1]
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, delegatePriv.PubKey(), cfg.SignerKey},
			},
		},
	}

	forfeits := vtxoScript.ForfeitClosures()
	require.Len(t, forfeits, 2)

	forfeit, ok := forfeits[0].(*script.MultisigClosure)
	require.True(t, ok, "forfeitClosures[0] must be *MultisigClosure")
	require.Len(t, forfeit.PubKeys, 2, "forfeitClosures[0] must be 2-of-2 (owner+server)")

	delegate, ok := forfeits[1].(*script.MultisigClosure)
	require.True(t, ok, "forfeitClosures[1] must be *MultisigClosure")
	require.Len(t, delegate.PubKeys, 3, "forfeitClosures[1] must be 3-of-3 (owner+delegate+server)")

	// Verify DeriveContract produces a contract whose tap key matches this layout,
	// proving the handler uses this exact closure order.
	c, err := (&contract.DelegateHandler{}).DeriveContract(
		context.Background(), key, cfg, delegatePriv.PubKey(),
	)
	require.NoError(t, err)

	refTapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)
	refAddr := &arklib.Address{
		HRP: cfg.Network.Addr, Signer: cfg.SignerKey, VtxoTapKey: refTapKey,
	}
	refEncoded, err := refAddr.EncodeV0()
	require.NoError(t, err)
	require.Equal(t, refEncoded, c.Address,
		"DeriveContract address must match the expected closure ordering")
}
