package contract_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) wallet.KeyRef {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return wallet.KeyRef{Id: "test-key", PubKey: priv.PubKey()}
}

func testCfg(t *testing.T) *clientTypes.Config {
	t.Helper()
	serverPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return &clientTypes.Config{
		SignerPubKey: serverPriv.PubKey(),
		Network:      arklib.BitcoinRegTest,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 144,
		},
		BoardingExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 1008,
		},
	}
}

// splitContracts separates the three contracts returned by DeriveContracts.
func splitContracts(
	t *testing.T, cs []*contract.Contract,
) (offchain, boarding, onchain *contract.Contract) {
	t.Helper()
	for _, c := range cs {
		switch c.Type {
		case contract.TypeDefault:
			offchain = c
		case contract.TypeDefaultBoarding:
			boarding = c
		case contract.TypeDefaultOnchain:
			onchain = c
		}
	}
	require.NotNil(t, offchain, "expected offchain contract")
	require.NotNil(t, boarding, "expected boarding contract")
	require.NotNil(t, onchain, "expected onchain contract")
	return
}

func TestDefaultHandler_DeriveContract(t *testing.T) {
	t.Parallel()

	h := &contract.DefaultHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	cs, err := h.DeriveContracts(ctx, key, cfg)
	require.NoError(t, err)
	require.Len(t, cs, 3)

	offchain, boarding, onchain := splitContracts(t, cs)

	require.Equal(t, "test-key", offchain.Params[contract.ParamKeyID])
	delay, err := offchain.GetDelay()
	require.NoError(t, err)
	require.Equal(t, arklib.LocktimeTypeBlock, delay.Type)
	require.False(t, offchain.IsOnchain)
	require.True(t, boarding.IsOnchain)
	require.True(t, onchain.IsOnchain)

	// Offchain address matches arklib reference derivation.
	offchainScript := script.NewDefaultVtxoScript(
		key.PubKey, cfg.SignerPubKey, cfg.UnilateralExitDelay,
	)
	refVtxoTapKey, _, err := offchainScript.TapTree()
	require.NoError(t, err)

	refArkAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerPubKey,
		VtxoTapKey: refVtxoTapKey,
	}
	refEncoded, err := refArkAddr.EncodeV0()
	require.NoError(t, err)
	require.Equal(t, refEncoded, offchain.Address)

	// pkScript matches P2TR for the tap key.
	refPkScript, err := txscript.PayToTaprootScript(refVtxoTapKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(refPkScript), offchain.Script)

	// Boarding address matches reference.
	boardingScript := script.NewDefaultVtxoScript(
		key.PubKey, cfg.SignerPubKey, cfg.BoardingExitDelay,
	)
	boardingTapKey, _, err := boardingScript.TapTree()
	require.NoError(t, err)

	refBoarding, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(boardingTapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	require.Equal(t, refBoarding.EncodeAddress(), boarding.Address)

	// Onchain address is bare key-path P2TR.
	refOnchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
	refOnchain, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(refOnchainTapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	require.Equal(t, refOnchain.EncodeAddress(), onchain.Address)

	require.Len(t, offchain.GetTapscripts(), 2)
	require.Len(t, boarding.GetTapscripts(), 2)
	require.Empty(t, onchain.GetTapscripts())
}

func TestDefaultHandler_DeterministicOutput(t *testing.T) {
	t.Parallel()

	h := &contract.DefaultHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	cs1, err := h.DeriveContracts(ctx, key, cfg)
	require.NoError(t, err)
	cs2, err := h.DeriveContracts(ctx, key, cfg)
	require.NoError(t, err)

	off1, board1, on1 := splitContracts(t, cs1)
	off2, board2, on2 := splitContracts(t, cs2)

	require.Equal(t, off1.Script, off2.Script)
	require.Equal(t, off1.Address, off2.Address)
	require.Equal(t, board1.Script, board2.Script)
	require.Equal(t, board1.Address, board2.Address)
	require.Equal(t, on1.Script, on2.Script)
	require.Equal(t, on1.Address, on2.Address)
}

func TestDefaultHandler_DifferentKeysDifferentContracts(t *testing.T) {
	t.Parallel()

	h := &contract.DefaultHandler{}
	cfg := testCfg(t)
	ctx := context.Background()

	cs1, err := h.DeriveContracts(ctx, testKey(t), cfg)
	require.NoError(t, err)
	cs2, err := h.DeriveContracts(ctx, testKey(t), cfg)
	require.NoError(t, err)

	off1, board1, on1 := splitContracts(t, cs1)
	off2, board2, on2 := splitContracts(t, cs2)

	require.NotEqual(t, off1.Script, off2.Script)
	require.NotEqual(t, off1.Address, off2.Address)
	require.NotEqual(t, board1.Script, board2.Script)
	require.NotEqual(t, board1.Address, board2.Address)
	require.NotEqual(t, on1.Script, on2.Script)
	require.NotEqual(t, on1.Address, on2.Address)
}

func TestDefaultHandler_SelectPath(t *testing.T) {
	t.Parallel()

	h := &contract.DefaultHandler{}
	cfg := testCfg(t)
	ctx := context.Background()

	cs, err := h.DeriveContracts(ctx, testKey(t), cfg)
	require.NoError(t, err)
	offchain, _, _ := splitContracts(t, cs)

	t.Run("unilateral path has BIP68 sequence set", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(ctx, offchain, contract.PathContext{Collaborative: false})
		require.NoError(t, err)
		require.NotNil(t, sel.Sequence)
		require.Nil(t, sel.Locktime)
		require.NotEmpty(t, sel.Leaf.Script)
	})

	t.Run("collaborative path has no sequence", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(ctx, offchain, contract.PathContext{Collaborative: true})
		require.NoError(t, err)
		require.Nil(t, sel.Sequence)
		require.NotEmpty(t, sel.Leaf.Script)
	})

	t.Run("fewer than 2 tapscripts returns error", func(t *testing.T) {
		t.Parallel()
		bad := &contract.Contract{
			Params: map[string]string{contract.ParamTapscripts: `["aabb"]`},
		}
		_, err := h.SelectPath(ctx, bad, contract.PathContext{})
		require.Error(t, err)
	})
}

func TestDefaultHandler_GetSpendablePaths(t *testing.T) {
	t.Parallel()

	h := &contract.DefaultHandler{}
	cfg := testCfg(t)
	ctx := context.Background()

	cs, err := h.DeriveContracts(ctx, testKey(t), cfg)
	require.NoError(t, err)
	offchain, _, _ := splitContracts(t, cs)

	t.Run("unilateral context returns exit path only", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(ctx, offchain, contract.PathContext{Collaborative: false})
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.NotNil(t, paths[0].Sequence)
	})

	t.Run("collaborative context returns exit and forfeit paths", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(ctx, offchain, contract.PathContext{Collaborative: true})
		require.NoError(t, err)
		require.Len(t, paths, 2)
		require.NotNil(t, paths[0].Sequence) // exit path carries CSV sequence
		require.Nil(t, paths[1].Sequence)    // forfeit path has no sequence
	})

	t.Run("fewer than 2 tapscripts returns error", func(t *testing.T) {
		t.Parallel()
		bad := &contract.Contract{
			Params: map[string]string{contract.ParamTapscripts: `["aabb"]`},
		}
		_, err := h.GetSpendablePaths(ctx, bad, contract.PathContext{})
		require.Error(t, err)
	})
}

func TestDefaultHandler_UnknownNetwork(t *testing.T) {
	t.Parallel()

	h := &contract.DefaultHandler{}
	cfg := testCfg(t)
	cfg.Network = arklib.Network{Name: "does-not-exist"}

	_, err := h.DeriveContracts(context.Background(), testKey(t), cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does-not-exist")
}
