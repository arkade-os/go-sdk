package e2e_test

import (
	"encoding/hex"
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// TestMigrateViaOffchainTx verifies that a live arkd accepts deprecated-signer
// inputs through SubmitTx/FinalizeTx and migrates BTC plus assets into one
// current-signer output.
func TestMigrateViaOffchainTx(t *testing.T) {
	t.Skip(
		"requires arkd #1097; verifies SubmitTx accepts deprecated-signer input " +
			"(incl. asset inputs) and preserves assets across migration — " +
			"remove skip for manual pre-merge validation",
	)

	ctx := t.Context()

	// Fund Alice under KEY A, then issue two assets to verify asset preservation.
	alice := setupClient(t, "")
	const fundBtc = 0.001
	const fundSats = uint64(fundBtc * 1e8)
	faucetOffchain(t, alice, fundBtc)

	const assetSupplyA = uint64(5_000)
	const assetSupplyB = uint64(3_000)

	_, assetIdsA, err := alice.IssueAsset(ctx, assetSupplyA, nil, nil)
	require.NoError(t, err)
	require.Len(t, assetIdsA, 1)
	assetA := assetIdsA[0].String()

	_, assetIdsB, err := alice.IssueAsset(ctx, assetSupplyB, nil, nil)
	require.NoError(t, err)
	require.Len(t, assetIdsB, 1)
	assetB := assetIdsB[0].String()
	require.NotEqual(t, assetA, assetB, "the two issued assets must be distinct")

	require.Equal(t, assetSupplyA, totalAssetAmount(listVtxosWithAsset(t, alice, assetA), assetA),
		"full asset-A supply must be visible before rotation")
	require.Equal(t, assetSupplyB, totalAssetAmount(listVtxosWithAsset(t, alice, assetB), assetB),
		"full asset-B supply must be visible before rotation")

	preVtxos, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, preVtxos, "alice must hold spendable vtxos before rotation")
	// Includes the BTC funding plus asset carrier sats.
	preSats := totalVtxoAmount(preVtxos)
	require.Greater(t, preSats, fundSats,
		"pre-rotation sats include the asset carrier on top of the funding")

	oldSigner := vtxoSignerKey(t, alice, preVtxos[0])
	require.NotEmpty(t, oldSigner)

	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	// Rotate: KEY B becomes current, KEY A becomes deprecated before cutoff.
	migrateRotateArkd(t)

	// Restore from seed so migration runs during Unlock.
	restored := setupClient(t, seed)

	currentSigner := arkdCurrentSigner(t, restored)
	require.NotEqual(t, oldSigner, currentSigner,
		"rotation must have changed the active signer (A → B)")

	// All surviving spendable vtxos must now commit to KEY B.
	postVtxos, _, err := restored.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, postVtxos, "restored wallet must hold the migrated funds")
	for _, v := range postVtxos {
		require.Equal(t, currentSigner, vtxoSignerKey(t, restored, v),
			"every migrated vtxo must commit to the current signer KEY B (#822)")
	}

	// Migration consolidates BTC plus both assets into one current-signer vtxo.
	require.Len(t, postVtxos, 1,
		"migration must consolidate the whole set into a single vtxo")
	consolidated := postVtxos[0]
	require.Equal(t, currentSigner, vtxoSignerKey(t, restored, consolidated),
		"the consolidated vtxo must commit to the current signer KEY B (#822)")
	require.Equal(t, preSats, consolidated.Amount,
		"the consolidated vtxo must hold the full migrated BTC balance")
	require.Equal(t, assetSupplyA, findVtxoAssetAmount(consolidated, assetA),
		"the consolidated vtxo must carry the full asset-A supply")
	require.Equal(t, assetSupplyB, findVtxoAssetAmount(consolidated, assetB),
		"the consolidated vtxo must carry the full asset-B supply")

	// Asset totals must be unchanged after migration.
	postA := listVtxosWithAsset(t, restored, assetA)
	postB := listVtxosWithAsset(t, restored, assetB)
	require.Equal(t, assetSupplyA, totalAssetAmount(postA, assetA),
		"total asset-A amount must be preserved across migration")
	require.Equal(t, assetSupplyB, totalAssetAmount(postB, assetB),
		"total asset-B amount must be preserved across migration")

	// SendOffChain migration should preserve the full sats balance.
	require.Equal(t, preSats, totalVtxoAmount(postVtxos),
		"no fee consumed on the offchain (SubmitTx) migration path")

	bal, err := restored.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, preSats, bal.OffchainBalance.Total,
		"offchain sats balance preserved across the migration")

	// The deprecated KEY-A contract is inactive after successful migration.
	inactive, err := restored.ContractManager().GetContracts(
		ctx, contract.WithState(types.ContractStateInactive),
	)
	require.NoError(t, err)
	require.NotEmpty(t, inactive,
		"the migrated deprecated-signer contract must be marked inactive")
	for _, c := range inactive {
		require.Equal(t, types.ContractStateInactive, c.State)
	}

	// Spend part of the consolidated vtxo to prove the migrated funds are usable.
	bob := setupClient(t, "")
	bobAddr, err := bob.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobAddr)

	const sendBtc = uint64(20_000)   // a small BTC portion of the consolidated vtxo
	const sendAssetA = uint64(1_200) // a small portion of asset A (supply 5_000)
	require.Less(t, sendBtc, preSats, "the BTC spend must be a portion of the balance")
	require.Less(t, sendAssetA, assetSupplyA, "the asset spend must be a portion of supply")

	_, err = restored.SendOffChain(ctx, []clientTypes.Receiver{
		{
			To:     bobAddr,
			Amount: sendBtc,
			Assets: []clientTypes.Asset{{AssetId: assetA, Amount: sendAssetA}},
		},
	})
	require.NoError(t, err,
		"spending BTC + a single asset from the consolidated vtxo must succeed")

	// Recipient gets BTC and asset A only.
	bobBal, err := bob.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, sendBtc, bobBal.OffchainBalance.Total,
		"recipient must hold exactly the sent BTC portion")
	require.NotNil(t, bobBal.AssetBalances)
	require.Equal(t, sendAssetA, bobBal.AssetBalances[assetA],
		"recipient must hold exactly the sent asset-A amount")
	_, hasB := bobBal.AssetBalances[assetB]
	require.False(t, hasB, "recipient must not receive any of the untouched asset B")

	// Sender keeps the remaining BTC, debited asset A, and all of asset B.
	senderBal, err := restored.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, preSats-sendBtc, senderBal.OffchainBalance.Total,
		"sender must retain the remaining BTC (offchain send charges no fee)")
	require.Equal(t, assetSupplyA-sendAssetA, senderBal.AssetBalances[assetA],
		"sender's asset-A balance must be debited by the sent amount")
	require.Equal(t, assetSupplyB, senderBal.AssetBalances[assetB],
		"the untouched asset B must remain fully on the sender")
}

// findVtxoAssetAmount returns the amount of assetID carried by one vtxo.
func findVtxoAssetAmount(vtxo clientTypes.Vtxo, assetID string) uint64 {
	for _, a := range vtxo.Assets {
		if a.AssetId == assetID {
			return a.Amount
		}
	}
	return 0
}

// totalAssetAmount sums assetID across vtxos.
func totalAssetAmount(vtxos []clientTypes.Vtxo, assetID string) uint64 {
	var total uint64
	for _, v := range vtxos {
		for _, a := range v.Assets {
			if a.AssetId == assetID {
				total += a.Amount
			}
		}
	}
	return total
}

// totalVtxoAmount sums the amounts of the given vtxos.
func totalVtxoAmount(vtxos []clientTypes.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

// vtxoSignerKey returns the stored contract signer's x-only hex.
func vtxoSignerKey(t *testing.T, w arksdk.Wallet, vtxo clientTypes.Vtxo) string {
	t.Helper()
	mgr := w.ContractManager()
	require.NotNil(t, mgr)

	contracts, err := mgr.GetContracts(t.Context(), contract.WithScripts([]string{vtxo.Script}))
	require.NoError(t, err)
	require.Len(t, contracts, 1, "expected exactly one contract for vtxo script %s", vtxo.Script)

	handler, err := mgr.GetHandler(t.Context(), contracts[0])
	require.NoError(t, err)
	signerKey, err := handler.GetSignerKey(contracts[0])
	require.NoError(t, err)
	return hex.EncodeToString(schnorr.SerializePubKey(signerKey))
}

// arkdCurrentSigner returns arkd's current signer as x-only hex.
func arkdCurrentSigner(t *testing.T, w arksdk.Wallet) string {
	t.Helper()
	info, err := w.Client().GetInfo(t.Context())
	require.NoError(t, err)
	buf, err := hex.DecodeString(info.SignerPubKey)
	require.NoError(t, err)
	// btcec.ParsePubKey accepts both compressed and x-only inputs.
	key, err := btcec.ParsePubKey(buf)
	require.NoError(t, err)
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

// migrateRotateArkd is wired once the arkd rotation control is available.
func migrateRotateArkd(t *testing.T) {
	t.Helper()
	t.Fatal(
		"migrateRotateArkd: server-side signer rotation (arkd #1097) is not yet " +
			"wired — remove the t.Skip only once arkd exposes the rotation control",
	)
}
