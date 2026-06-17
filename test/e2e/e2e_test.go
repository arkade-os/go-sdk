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

// TestMigrateViaOffchainTx is the live-test gate for Change 1 (migrate via
// SendOffChain). It validates the UNPROVEN portion of the SendOffChain
// migration: specifically, whether arkd's SubmitTx handler accepts a PSBT where
// the input vtxo commits to a DEPRECATED signer key, and co-signs a checkpoint
// that moves the funds onto a CURRENT-signer output.
//
// The S17 live test proved the Settle / RegisterIntent (batch) path only. The
// new migration path uses SubmitTx / FinalizeTx (the SendOffChain transport),
// which is a structurally distinct server flow. The go-sdk client-lib does NOT
// signer-check input vtxos on the send path (createOffchainTx uses opts.vtxos
// directly when pinned via WithVtxos), and the receiver is always a
// current-signer address (newOffchainAddress, the arkd #822 invariant), but
// whether the SERVER accepts the deprecated-signer input on SubmitTx is a
// server-side concern that only a live run can confirm.
//
// This test MUST be run manually against a live arkd #1097 instance before the
// feat/deprecated-signer-rotation branch is merged (AC-8 / spec-rework.md
// "UNPROVEN Risk"). Remove the t.Skip below to execute. If the live run fails
// (arkd rejects the deprecated-signer input on SubmitTx), the SendOffChain
// migration approach is blocked pending a server-side fix.
//
// Asset extension: the scenario also issues TWO distinct assets under KEY A
// before the rotation and, after migration, asserts BOTH asset amounts are
// PRESERVED on the restored (KEY B) wallet — closing the silent-asset-strip
// defect. This also gates the asset co-sign path (deprecated-signer asset inputs
// on SubmitTx), which is UNPROVEN against arkd #1097 and shares the same
// live-test gate.
//
// Consolidation: migration collapses the whole ToMigrate set (BTC + both assets)
// into ONE current-signer vtxo. The test asserts a single consolidated vtxo that
// carries the full BTC balance and both assets, then SPENDS from it — a small BTC
// portion and a small amount of ONE asset via SendOffChain — and asserts the
// remaining BTC, the sent asset, and the untouched second asset all reconcile.
func TestMigrateViaOffchainTx(t *testing.T) {
	t.Skip(
		"requires arkd #1097; verifies SubmitTx accepts deprecated-signer input " +
			"(incl. asset inputs) and preserves assets across migration — " +
			"remove skip for manual pre-merge validation",
	)

	ctx := t.Context()

	// 1. Fund Alice under signer KEY A (the soon-to-be-deprecated current signer).
	alice := setupClient(t, "")
	const fundBtc = 0.001
	const fundSats = uint64(fundBtc * 1e8)
	faucetOffchain(t, alice, fundBtc)

	// 1b. Issue TWO distinct assets under KEY A (pre-rotation) so migration must
	// preserve BOTH (not silently strip either to sats — the silent-asset-strip
	// defect) AND consolidate them into the same output as the BTC balance.
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

	// Confirm alice holds both asset vtxos under KEY A before the rotation.
	require.Equal(t, assetSupplyA, totalAssetAmount(listVtxosWithAsset(t, alice, assetA), assetA),
		"full asset-A supply must be visible before rotation")
	require.Equal(t, assetSupplyB, totalAssetAmount(listVtxosWithAsset(t, alice, assetB), assetB),
		"full asset-B supply must be visible before rotation")

	preVtxos, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, preVtxos, "alice must hold spendable vtxos before rotation")
	// Total pre-rotation sats = the BTC funding plus the asset vtxo's dust
	// carrier; migration (offchain, no fee) must preserve this total exactly.
	preSats := totalVtxoAmount(preVtxos)
	require.Greater(t, preSats, fundSats,
		"pre-rotation sats include the asset carrier on top of the funding")

	// Record KEY A — the signer the funded vtxo commits to.
	oldSigner := vtxoSignerKey(t, alice, preVtxos[0])
	require.NotEmpty(t, oldSigner)

	// Export the seed so the migration runs from a fresh DB after the rotation.
	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	// 2. Rotate arkd: KEY B becomes the current signer, KEY A becomes a
	// deprecated signer with a FUTURE cutoff (so migration is still
	// collaborative). With arkd #1097 this is driven via the admin / operator
	// control; until that control is wired here this is the rotation step.
	migrateRotateArkd(t)

	// 3. Restore Alice from seed into a brand-new (empty) DB. migrateOnUnlock
	// fires during Unlock → reconcileDeprecatedSigners → sendOffchain (the
	// SubmitTx / FinalizeTx path under test).
	restored := setupClient(t, seed)

	// KEY B must now be the advertised current signer.
	currentSigner := arkdCurrentSigner(t, restored)
	require.NotEqual(t, oldSigner, currentSigner,
		"rotation must have changed the active signer (A → B)")

	// 4. Migration assertion: all KEY-A (ToMigrate) vtxos have been migrated onto
	// KEY-B outputs. Every surviving spendable vtxo must commit to KEY B.
	postVtxos, _, err := restored.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, postVtxos, "restored wallet must hold the migrated funds")
	for _, v := range postVtxos {
		require.Equal(t, currentSigner, vtxoSignerKey(t, restored, v),
			"every migrated vtxo must commit to the current signer KEY B (#822)")
	}

	// 4b. CONSOLIDATION: the whole ToMigrate set (BTC + both assets) must have
	// collapsed into exactly ONE current-signer vtxo carrying the full BTC
	// balance and BOTH assets — not one vtxo per asset profile.
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

	// 4c. Asset-preservation across the wallet: both totals unchanged, every
	// asset vtxo committing to KEY B (no asset stripped, the silent-asset-strip
	// defect).
	postA := listVtxosWithAsset(t, restored, assetA)
	postB := listVtxosWithAsset(t, restored, assetB)
	require.Equal(t, assetSupplyA, totalAssetAmount(postA, assetA),
		"total asset-A amount must be preserved across migration")
	require.Equal(t, assetSupplyB, totalAssetAmount(postB, assetB),
		"total asset-B amount must be preserved across migration")

	// 5. The SendOffChain path charges no fee: the migrated sats balance must
	// equal the pre-migration total (funding + asset carriers) exactly.
	require.Equal(t, preSats, totalVtxoAmount(postVtxos),
		"no fee consumed on the offchain (SubmitTx) migration path")

	bal, err := restored.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, preSats, bal.OffchainBalance.Total,
		"offchain sats balance preserved across the migration")

	// 6. The deprecated (KEY A) contract must be flipped to ContractStateInactive
	// after the successful migration.
	inactive, err := restored.ContractManager().GetContracts(
		ctx, contract.WithState(types.ContractStateInactive),
	)
	require.NoError(t, err)
	require.NotEmpty(t, inactive,
		"the migrated deprecated-signer contract must be marked inactive")
	for _, c := range inactive {
		require.Equal(t, types.ContractStateInactive, c.State)
	}

	// 7. PARTIAL SPEND from the consolidated vtxo: prove the migrated funds are
	// fully usable by spending a SMALL BTC portion and a SMALL amount of ONE asset
	// (asset A) to a fresh recipient, leaving the second asset (B) untouched.
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

	// 7a. Recipient balances: bob holds exactly the sent BTC and asset-A amount,
	// and none of asset B.
	bobBal, err := bob.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, sendBtc, bobBal.OffchainBalance.Total,
		"recipient must hold exactly the sent BTC portion")
	require.NotNil(t, bobBal.AssetBalances)
	require.Equal(t, sendAssetA, bobBal.AssetBalances[assetA],
		"recipient must hold exactly the sent asset-A amount")
	_, hasB := bobBal.AssetBalances[assetB]
	require.False(t, hasB, "recipient must not receive any of the untouched asset B")

	// 7b. Sender (change) balances: the remaining BTC is preserved (no fee), the
	// sent asset is debited, and the untouched asset B is unchanged.
	senderBal, err := restored.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, preSats-sendBtc, senderBal.OffchainBalance.Total,
		"sender must retain the remaining BTC (offchain send charges no fee)")
	require.Equal(t, assetSupplyA-sendAssetA, senderBal.AssetBalances[assetA],
		"sender's asset-A balance must be debited by the sent amount")
	require.Equal(t, assetSupplyB, senderBal.AssetBalances[assetB],
		"the untouched asset B must remain fully on the sender")
}

// findVtxoAssetAmount returns the amount of assetID carried by a single vtxo, or
// 0 if it carries none of that asset.
func findVtxoAssetAmount(vtxo clientTypes.Vtxo, assetID string) uint64 {
	for _, a := range vtxo.Assets {
		if a.AssetId == assetID {
			return a.Amount
		}
	}
	return 0
}

// totalAssetAmount sums, across the given vtxos, the amount of the asset with
// the given assetID (a vtxo may carry several assets; only assetID is counted).
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

// vtxoSignerKey returns the x-only hex of the signer the contract backing the
// given vtxo commits to, read from the stored contract via its handler.
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

// arkdCurrentSigner returns the x-only hex of arkd's CURRENT active signer as
// advertised over the wire.
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

// migrateRotateArkd triggers a signer rotation on the running arkd. Implemented
// against the admin API once arkd #1097 lands; today it fails loudly so the test
// can only be unskipped once the rotation control is available.
func migrateRotateArkd(t *testing.T) {
	t.Helper()
	t.Fatal(
		"migrateRotateArkd: server-side signer rotation (arkd #1097) is not yet " +
			"wired — remove the t.Skip only once arkd exposes the rotation control",
	)
}
