//go:build stress

package stress_test

import (
	"context"
	"testing"
	"time"

	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

// TestStressHDWalletAndContractManager exercises the HD wallet + Contract
// Manager stack at the tier selected by the STRESS_TIER env var.
//
// The scenario is intentionally one big sequential function so the phases
// remain easy to correlate with the spec and so log output reads top-to-bottom
// at runtime.
//
//	Phase 1 — Setup Alice (stable datadir) and Bob.
//	Phase 2 — Derive N offchain addresses on Alice and create N default
//	          contracts so the Contract Manager key counter advances in
//	          lock-step with the wallet's offchain key counter.
//	Phase 3 — Bob receives one exact funding VTXO per batch, then sends
//	          `amountSat` to each of Alice's N addresses in batches of 128.
//	Phase 4 — Verify Alice's pre-restore balance integrity.
//	Phase 5 — Stop Alice (keep her datadir on disk).
//	Phase 6 — LoadWallet from the same datadir (inherits the Contract
//	          Manager SQLite store, exercises the warm-restore path).
//	Phase 7 — Verify warm-restore VTXO, balance, Contract Manager and next
//	          address integrity.
//	Phase 8 — Restore the dumped seed into a fresh datadir.
//	Phase 9 — Verify seed-restore VTXO, balance, Contract Manager and next
//	          address integrity.
func TestStressHDWalletAndContractManager(t *testing.T) {
	N := parseTier(t)
	ctx := t.Context()

	t.Logf("starting stress test with N=%d", N)

	// ── Phase 1: Setup ──────────────────────────────────────────────────
	// Alice uses a stable datadir so we can re-open it after Stop.
	alice, aliceDatadir := setupStressClient(t, "", "",
		sdk.WithGapLimit(stressGapLimit),
		sdk.WithoutAutoSettle(),
	)
	t.Logf("alice initialized, datadir=%s", aliceDatadir)

	bob, _ := setupStressClient(t, "", "",
		sdk.WithoutAutoSettle(),
	)
	t.Logf("bob initialized")

	// ── Phase 2: Derive N addresses (each backed by a default contract) ─
	//
	// In go-sdk, NewOffchainAddress IS contract.NewContract(ContractTypeDefault):
	// see wallet.newOffchainAddress.  So a single derive loop advances both
	// the HD key counter and the Contract Manager's default contract counter
	// in lock-step, producing exactly N default contracts.  The earlier
	// pseudocode that called NewOffchainAddress AND NewContract was a
	// double-derive and is intentionally collapsed here.
	addrs := make([]string, N)
	addrSet := make(map[string]struct{}, N)
	t.Logf("deriving %d addresses (each creating a default contract)...", N)
	insertStart := time.Now()
	for i := 0; i < N; i++ {
		addr, err := alice.NewOffchainAddress(ctx)
		require.NoErrorf(t, err, "NewOffchainAddress failed at i=%d", i)
		if _, ok := addrSet[addr]; ok {
			t.Fatalf("NewOffchainAddress returned duplicate address at i=%d: %s", i, addr)
		}
		addrs[i] = addr
		addrSet[addr] = struct{}{}
	}
	t.Logf(
		"address derivation for N=%d took %v (%.1f items/sec)",
		N, time.Since(insertStart), float64(N)/time.Since(insertStart).Seconds(),
	)

	// Sanity: the manager should hold exactly N default contracts now.
	preStopContracts, err := alice.ContractManager().GetContracts(
		ctx, contract.WithType(types.ContractTypeDefault),
	)
	require.NoError(t, err)
	require.Lenf(
		t, preStopContracts, N,
		"alice should have exactly %d default contracts pre-stop, got %d", N, len(preStopContracts),
	)

	// Dump seed before stopping so the test can cover both warm reload and
	// fresh seed restore.
	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	// ── Phase 3: Send to all N addresses ────────────────────────────────
	t.Logf("sending %d sat to %d addresses in batches of %d...", amountSat, N, sendBatchSize)
	sendStart := time.Now()
	expectedTotal := fundAndSendBatched(t, ctx, bob, addrs, amountSat)
	t.Logf(
		"batched send of %d payments took %v; expectedTotal=%d sat",
		N, time.Since(sendStart), expectedTotal,
	)

	// ── Phase 4: Pre-restore balance integrity ──────────────────────────
	timeout := tierTimeout(N)
	requireWalletState(t, ctx, alice, N, expectedTotal, timeout, "pre-stop")
	t.Logf("pre-restore balance integrity confirmed: %d VTXOs, %d sat", N, expectedTotal)

	// ── Phase 5: Stop Alice ──────────────────────────────────────────────
	t.Logf("stopping alice, datadir=%s", aliceDatadir)
	alice.Stop()
	alice = nil //nolint:ineffassign,wastedassign // explicit nil to make GC eligibility obvious

	// ── Phase 6: Restore from same datadir ──────────────────────────────
	t.Logf("restoring alice from datadir=%s...", aliceDatadir)
	restoreStart := time.Now()
	restoredAlice := loadStressClient(t, aliceDatadir,
		sdk.WithGapLimit(stressGapLimit),
		sdk.WithoutAutoSettle(),
	)
	t.Logf("loadStressClient (IsSynced) completed in %v", time.Since(restoreStart))

	// ── Phase 7: Warm-restore recovery integrity ────────────────────────
	requireWalletState(t, ctx, restoredAlice, N, expectedTotal, timeout, "warm restore")
	requireDefaultContracts(t, ctx, restoredAlice, N, "warm restore")
	requireFreshAddress(t, ctx, restoredAlice, addrSet, "warm restore")
	t.Logf("warm restore integrity confirmed: %d VTXOs, %d sat", N, expectedTotal)

	restoredAlice.Stop()

	// ── Phase 8: Restore from seed into a fresh datadir ──────────────────
	t.Logf("restoring alice from seed into a fresh datadir...")
	seedRestoreStart := time.Now()
	seedRestoredAlice, seedDatadir := setupStressClient(t, "", seed,
		sdk.WithGapLimit(stressGapLimit),
		sdk.WithoutAutoSettle(),
	)
	t.Logf(
		"seed restore completed in %v, datadir=%s",
		time.Since(seedRestoreStart), seedDatadir,
	)

	// ── Phase 9: Seed-restore recovery integrity ────────────────────────
	requireWalletState(t, ctx, seedRestoredAlice, N, expectedTotal, timeout, "seed restore")
	requireDefaultContracts(t, ctx, seedRestoredAlice, N, "seed restore")
	requireFreshAddress(t, ctx, seedRestoredAlice, addrSet, "seed restore")
	t.Logf("seed restore integrity confirmed: %d VTXOs, %d sat", N, expectedTotal)

	t.Logf("TestStressHDWalletAndContractManager PASSED for N=%d", N)
}

func requireWalletState(
	t *testing.T,
	ctx context.Context,
	w sdk.Wallet,
	N int,
	expectedTotal uint64,
	timeout time.Duration,
	label string,
) {
	t.Helper()

	t.Logf("waiting for %s wallet to show %d VTXOs and %d sat...", label, N, expectedTotal)
	require.Eventually(t, func() bool {
		spendable, err := listAllVtxos(ctx, w, sdk.WithSpendableOnly())
		return err == nil && len(spendable) == N && sumVtxoAmounts(spendable) == expectedTotal
	}, timeout, 2*time.Second,
		"%s wallet did not recover all %d VTXOs within %v", label, N, timeout,
	)

	spendable, err := listAllVtxos(ctx, w, sdk.WithSpendableOnly())
	require.NoError(t, err)
	require.Lenf(t, spendable, N, "%s wallet: expected %d spendable VTXOs", label, N)
	require.Equalf(
		t, expectedTotal, sumVtxoAmounts(spendable),
		"%s wallet VTXO sum mismatch: expected %d sat", label, expectedTotal,
	)

	balance, err := w.Balance(ctx)
	require.NoError(t, err)
	require.EqualValuesf(
		t, expectedTotal, balance.OffchainBalance.Total,
		"%s wallet balance integrity: expected %d sat, got %d",
		label, expectedTotal, balance.OffchainBalance.Total,
	)
}

func requireDefaultContracts(
	t *testing.T, ctx context.Context, w sdk.Wallet, N int, label string,
) {
	t.Helper()

	t.Logf("%s: scanning contracts with gapLimit=%d...", label, stressGapLimit)
	scanStart := time.Now()
	err := w.ContractManager().ScanContracts(ctx, stressGapLimit)
	require.NoError(t, err)
	t.Logf("%s: ScanContracts took %v", label, time.Since(scanStart))

	allContracts, err := w.ContractManager().GetContracts(
		ctx, contract.WithType(types.ContractTypeDefault),
	)
	require.NoError(t, err)
	require.Lenf(
		t, allContracts, N,
		"%s contract manager should hold %d default contracts, got %d",
		label, N, len(allContracts),
	)
}

func requireFreshAddress(
	t *testing.T,
	ctx context.Context,
	w sdk.Wallet,
	used map[string]struct{},
	label string,
) {
	t.Helper()

	nextAddr, err := w.NewOffchainAddress(ctx)
	require.NoError(t, err)
	if _, ok := used[nextAddr]; ok {
		t.Fatalf("%s next address reused a pre-derived address: %s", label, nextAddr)
	}
	t.Logf("%s address reuse check passed: next address %s is fresh", label, nextAddr)
}
