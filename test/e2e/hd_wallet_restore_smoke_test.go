//go:build smoke

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const (
	smokeAmountSat = uint64(10_000)

	// This scenario funds continuous HD indexes. Seed restore scans until this
	// many consecutive unused addresses after the last funded index.
	smokeGapLimit = uint32(128)

	// Keep each SendOffChain call at the production round participant pace.
	smokeSendBatchSize = 128

	// Keep regtest from hitting Bitcoin Core's too-long-mempool-chain policy.
	smokeConfirmEveryBatches = 16
)

// TestSmokeHDWalletRestoreAtScale exercises the HD wallet and Contract Manager
// restore paths at the tier selected by SMOKE_TIER.
func TestSmokeHDWalletRestoreAtScale(t *testing.T) {
	N := parseSmokeTier(t)
	ctx := t.Context()

	t.Logf("starting HD wallet restore smoke test with N=%d", N)

	alice, aliceDatadir := setupSmokeClient(t, "", "",
		arksdk.WithGapLimit(smokeGapLimit),
		arksdk.WithoutAutoSettle(),
	)
	t.Logf("alice initialized, datadir=%s", aliceDatadir)

	bob, _ := setupSmokeClient(t, "", "", arksdk.WithoutAutoSettle())
	t.Log("bob initialized")

	addrs := make([]string, N)
	addrSet := make(map[string]struct{}, N)
	t.Logf("deriving %d addresses, each creating a default contract...", N)
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

	preStopContracts, err := alice.ContractManager().GetContracts(
		ctx, contract.WithType(types.ContractTypeDefault),
	)
	require.NoError(t, err)
	require.Lenf(
		t, preStopContracts, N,
		"alice should have exactly %d default contracts pre-stop, got %d",
		N, len(preStopContracts),
	)

	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	t.Logf("sending %d sat to %d addresses in batches of %d...",
		smokeAmountSat, N, smokeSendBatchSize,
	)
	sendStart := time.Now()
	expectedTotal := fundAndSendSmokeBatches(t, ctx, bob, addrs, smokeAmountSat)
	t.Logf(
		"batched send of %d payments took %v; expectedTotal=%d sat",
		N, time.Since(sendStart), expectedTotal,
	)

	timeout := smokeTierTimeout(N)
	requireSmokeWalletState(t, ctx, alice, N, expectedTotal, timeout, "pre-stop")
	t.Logf("pre-restore balance integrity confirmed: %d VTXOs, %d sat", N, expectedTotal)

	t.Logf("stopping alice, datadir=%s", aliceDatadir)
	alice.Stop()

	t.Logf("restoring alice from datadir=%s...", aliceDatadir)
	restoreStart := time.Now()
	restoredAlice := loadSmokeClient(t, aliceDatadir,
		arksdk.WithGapLimit(smokeGapLimit),
		arksdk.WithoutAutoSettle(),
	)
	t.Logf("LoadWallet completed in %v", time.Since(restoreStart))

	requireSmokeWalletState(t, ctx, restoredAlice, N, expectedTotal, timeout, "warm restore")
	requireSmokeDefaultContracts(t, ctx, restoredAlice, N, "warm restore")
	requireSmokeFreshAddress(t, ctx, restoredAlice, addrSet, "warm restore")
	t.Logf("warm restore integrity confirmed: %d VTXOs, %d sat", N, expectedTotal)

	restoredAlice.Stop()

	t.Log("restoring alice from seed into a fresh datadir...")
	seedRestoreStart := time.Now()
	seedRestoredAlice, seedDatadir := setupSmokeClient(t, "", seed,
		arksdk.WithGapLimit(smokeGapLimit),
		arksdk.WithoutAutoSettle(),
	)
	t.Logf(
		"seed restore completed in %v, datadir=%s",
		time.Since(seedRestoreStart), seedDatadir,
	)

	requireSmokeWalletState(t, ctx, seedRestoredAlice, N, expectedTotal, timeout, "seed restore")
	requireSmokeDefaultContracts(t, ctx, seedRestoredAlice, N, "seed restore")
	requireSmokeFreshAddress(t, ctx, seedRestoredAlice, addrSet, "seed restore")
	t.Logf("seed restore integrity confirmed: %d VTXOs, %d sat", N, expectedTotal)
}

func parseSmokeTier(t *testing.T) int {
	t.Helper()

	tier := strings.ToLower(strings.TrimSpace(os.Getenv("SMOKE_TIER")))
	switch tier {
	case "", "1k":
		return 1000
	case "10k":
		return 10000
	case "50k":
		return 50000
	default:
		t.Fatalf("unknown SMOKE_TIER: %q (allowed: 1k, 10k, 50k)", tier)
		return 0
	}
}

func smokeTierTimeout(N int) time.Duration {
	switch N {
	case 1000:
		return 20 * time.Minute
	case 10000:
		return 90 * time.Minute
	case 50000:
		return 180 * time.Minute
	default:
		return 20 * time.Minute
	}
}

func setupSmokeClient(
	t *testing.T, datadir string, seed string, opts ...arksdk.WalletOption,
) (arksdk.Wallet, string) {
	t.Helper()

	if datadir == "" {
		dir, err := os.MkdirTemp("", "smoke-wallet-*")
		require.NoError(t, err)
		datadir = dir
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("preserving failed smoke wallet datadir=%s", dir)
				return
			}
			_ = os.RemoveAll(dir)
		})
	}

	wallet, err := arksdk.NewWallet(datadir, opts...)
	require.NoError(t, err)

	err = wallet.Init(t.Context(), serverUrl, seed, password)
	require.NoError(t, err)

	err = wallet.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-wallet.IsSynced(t.Context())
	require.NoError(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(wallet.Stop)

	return wallet, datadir
}

func loadSmokeClient(
	t *testing.T, datadir string, opts ...arksdk.WalletOption,
) arksdk.Wallet {
	t.Helper()

	wallet, err := arksdk.LoadWallet(datadir, opts...)
	require.NoError(t, err)

	err = wallet.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-wallet.IsSynced(t.Context())
	require.NoError(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(wallet.Stop)

	return wallet
}

func fundAndSendSmokeBatches(
	t *testing.T,
	ctx context.Context,
	sender arksdk.Wallet,
	addrs []string,
	sat uint64,
) uint64 {
	t.Helper()

	t.Log("mining 1 block before smoke sends to clear any previous run's mempool chain")
	generateBlocks(t, 1)
	defer func() {
		if _, err := runCommand("nigiri", "rpc", "--generate", "1"); err != nil {
			t.Logf("failed to mine cleanup block after smoke sends: %v", err)
		}
	}()

	for offset := 0; offset < len(addrs); offset += smokeSendBatchSize {
		end := min(offset+smokeSendBatchSize, len(addrs))
		batch := addrs[offset:end]
		batchNum := offset/smokeSendBatchSize + 1
		batchAmount := uint64(len(batch)) * sat

		fundSmokeSenderExact(t, ctx, sender, batchAmount, offset, len(batch))

		receivers := make([]clienttypes.Receiver, len(batch))
		for i, addr := range batch {
			receivers[i] = clienttypes.Receiver{To: addr, Amount: sat}
		}

		_, err := sender.SendOffChain(ctx, receivers)
		require.NoErrorf(
			t, err,
			"SendOffChain failed for batch offset=%d size=%d", offset, len(batch),
		)

		requireSmokeOffchainBalance(t, ctx, sender, 0, 30*time.Second,
			"sender was not drained after batch offset=%d size=%d",
			offset, len(batch),
		)

		if batchNum%smokeConfirmEveryBatches == 0 && end < len(addrs) {
			generateBlocks(t, 1)
		}
	}

	return uint64(len(addrs)) * sat
}

func fundSmokeSenderExact(
	t *testing.T,
	ctx context.Context,
	sender arksdk.Wallet,
	amount uint64,
	offset int,
	batchSize int,
) {
	t.Helper()

	note := generateNote(t, amount)
	txid, err := sender.RedeemNotes(ctx, []string{note})
	require.NoErrorf(
		t, err,
		"RedeemNotes failed for send batch offset=%d size=%d", offset, batchSize,
	)
	require.NotEmpty(
		t, txid,
		"RedeemNotes returned empty txid for send batch offset=%d",
		offset,
	)

	requireSmokeOffchainBalance(t, ctx, sender, amount, 30*time.Second,
		"sender did not reach exact funding balance for batch offset=%d size=%d",
		offset, batchSize,
	)
}

func requireSmokeWalletState(
	t *testing.T,
	ctx context.Context,
	w arksdk.Wallet,
	N int,
	expectedTotal uint64,
	timeout time.Duration,
	label string,
) {
	t.Helper()

	t.Logf("waiting for %s wallet to show %d VTXOs and %d sat...", label, N, expectedTotal)
	require.Eventually(t, func() bool {
		spendable := listSmokeSpendableVtxos(t, w)
		return len(spendable) == N && sumVtxoAmounts(spendable) == expectedTotal
	}, timeout, 2*time.Second,
		"%s wallet did not recover all %d VTXOs within %v", label, N, timeout,
	)

	spendable := listSmokeSpendableVtxos(t, w)
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

func listSmokeSpendableVtxos(t *testing.T, wallet arksdk.Wallet) []clienttypes.Vtxo {
	t.Helper()

	_, vtxos := walkVtxoPages(
		t, wallet, arksdk.WithSpendableOnly(), arksdk.WithLimit(1000),
	)
	return vtxos
}

func requireSmokeDefaultContracts(
	t *testing.T, ctx context.Context, w arksdk.Wallet, N int, label string,
) {
	t.Helper()

	t.Logf("%s: scanning contracts with gapLimit=%d...", label, smokeGapLimit)
	scanStart := time.Now()
	err := w.ContractManager().ScanContracts(ctx, smokeGapLimit)
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

func requireSmokeFreshAddress(
	t *testing.T,
	ctx context.Context,
	w arksdk.Wallet,
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

func requireSmokeOffchainBalance(
	t *testing.T,
	ctx context.Context,
	wallet arksdk.Wallet,
	expected uint64,
	timeout time.Duration,
	msg string,
	args ...interface{},
) {
	t.Helper()

	msgAndArgs := append([]interface{}{msg}, args...)
	require.Eventually(t, func() bool {
		bal, err := wallet.Balance(ctx)
		return err == nil && bal.OffchainBalance.Total == expected
	}, timeout, 500*time.Millisecond, msgAndArgs...)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func formatSmokeTier(N int) string {
	switch N {
	case 1000:
		return "1k"
	case 10000:
		return "10k"
	case 50000:
		return "50k"
	default:
		return fmt.Sprintf("%d", N)
	}
}
