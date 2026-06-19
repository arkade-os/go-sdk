//go:build smoke

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const (
	smokeAmountSat = uint64(330)

	// This scenario funds continuous HD indexes. Seed restore scans until this
	// many consecutive unused addresses after the last funded index.
	smokeGapLimit = uint32(1000)
)

// TestSmokeHDWalletRestoreAtScale exercises the HD wallet and Contract Manager
// restore paths at the tier selected by SMOKE_TIER.
func TestSmokeHDWalletRestoreAtScale(t *testing.T) {
	N := parseSmokeTier(t)
	ctx := t.Context()

	t.Logf("=== START tier=%d gapLimit=%d amountSat=%d ===", N, smokeGapLimit, smokeAmountSat)

	alice, aliceDatadir := setupSmokeClient(t, "", arksdk.WithoutAutoSettle())
	t.Logf("alice datadir: %s", aliceDatadir)

	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)
	t.Logf("alice mnemonic: %s", seed)

	bob, bobDatadir := setupSmokeClient(t, "", arksdk.WithoutAutoSettle())
	t.Logf("bob datadir: %s", bobDatadir)

	addrs := make([]string, N)
	addrSet := make(map[string]struct{}, N)
	t.Logf("[derive] deriving %d offchain addresses from alice's wallet...", N)
	insertStart := time.Now()
	deriveStep := N / 10
	if deriveStep < 100 {
		deriveStep = 100
	}
	if deriveStep > 5000 {
		deriveStep = 5000
	}
	for i := 0; i < N; i++ {
		addr, err := alice.NewOffchainAddress(ctx)
		require.NoErrorf(t, err, "NewOffchainAddress failed at i=%d", i)
		if _, ok := addrSet[addr]; ok {
			t.Fatalf("NewOffchainAddress returned duplicate address at i=%d: %s", i, addr)
		}
		addrs[i] = addr
		addrSet[addr] = struct{}{}

		if (i+1)%deriveStep == 0 && i+1 < N {
			elapsed := time.Since(insertStart)
			rate := float64(i+1) / elapsed.Seconds()
			t.Logf(
				"[derive] progress %d/%d (%d%%) elapsed=%v rate=%.1f/s",
				i+1, N, (i+1)*100/N,
				elapsed.Truncate(time.Second), rate,
			)
		}
	}
	deriveElapsed := time.Since(insertStart)
	t.Logf(
		"[derive] done in %v (%.1f addrs/sec); first=%s last=%s",
		deriveElapsed.Truncate(time.Millisecond),
		float64(N)/deriveElapsed.Seconds(),
		addrs[0], addrs[N-1],
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

	sendStart := time.Now()
	expectedTotal := fundAndSendSmoke(t, ctx, bob, addrs, smokeAmountSat)
	sendElapsed := time.Since(sendStart)
	t.Logf(
		"[send] done in %v (%.1f sends/sec); expectedTotal=%d sat",
		sendElapsed.Truncate(time.Second),
		float64(N)/sendElapsed.Seconds(),
		expectedTotal,
	)

	requireSmokeWalletState(t, ctx, alice, N, expectedTotal, "pre-stop")

	t.Log("[stop] alice stopping")
	alice.Stop()

	t.Logf("[restore warm] LoadWallet from %s...", aliceDatadir)
	restoreStart := time.Now()
	restoredAlice := loadSmokeClient(t, aliceDatadir,
		arksdk.WithGapLimit(smokeGapLimit),
		arksdk.WithoutAutoSettle(),
	)
	t.Logf("[restore warm] LoadWallet ok in %v", time.Since(restoreStart).Truncate(time.Millisecond))

	requireSmokeWalletState(t, ctx, restoredAlice, N, expectedTotal, "warm restore")
	requireSmokeFreshAddress(t, ctx, restoredAlice, addrSet, "warm restore")

	restoredAlice.Stop()

	t.Log("[restore seed] from mnemonic into fresh datadir...")
	seedRestoreStart := time.Now()
	seedRestoredAlice, seedDatadir := setupSmokeClient(
		t, seed, arksdk.WithGapLimit(smokeGapLimit), arksdk.WithoutAutoSettle(),
	)
	t.Logf(
		"[restore seed] new datadir=%s; LoadWallet ok in %v",
		seedDatadir, time.Since(seedRestoreStart).Truncate(time.Second),
	)

	requireSmokeWalletState(t, ctx, seedRestoredAlice, N, expectedTotal, "seed restore")
	requireSmokeFreshAddress(t, ctx, seedRestoredAlice, addrSet, "seed restore")
}

func parseSmokeTier(t *testing.T) int {
	t.Helper()

	tier := strings.ToLower(strings.TrimSpace(os.Getenv("SMOKE_TIER")))
	if tier == "" {
		return 1000
	}

	multiplier := 1
	digits := tier
	switch {
	case strings.HasSuffix(tier, "m"):
		multiplier = 1_000_000
		digits = strings.TrimSuffix(tier, "m")
	case strings.HasSuffix(tier, "k"):
		multiplier = 1_000
		digits = strings.TrimSuffix(tier, "k")
	}

	n, err := strconv.Atoi(digits)
	if err != nil || n <= 0 {
		t.Fatalf("invalid SMOKE_TIER: %q (expected 1-999, Nk, or Nm)", tier)
		return 0
	}
	if multiplier == 1 && n > 999 {
		t.Fatalf("invalid SMOKE_TIER: %q (bare numbers must be 1-999; use Nk or Nm)", tier)
		return 0
	}
	return n * multiplier
}

func setupSmokeClient(
	t *testing.T, seed string, opts ...arksdk.WalletOption,
) (arksdk.Wallet, string) {
	t.Helper()

	dir, err := os.MkdirTemp("", "smoke-wallet-*")
	require.NoError(t, err)
	datadir := dir
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("[fail] preserving smoke wallet datadir=%s", dir)
			return
		}
		_ = os.RemoveAll(dir)
	})

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

func fundAndSendSmoke(
	t *testing.T, ctx context.Context, sender arksdk.Wallet, addrs []string, sat uint64,
) uint64 {
	t.Helper()

	total := uint64(len(addrs)) * sat

	t.Logf("[fund] funding bob with %d sat", total)

	note := generateNote(t, total)
	txid, err := sender.RedeemNotes(ctx, []string{note})
	require.NoError(t, err, "RedeemNotes failed")
	require.NotEmpty(t, txid, "RedeemNotes returned empty txid")
	t.Logf("[fund] txid = %s", txid)

	time.Sleep(time.Second)

	loopStart := time.Now()
	step := len(addrs) / 10
	if step < 100 {
		step = 100
	}
	if step > 5000 {
		step = 5000
	}

	t.Logf(
		"[send] sending %d sat from bob to alice's %d addresses, 1 tx at a time...",
		sat, len(addrs),
	)
	totUnspent := total
	for i, addr := range addrs {
		// Check bob's balance, if funds are close to expiry or recoverable a refresh is required
		bobBalance, err := sender.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)

		recoverableBalance := bobBalance.OffchainBalance.Recoverable
		var nextExpiry time.Time
		if d := bobBalance.OffchainBalance.Details; len(d) > 0 {
			expiry, err := time.Parse(time.RFC3339, d[0].ExpiryTime)
			require.NoError(t, err)
			nextExpiry = expiry
		}
		if recoverableBalance > 0 || time.Until(nextExpiry) < 20*time.Second {
			txid, err := sender.Settle(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, txid)
			t.Logf("[send] refreshed bob's funds txid = %s", txid)
			generateBlocks(t, 1)
		}

		wg := &sync.WaitGroup{}
		var notifyErr error
		wg.Go(func() {
			_, notifyErr = sender.NotifyIncomingFunds(ctx, addr)
		})
		receivers := []clienttypes.Receiver{{To: addr, Amount: sat}}
		_, err = sender.SendOffChain(ctx, receivers)
		require.NoErrorf(t, err, "SendOffChain failed at i=%d addr=%s", i, addr)
		wg.Wait()
		require.NoError(t, notifyErr)

		if (i+1)%step == 0 && i+1 < len(addrs) {
			elapsed := time.Since(loopStart)
			rate := float64(i+1) / elapsed.Seconds()
			t.Logf(
				"[send] progress %d/%d (%d%%) elapsed=%v rate=%.1f/s",
				i+1, len(addrs), (i+1)*100/len(addrs),
				elapsed.Truncate(time.Second), rate,
			)
		}
		totUnspent -= sat
	}

	return total
}

func requireSmokeWalletState(
	t *testing.T, ctx context.Context, w arksdk.Wallet, N int, expectedTotal uint64, label string,
) {
	t.Helper()

	verifyStart := time.Now()

	balance, err := w.Balance(ctx)
	require.NoError(t, err)
	require.EqualValuesf(
		t, expectedTotal, balance.OffchainBalance.Total,
		"%s wallet balance integrity: expected %d sat, got %d",
		label, expectedTotal, balance.OffchainBalance.Total,
	)
	t.Logf("[verify %s] ✓ %d VTXOs / %d sat in %v",
		label, N, expectedTotal, time.Since(verifyStart).Truncate(time.Second),
	)
}

func requireSmokeFreshAddress(
	t *testing.T, ctx context.Context, w arksdk.Wallet, used map[string]struct{}, label string,
) {
	t.Helper()

	nextAddr, err := w.NewOffchainAddress(ctx)
	require.NoError(t, err)
	if _, ok := used[nextAddr]; ok {
		t.Fatalf("%s next address reused a pre-derived address: %s", label, nextAddr)
	}
	t.Logf("[verify %s] ✓ fresh address: %s", label, nextAddr)
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
