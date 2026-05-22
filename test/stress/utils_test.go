//go:build stress

package stress_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

const (
	password  = "secret"
	serverUrl = "127.0.0.1:7070"
	adminUrl  = "http://127.0.0.1:7071"
	amountSat = uint64(10_000)

	// stressGapLimit stays moderate because this scenario funds continuous HD
	// indexes. Seed restore scans until this many consecutive unused addresses
	// after the last funded index.
	stressGapLimit = uint32(128)

	// sendBatchSize caps receivers per SendOffChain call. arkd rejects any
	// Ark TX whose weight exceeds MAX_TX_WEIGHT (default 0.01 * 4_000_000 =
	// 40_000 weight units). Keeping this at 128 also preserves the production
	// round participant pace instead of relying on stress-only arkd settings.
	sendBatchSize = 128

	// confirmEveryBatches keeps regtest from hitting Bitcoin Core's
	// too-long-mempool-chain policy while preserving the 128-payment pace.
	confirmEveryBatches = 16

	vtxoPageLimit = 1000
)

// parseTier reads the STRESS_TIER environment variable and returns the
// target address count N.
//
// Mapping:
//
//	""    or "1k"  -> 1000   (default)
//	"10k"          -> 10000
//	"50k"          -> 50000
//
// Any other value triggers t.Fatalf so the test fails fast in CI.
func parseTier(t *testing.T) int {
	t.Helper()
	tier := strings.ToLower(strings.TrimSpace(os.Getenv("STRESS_TIER")))
	switch tier {
	case "", "1k":
		return 1000
	case "10k":
		return 10000
	case "50k":
		return 50000
	default:
		t.Fatalf("unknown STRESS_TIER: %q (allowed: 1k, 10k, 50k)", tier)
		return 0
	}
}

// tierTimeout returns the tier-appropriate inner require.Eventually timeout.
// The outer `go test -timeout` flag in the Makefile is a separate safety net.
func tierTimeout(N int) time.Duration {
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

// setupStressClient creates a fresh wallet rooted at datadir, or a new temp
// dir when datadir is empty, and initializes/unlocks it with seed.
func setupStressClient(
	t *testing.T, datadir string, seed string, opts ...sdk.WalletOption,
) (sdk.Wallet, string) {
	t.Helper()
	if datadir == "" {
		dir, err := os.MkdirTemp("", "stress-wallet-*")
		require.NoError(t, err)
		datadir = dir
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("preserving failed stress wallet datadir=%s", dir)
				return
			}
			_ = os.RemoveAll(dir)
		})
	}

	wallet, err := sdk.NewWallet(datadir, opts...)
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

// loadStressClient re-opens an existing wallet datadir. This covers the warm
// reload path that reuses the existing Contract Manager SQLite store.
func loadStressClient(
	t *testing.T, datadir string, opts ...sdk.WalletOption,
) sdk.Wallet {
	t.Helper()

	wallet, err := sdk.LoadWallet(datadir, opts...)
	require.NoError(t, err)

	err = wallet.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-wallet.IsSynced(t.Context())
	require.NoError(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(wallet.Stop)

	return wallet
}

// generateNote mints one note worth amount satoshis through arkd's admin API.
func generateNote(t *testing.T, amount uint64) string {
	t.Helper()

	body := fmt.Sprintf(`{"amount": "%d", "quantity": 1}`, amount)
	req, err := http.NewRequest(
		"POST", adminUrl+"/v1/admin/note", bytes.NewReader([]byte(body)),
	)
	require.NoError(t, err, "build note request")
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "post note request")
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read note response")
	require.Truef(
		t, resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices,
		"admin /v1/admin/note returned status %d: %s", resp.StatusCode, string(payload),
	)

	var noteResp struct {
		Notes []string `json:"notes"`
	}
	require.NoError(t, json.Unmarshal(payload, &noteResp), "decode note response")
	require.Len(t, noteResp.Notes, 1, "admin /v1/admin/note returned wrong note count")

	return noteResp.Notes[0]
}

// fundSenderExact mints and redeems one note whose amount exactly matches the
// next send batch. Keeping only one spendable input in Bob's wallet avoids
// SendOffChain selecting thousands of inputs and hitting MAX_TX_WEIGHT.
func fundSenderExact(
	t *testing.T,
	ctx context.Context,
	sender sdk.Wallet,
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

	requireOffchainBalance(t, ctx, sender, amount, 30*time.Second,
		"sender did not reach exact funding balance for batch offset=%d size=%d",
		offset, batchSize,
	)
}

// fundAndSendBatched sends sat to each address in addrs, batched in sub-groups
// of sendBatchSize. Before each send, Bob receives one exact VTXO matching that
// batch total so SendOffChain has a small input set and no change output.
func fundAndSendBatched(
	t *testing.T,
	ctx context.Context,
	sender sdk.Wallet,
	addrs []string,
	sat uint64,
) uint64 {
	t.Helper()

	t.Log("mining 1 block before stress sends to clear any previous run's mempool chain")
	generateBlocks(t, 1)
	defer func() {
		if _, err := runCommand("nigiri", "rpc", "--generate", "1"); err != nil {
			t.Logf("failed to mine cleanup block after stress sends: %v", err)
		}
	}()

	for offset := 0; offset < len(addrs); offset += sendBatchSize {
		end := offset + sendBatchSize
		if end > len(addrs) {
			end = len(addrs)
		}
		batchNum := offset/sendBatchSize + 1
		batch := addrs[offset:end]
		batchAmount := uint64(len(batch)) * sat

		fundSenderExact(t, ctx, sender, batchAmount, offset, len(batch))

		receivers := make([]clienttypes.Receiver, len(batch))
		for i, addr := range batch {
			receivers[i] = clienttypes.Receiver{To: addr, Amount: sat}
		}

		_, err := sender.SendOffChain(ctx, receivers)
		require.NoErrorf(
			t, err,
			"SendOffChain failed for batch offset=%d size=%d", offset, len(batch),
		)

		requireOffchainBalance(t, ctx, sender, 0, 30*time.Second,
			"sender was not drained after batch offset=%d size=%d",
			offset, len(batch),
		)

		if batchNum%confirmEveryBatches == 0 && end < len(addrs) {
			generateBlocks(t, 1)
		}
	}

	return uint64(len(addrs)) * sat
}

func requireOffchainBalance(
	t *testing.T,
	ctx context.Context,
	wallet sdk.Wallet,
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

func listAllVtxos(
	ctx context.Context,
	wallet sdk.Wallet,
	opts ...sdk.ListVtxosOption,
) ([]clienttypes.Vtxo, error) {
	var (
		all    []clienttypes.Vtxo
		cursor string
	)
	for {
		pageOpts := append([]sdk.ListVtxosOption{}, opts...)
		pageOpts = append(pageOpts, sdk.WithLimit(vtxoPageLimit), sdk.WithCursor(cursor))

		vtxos, nextCursor, err := wallet.ListVtxos(ctx, pageOpts...)
		if err != nil {
			return nil, err
		}
		all = append(all, vtxos...)
		if nextCursor == "" {
			return all, nil
		}
		cursor = nextCursor
	}
}

// generateBlocks mines n regtest blocks through nigiri.
func generateBlocks(t *testing.T, n int) {
	t.Helper()

	_, err := runCommand("nigiri", "rpc", "--generate", fmt.Sprintf("%d", n))
	require.NoError(t, err)
}

func runCommand(name string, arg ...string) (string, error) {
	output, err := exec.Command(name, arg...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return strings.TrimSpace(string(output)), nil
}

// sumVtxoAmounts sums Amount across all VTXOs. Re-declared here because the
// helper in test/e2e cannot be imported across packages.
func sumVtxoAmounts(vtxos []clienttypes.Vtxo) uint64 {
	var total uint64
	for _, vtxo := range vtxos {
		total += vtxo.Amount
	}
	return total
}
