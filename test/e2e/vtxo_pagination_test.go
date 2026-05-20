package e2e_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	sdktypes "github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const vtxoPaginationSleep = 50 * time.Millisecond

type vtxoPaginationFixture struct {
	alice   arksdk.Wallet
	bob     arksdk.Wallet
	assetID string
}

func TestE2EVtxoPagination(t *testing.T) {
	f := setupVtxoPaginationFixture(t)

	t.Run("paginated walk equals single-call result", func(t *testing.T) {
		reference, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Empty(t, cursor, "limit 1000 should read all spendable VTXOs")
		require.Len(t, reference, 10, "expected seeded spendable VTXO count")

		limit := 3
		pages, walked := walkVtxoPages(
			t, f.alice, arksdk.WithSpendableOnly(), arksdk.WithLimit(limit),
		)

		requireOutpointSetEqual(t, reference, walked)
		require.Equal(t, 4, pages)
		require.Equal(t, 10, len(walked))
		requireNoDuplicateOutpoints(t, walked)
		require.GreaterOrEqual(t, pages*limit, len(reference), "pages*limit must cover reference count")
		require.LessOrEqual(t, pages*limit, len(reference)+limit, "only the final page may be partial")
	})

	t.Run("end-of-pagination returns nil cursor", func(t *testing.T) {
		var cursor string
		var finalCursor string
		for {
			_, next, err := f.alice.ListVtxos(
				t.Context(),
				arksdk.WithSpendableOnly(),
				arksdk.WithLimit(3),
				arksdk.WithCursor(cursor),
			)
			require.NoError(t, err)
			finalCursor = next
			if next == "" {
				break
			}
			cursor = next
		}
		require.Empty(t, finalCursor, "empty cursor must signal no more pages")
	})

	t.Run("limit greater than dataset returns nil cursor on first call", func(t *testing.T) {
		vtxos, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Len(t, vtxos, 10, "expected all seeded spendable VTXOs")
		require.Empty(t, cursor, "cursor must be empty when the first page exhausts the dataset")
	})

	t.Run("limit changes between pages", func(t *testing.T) {
		reference, _, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)

		page1, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(2),
		)
		require.NoError(t, err)
		require.Len(t, page1, 2, "first page should use its requested limit")
		require.NotEmpty(t, cursor, "first page should return a cursor")

		page2, _, err := f.alice.ListVtxos(
			t.Context(),
			arksdk.WithSpendableOnly(),
			arksdk.WithLimit(7),
			arksdk.WithCursor(cursor),
		)
		require.NoError(t, err)
		require.LessOrEqual(t, len(page2), 7, "second page must respect changed limit")
		requireNoOutpointOverlap(t, page1, page2)
		require.Equal(t, reference[2:2+len(page2)], page2, "page 2 must continue from page 1 cursor")
	})

	t.Run("WithSpendableOnly returns only spent=false AND unrolled=false", func(t *testing.T) {
		vtxos, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Empty(t, cursor)
		require.Len(t, vtxos, 10, "expected 10 spendable VTXOs")
		for _, vtxo := range vtxos {
			require.False(t, vtxo.Spent, "outpoint %s must not be spent", outpointKey(vtxo))
			require.False(t, vtxo.Unrolled, "outpoint %s must not be unrolled", outpointKey(vtxo))
		}
	})

	t.Run("WithSpentOnly returns only spent OR unrolled", func(t *testing.T) {
		vtxos, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpentOnly(), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Empty(t, cursor)
		require.Len(t, vtxos, 2, "expected 2 spent VTXOs")
		for _, vtxo := range vtxos {
			require.True(t, vtxo.Spent || vtxo.Unrolled, "outpoint %s must be spent or unrolled", outpointKey(vtxo))
		}
	})

	t.Run("default (no status filter) returns all 12", func(t *testing.T) {
		vtxos, cursor, err := f.alice.ListVtxos(t.Context(), arksdk.WithLimit(1000))
		require.NoError(t, err)
		require.Empty(t, cursor)
		require.Len(t, vtxos, 12, "expected all seeded VTXOs")
	})

	t.Run("WithAssetID filters to VTXOs holding the asset, but hydrates all their assets", func(t *testing.T) {
		vtxos, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithAssetID(f.assetID), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Empty(t, cursor)
		require.Len(t, vtxos, 2, "expected exactly the two VTXOs holding asset %s", f.assetID)
		for _, vtxo := range vtxos {
			require.Positive(t, vtxo.Amount, "outpoint %s must carry BTC amount", outpointKey(vtxo))
			requireAssetAmount(t, vtxo, f.assetID, 1)
			require.Len(t, vtxo.Assets, 1, "outpoint %s should hydrate all issued assets", outpointKey(vtxo))
		}
	})

	t.Run("WithAssetID for non-existent asset returns empty", func(t *testing.T) {
		vtxos, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithAssetID("nonexistent-asset"), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Empty(t, cursor)
		require.Empty(t, vtxos)
	})

	t.Run("page boundary does not cut a multi-asset VTXO mid-way", func(t *testing.T) {
		var cursor string
		found := 0
		for pageIndex := 1; ; pageIndex++ {
			page, next, err := f.alice.ListVtxos(
				t.Context(),
				arksdk.WithSpendableOnly(),
				arksdk.WithLimit(2),
				arksdk.WithCursor(cursor),
			)
			require.NoError(t, err)
			require.LessOrEqual(t, len(page), 2, "page %d must contain VTXOs, not asset rows", pageIndex)
			for _, vtxo := range page {
				if hasAsset(vtxo, f.assetID) {
					found++
					require.Positive(t, vtxo.Amount, "multi-asset outpoint %s must carry BTC amount", outpointKey(vtxo))
					requireAssetAmount(t, vtxo, f.assetID, 1)
					require.Len(t, vtxo.Assets, 1, "multi-asset outpoint %s assets were truncated", outpointKey(vtxo))
				}
			}
			if next == "" {
				break
			}
			cursor = next
		}
		require.Equal(t, 2, found, "expected both multi-asset VTXOs to be seen complete")
	})

	t.Run("WithSpendableOnly + WithAssetID + pagination", func(t *testing.T) {
		_, vtxos := walkVtxoPages(
			t,
			f.alice,
			arksdk.WithSpendableOnly(),
			arksdk.WithAssetID(f.assetID),
			arksdk.WithLimit(1),
		)
		require.Len(t, vtxos, 2, "expected two asset VTXOs across two pages")
		for _, vtxo := range vtxos {
			require.False(t, vtxo.Spent, "outpoint %s must be spendable", outpointKey(vtxo))
			require.False(t, vtxo.Unrolled, "outpoint %s must be spendable", outpointKey(vtxo))
			requireAssetAmount(t, vtxo, f.assetID, 1)
		}
	})

	t.Run("WithLimit(0) returns ErrInvalidLimit", func(t *testing.T) {
		requireListVtxosOptionError(t, f.alice, arksdk.ErrInvalidLimit, arksdk.WithLimit(0))
	})

	t.Run("WithLimit(1001) returns ErrInvalidLimit", func(t *testing.T) {
		requireListVtxosOptionError(t, f.alice, arksdk.ErrInvalidLimit, arksdk.WithLimit(1001))
	})

	t.Run("WithLimit(-1) returns ErrInvalidLimit", func(t *testing.T) {
		requireListVtxosOptionError(t, f.alice, arksdk.ErrInvalidLimit, arksdk.WithLimit(-1))
	})

	t.Run("WithSpendableOnly + WithSpentOnly returns ErrConflictingStatusOption", func(t *testing.T) {
		requireListVtxosOptionError(
			t, f.alice, arksdk.ErrConflictingStatusOption, arksdk.WithSpendableOnly(), arksdk.WithSpentOnly(),
		)
		requireListVtxosOptionError(
			t, f.alice, arksdk.ErrConflictingStatusOption, arksdk.WithSpentOnly(), arksdk.WithSpendableOnly(),
		)
	})

	t.Run("WithAssetID(empty) returns error", func(t *testing.T) {
		vtxos, cursor, err := f.alice.ListVtxos(t.Context(), arksdk.WithAssetID(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "asset id must not be empty")
		require.Nil(t, vtxos)
		require.Empty(t, cursor)
	})

	t.Run("WithCursor(malformed) returns ErrInvalidCursor", func(t *testing.T) {
		requireListVtxosOptionError(t, f.alice, arksdk.ErrInvalidCursor, arksdk.WithCursor("not-base64-!!"))
	})

	t.Run("WithCursor(valid base64, malformed JSON) returns ErrInvalidCursor", func(t *testing.T) {
		cursor := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		requireListVtxosOptionError(t, f.alice, arksdk.ErrInvalidCursor, arksdk.WithCursor(cursor))
	})

	t.Run("WithCursor across different filter sets returns ErrCursorFilterMismatch", func(t *testing.T) {
		_, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(2),
		)
		require.NoError(t, err)
		require.NotEmpty(t, cursor, "first page should return a reusable cursor")

		requireListVtxosOptionError(
			t,
			f.alice,
			arksdk.ErrCursorFilterMismatch,
			arksdk.WithSpentOnly(),
			arksdk.WithCursor(cursor),
		)
	})

	t.Run("cursor stable when new VTXOs arrive between pages", func(t *testing.T) {
		reference, _, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Len(t, reference, 10, "expected seeded spendable VTXO count before concurrent writes")

		page1, cursor, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(3),
		)
		require.NoError(t, err)
		require.Len(t, page1, 3, "expected first page size")
		require.NotEmpty(t, cursor, "first page should return cursor")

		waitAfterVtxoCreatedAt(page1[0])
		newVtxos := sendVtxos(t, f.bob, f.alice, 2, 2_000)

		page2, nextCursor, err := f.alice.ListVtxos(
			t.Context(),
			arksdk.WithSpendableOnly(),
			arksdk.WithLimit(3),
			arksdk.WithCursor(cursor),
		)
		require.NoError(t, err)
		require.NotEmpty(t, nextCursor, "second page should still have a cursor")
		require.Equal(t, reference[3:6], page2, "page 2 must continue from the cursor anchor")
		requireNoOutpointOverlap(t, page1, page2)
		for _, newVtxo := range newVtxos {
			require.NotContains(t, outpointSet(page2), outpointKey(newVtxo), "newer VTXO must not appear after cursor")
		}

		walked := append(slices.Clone(page1), page2...)
		cursor = nextCursor
		for cursor != "" {
			page, next, err := f.alice.ListVtxos(
				t.Context(),
				arksdk.WithSpendableOnly(),
				arksdk.WithLimit(3),
				arksdk.WithCursor(cursor),
			)
			require.NoError(t, err)
			walked = append(walked, page...)
			cursor = next
		}

		current, _, err := f.alice.ListVtxos(
			t.Context(), arksdk.WithSpendableOnly(), arksdk.WithLimit(1000),
		)
		require.NoError(t, err)
		require.Len(t, current, 12, "expected 10 original plus 2 new spendable VTXOs")
		walkedPlusNew := append(slices.Clone(walked), newVtxos...)
		requireOutpointSetEqual(t, current, walkedPlusNew)
	})
}

// setupVtxoPaginationFixture builds Alice's pagination dataset:
//   - 2 VTXOs are received first, then settled, leaving them spent.
//   - the settlement creates 1 spendable VTXO.
//   - 2 spendable VTXOs with assets are received next.
//   - 7 more spendable VTXOs are received last.
//
// Final Alice state: 12 VTXOs total, 10 spendable, 2 spent, with the
// asset VTXOs inside the spendable set. Sends are separated by short sleeps
// so second-resolution created_at ordering remains deterministic.
func setupVtxoPaginationFixture(t *testing.T) vtxoPaginationFixture {
	t.Helper()

	ctx := t.Context()
	alice := setupClient(t, "", arksdk.WithoutAutoSettle())
	bob := setupClient(t, "", arksdk.WithoutAutoSettle())

	faucetOffchain(t, bob, 0.02)

	sendVtxos(t, bob, alice, 2, 1_500)

	aliceVtxoCh := alice.GetVtxoEventChannel(ctx)
	_, err := alice.Settle(ctx)
	require.NoError(t, err)
	waitForVtxosAdded(t, aliceVtxoCh, "")

	_, assetIDs, err := bob.IssueAsset(ctx, 2, nil, nil)
	require.NoError(t, err)
	require.Len(t, assetIDs, 1)
	assetID := assetIDs[0].String()
	require.Eventually(t, func() bool {
		vtxos, _, err := bob.ListVtxos(ctx, arksdk.WithAssetID(assetID), arksdk.WithLimit(1000))
		return err == nil && len(vtxos) == 1 && hasAssetAmount(vtxos[0], assetID, 2)
	}, 10*time.Second, 100*time.Millisecond, "bob should index issued asset %s", assetID)

	sendVtxoWithAsset(t, bob, alice, assetID)
	// Wait for Bob's asset change before spending it in the second asset send.
	requireSpendableAssetVtxos(t, bob, assetID, 1, 1)
	sendVtxoWithAsset(t, bob, alice, assetID)
	sendVtxos(t, bob, alice, 7, 1_500)

	require.Eventually(t, func() bool {
		spendable, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly(), arksdk.WithLimit(1000))
		if err != nil || len(spendable) != 10 {
			return false
		}
		spent, _, err := alice.ListVtxos(ctx, arksdk.WithSpentOnly(), arksdk.WithLimit(1000))
		if err != nil || len(spent) != 2 {
			return false
		}
		all, _, err := alice.ListVtxos(ctx, arksdk.WithLimit(1000))
		return err == nil && len(all) == 12
	}, 10*time.Second, 100*time.Millisecond, "pagination fixture should have 10 spendable, 2 spent, 12 total VTXOs")

	return vtxoPaginationFixture{
		alice:   alice,
		bob:     bob,
		assetID: assetID,
	}
}

// sendVtxos sends count BTC-only VTXOs and waits for each receiver-side event.
func sendVtxos(
	t *testing.T, sender, receiver arksdk.Wallet, count int, amount uint64,
) []clientTypes.Vtxo {
	t.Helper()

	ctx := t.Context()
	addr, err := receiver.NewOffchainAddress(ctx)
	require.NoError(t, err)

	vtxoCh := receiver.GetVtxoEventChannel(ctx)
	vtxos := make([]clientTypes.Vtxo, 0, count)
	for i := range count {
		txid := sendOffchainEventually(t, sender, []clientTypes.Receiver{{
			To:     addr,
			Amount: amount + uint64(i),
		}})
		vtxo := waitForVtxosAdded(t, vtxoCh, txid)
		require.Positive(t, vtxo.Amount, "received VTXO %s must carry BTC amount", outpointKey(vtxo))
		vtxos = append(vtxos, vtxo)
		time.Sleep(vtxoPaginationSleep)
	}
	return vtxos
}

// sendVtxoWithAsset sends one BTC carrier VTXO plus one issued-asset unit.
func sendVtxoWithAsset(t *testing.T, sender, receiver arksdk.Wallet, assetID string) clientTypes.Vtxo {
	t.Helper()

	ctx := t.Context()
	addr, err := receiver.NewOffchainAddress(ctx)
	require.NoError(t, err)

	vtxoCh := receiver.GetVtxoEventChannel(ctx)
	txid := sendOffchainEventually(t, sender, []clientTypes.Receiver{{
		To:     addr,
		Amount: 1_500,
		Assets: []clientTypes.Asset{{
			AssetId: assetID,
			Amount:  1,
		}},
	}})
	vtxo := waitForVtxosAdded(t, vtxoCh, txid)
	require.Positive(t, vtxo.Amount, "received VTXO %s must carry BTC amount", outpointKey(vtxo))
	requireAssetAmount(t, vtxo, assetID, 1)
	time.Sleep(vtxoPaginationSleep)
	return vtxo
}

// sendOffchainEventually retries while arkd/indexer catches up with new inputs.
func sendOffchainEventually(
	t *testing.T, sender arksdk.Wallet, receivers []clientTypes.Receiver,
) string {
	t.Helper()

	var txid string
	var lastErr error
	require.Eventually(t, func() bool {
		var err error
		txid, err = sender.SendOffChain(t.Context(), receivers)
		if err != nil {
			lastErr = err
			return false
		}
		return true
	}, 10*time.Second, 250*time.Millisecond, "SendOffChain should succeed, last error: %v", lastErr)
	require.NotEmpty(t, txid)
	return txid
}

// waitForVtxosAdded waits for a receiver-side added event matching txid.
func waitForVtxosAdded(
	t *testing.T, ch <-chan sdktypes.VtxoEvent, txid string,
) clientTypes.Vtxo {
	t.Helper()

	timeout := time.After(10 * time.Second)
	for {
		select {
		case event := <-ch:
			if event.Type != sdktypes.VtxosAdded || len(event.Vtxos) == 0 {
				continue
			}
			for _, vtxo := range event.Vtxos {
				if txid == "" || vtxo.Txid == txid {
					return vtxo
				}
			}
		case <-timeout:
			require.FailNow(t, "timed out waiting for VtxosAdded", "txid=%s", txid)
		}
	}
}

// requireSpendableAssetVtxos waits until asset change is indexed as spendable.
func requireSpendableAssetVtxos(
	t *testing.T, wallet arksdk.Wallet, assetID string, count int, amount uint64,
) {
	t.Helper()

	// Asset sends create asset change; wait until it is indexed as spendable.
	require.Eventually(t, func() bool {
		vtxos, _, err := wallet.ListVtxos(
			t.Context(),
			arksdk.WithSpendableOnly(),
			arksdk.WithAssetID(assetID),
			arksdk.WithLimit(1000),
		)
		if err != nil || len(vtxos) != count {
			return false
		}
		for _, vtxo := range vtxos {
			if !hasAssetAmount(vtxo, assetID, amount) {
				return false
			}
		}
		return true
	}, 10*time.Second, 100*time.Millisecond, "wallet should have %d spendable VTXOs with asset %s amount %d", count, assetID, amount)
}

// waitAfterVtxoCreatedAt ensures later writes sort after the cursor anchor.
func waitAfterVtxoCreatedAt(vtxo clientTypes.Vtxo) {
	for time.Now().Unix() <= vtxo.CreatedAt.Unix() {
		time.Sleep(vtxoPaginationSleep)
	}
}

// walkVtxoPages follows cursors until the empty-cursor end signal.
func walkVtxoPages(
	t *testing.T, wallet arksdk.Wallet, opts ...arksdk.ListVtxosOption,
) (int, []clientTypes.Vtxo) {
	t.Helper()

	var cursor string
	var pages int
	var all []clientTypes.Vtxo
	for {
		pageOpts := append(slices.Clone(opts), arksdk.WithCursor(cursor))
		page, next, err := wallet.ListVtxos(t.Context(), pageOpts...)
		require.NoError(t, err)
		pages++
		all = append(all, page...)
		if next == "" {
			return pages, all
		}
		cursor = next
	}
}

// requireListVtxosOptionError verifies invalid options return no page data.
func requireListVtxosOptionError(
	t *testing.T, wallet arksdk.Wallet, target error, opts ...arksdk.ListVtxosOption,
) {
	t.Helper()

	vtxos, cursor, err := wallet.ListVtxos(t.Context(), opts...)
	require.Error(t, err)
	require.True(t, errors.Is(err, target), "expected %v, got %v", target, err)
	require.Nil(t, vtxos)
	require.Empty(t, cursor)
}

// requireOutpointSetEqual compares VTXO slices by outpoint identity.
func requireOutpointSetEqual(t *testing.T, expected, actual []clientTypes.Vtxo) {
	t.Helper()

	expectedSet := outpointSet(expected)
	actualSet := outpointSet(actual)
	require.Equal(
		t,
		expectedSet,
		actualSet,
		"outpoint set mismatch: expected %d VTXOs, got %d VTXOs",
		len(expected),
		len(actual),
	)
}

// requireNoDuplicateOutpoints catches repeated VTXOs across paginated pages.
func requireNoDuplicateOutpoints(t *testing.T, vtxos []clientTypes.Vtxo) {
	t.Helper()

	seen := make(map[string]struct{}, len(vtxos))
	for _, vtxo := range vtxos {
		key := outpointKey(vtxo)
		require.NotContains(t, seen, key, "duplicate outpoint %s", key)
		seen[key] = struct{}{}
	}
}

// requireNoOutpointOverlap verifies adjacent pages do not share VTXOs.
func requireNoOutpointOverlap(t *testing.T, a, b []clientTypes.Vtxo) {
	t.Helper()

	seen := outpointSet(a)
	for _, vtxo := range b {
		require.NotContains(t, seen, outpointKey(vtxo), "overlapping outpoint %s", outpointKey(vtxo))
	}
}

// requireAssetAmount checks the hydrated asset amount on a VTXO.
func requireAssetAmount(t *testing.T, vtxo clientTypes.Vtxo, assetID string, amount uint64) {
	t.Helper()

	require.True(
		t,
		hasAssetAmount(vtxo, assetID, amount),
		"outpoint %s expected asset %s amount %d in assets %+v",
		outpointKey(vtxo),
		assetID,
		amount,
		vtxo.Assets,
	)
}

// hasAsset reports whether the VTXO contains the requested asset.
func hasAsset(vtxo clientTypes.Vtxo, assetID string) bool {
	for _, asset := range vtxo.Assets {
		if asset.AssetId == assetID {
			return true
		}
	}
	return false
}

// hasAssetAmount reports whether the VTXO contains the requested asset amount.
func hasAssetAmount(vtxo clientTypes.Vtxo, assetID string, amount uint64) bool {
	for _, asset := range vtxo.Assets {
		if asset.AssetId == assetID && asset.Amount == amount {
			return true
		}
	}
	return false
}

// outpointSet converts VTXOs into a txid:vout keyed set.
func outpointSet(vtxos []clientTypes.Vtxo) map[string]struct{} {
	set := make(map[string]struct{}, len(vtxos))
	for _, vtxo := range vtxos {
		set[outpointKey(vtxo)] = struct{}{}
	}
	return set
}

// outpointKey returns the stable VTXO identity used in assertions.
func outpointKey(vtxo clientTypes.Vtxo) string {
	return fmt.Sprintf("%s:%d", vtxo.Txid, vtxo.VOut)
}
