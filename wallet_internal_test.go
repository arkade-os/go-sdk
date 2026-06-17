package arksdk

import (
	"context"
	"fmt"
	"testing"
	"time"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestRefreshTimeRangeUsesMilliseconds(t *testing.T) {
	updateTime := time.Unix(1_781_692_380, 123_000_000)
	lastUpdate := time.Unix(1_781_692_370, 456_000_000)

	before, after, ok := refreshTimeRange(updateTime, lastUpdate)

	require.True(t, ok)
	require.Equal(t, int64(1_781_692_380_123), before)
	require.Equal(t, int64(1_781_692_370_456), after)
}

func TestRefreshTimeRangeSkipsInvalidRanges(t *testing.T) {
	now := time.Unix(1_781_692_380, 0)

	_, _, ok := refreshTimeRange(now, time.Time{})
	require.False(t, ok, "first refresh should be a full scan without time bounds")

	_, _, ok = refreshTimeRange(now, now)
	require.False(t, ok, "equal millisecond bounds are rejected by indexer.WithTimeRange")
}

// TestDetectRotationDigestAdvance verifies the rotation digest is advanced only
// after reconciliation succeeds. refreshDb is owned by the caller
// (periodicRefreshDb or Unlock), so this test focuses on the shared detector:
// digest fetch failure or reconcile failure must leave lastSignerSetDigest at
// its old value so the next periodic tick re-detects the change and retries.
func TestDetectRotationDigestAdvance(t *testing.T) {
	const oldDigest = "old"
	const newDigest = "new"

	t.Run("digest failure: digest unchanged", func(t *testing.T) {
		digestCalls := 0
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationDigestFn: func(_ context.Context) (string, error) {
				digestCalls++
				return "", fmt.Errorf("transient info failure")
			},
			rotationReconcileFn: func(_ context.Context) error {
				t.Fatal("reconcile must not run when signer digest cannot be read")
				return nil
			},
		}

		w.detectAndHandleRotation(context.Background())
		require.Equal(t, oldDigest, w.lastSignerSetDigest,
			"digest must not advance when signer info cannot be read")
		require.Equal(t, 1, digestCalls)
	})

	t.Run("reconcile failure: digest unchanged, retry on next tick", func(t *testing.T) {
		reconcileCalls := 0
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationDigestFn: func(_ context.Context) (string, error) {
				return newDigest, nil
			},
			rotationReconcileFn: func(_ context.Context) error {
				reconcileCalls++
				return fmt.Errorf("migration failed")
			},
		}
		w.detectAndHandleRotation(context.Background())
		require.Equal(t, oldDigest, w.lastSignerSetDigest,
			"digest must not advance when reconciliation fails")
		require.Equal(t, 1, reconcileCalls)

		w.rotationReconcileFn = func(_ context.Context) error {
			reconcileCalls++
			return nil
		}
		w.detectAndHandleRotation(context.Background())
		require.Equal(t, newDigest, w.lastSignerSetDigest,
			"digest must advance once reconciliation succeeds on retry")
		require.Equal(t, 2, reconcileCalls, "reconcile must be retried on the next tick")
	})

	t.Run("same digest: no reconcile", func(t *testing.T) {
		reconcileCalls := 0
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationDigestFn: func(_ context.Context) (string, error) {
				return oldDigest, nil
			},
			rotationReconcileFn: func(_ context.Context) error {
				reconcileCalls++
				return nil
			},
		}
		w.detectAndHandleRotation(context.Background())
		require.Equal(t, oldDigest, w.lastSignerSetDigest)
		require.Equal(t, 0, reconcileCalls)
	})

	t.Run("all succeed: digest advances", func(t *testing.T) {
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationDigestFn: func(_ context.Context) (string, error) {
				return newDigest, nil
			},
			rotationReconcileFn: func(_ context.Context) error { return nil },
		}
		w.detectAndHandleRotation(context.Background())
		require.Equal(t, newDigest, w.lastSignerSetDigest)
	})
}

func TestGroupSpentVtxosByTx(t *testing.T) {
	t.Parallel()

	t.Run("groups offchain and settled vtxos and ignores unknown outpoints", func(t *testing.T) {
		t.Parallel()

		outpoint1 := clienttypes.Outpoint{Txid: "tx1", VOut: 0}
		outpoint2 := clienttypes.Outpoint{Txid: "tx2", VOut: 1}
		outpoint3 := clienttypes.Outpoint{Txid: "tx3", VOut: 2}
		missingOutpoint := clienttypes.Outpoint{Txid: "missing", VOut: 3}

		oldSpendable := map[clienttypes.Outpoint]clienttypes.Vtxo{
			outpoint1: {Outpoint: outpoint1},
			outpoint2: {Outpoint: outpoint2},
			outpoint3: {Outpoint: outpoint3},
		}

		spentVtxos := []clienttypes.Vtxo{
			{
				Outpoint: outpoint1,
				ArkTxid:  "arktx-checkpoint-1",
				SpentBy:  "checkpoint-txid-1",
			},
			{
				Outpoint: outpoint2,
				ArkTxid:  "arktx-checkpoint-1",
				SpentBy:  "checkpoint-txid-2",
			},
			{
				Outpoint:  outpoint3,
				SettledBy: "commitment-txid-1",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  missingOutpoint,
				ArkTxid:   "arktx-ignored",
				SettledBy: "commitment-txid-ignored",
				SpentBy:   "forfeit",
			},
		}

		vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendable)

		require.Equal(t, map[string]map[clienttypes.Outpoint]string{
			"arktx-checkpoint-1": {
				outpoint1: "checkpoint-txid-1",
				outpoint2: "checkpoint-txid-2",
			},
		}, vtxosToSpend)

		require.Equal(t, map[string]map[clienttypes.Outpoint]string{
			"commitment-txid-1": {
				outpoint3: "forfeit",
			},
		}, vtxosToSettle)
	})

	t.Run("creates multiple groups and prioritizes settled entries", func(t *testing.T) {
		t.Parallel()

		outpoint1 := clienttypes.Outpoint{Txid: "tx10", VOut: 0}
		outpoint2 := clienttypes.Outpoint{Txid: "tx11", VOut: 1}
		outpoint3 := clienttypes.Outpoint{Txid: "tx12", VOut: 2}
		outpoint4 := clienttypes.Outpoint{Txid: "tx13", VOut: 3}
		missingOutpoint := clienttypes.Outpoint{Txid: "tx14", VOut: 1}

		oldSpendable := map[clienttypes.Outpoint]clienttypes.Vtxo{
			outpoint1: {Outpoint: outpoint1},
			outpoint2: {Outpoint: outpoint2},
			outpoint3: {Outpoint: outpoint3},
			outpoint4: {Outpoint: outpoint4},
		}

		spentVtxos := []clienttypes.Vtxo{
			{
				Outpoint: outpoint1,
				ArkTxid:  "arktx-checkpoint-a",
				SpentBy:  "checkpoint-a-1",
			},
			{
				Outpoint: outpoint2,
				ArkTxid:  "arktx-checkpoint-b",
				SpentBy:  "checkpoint-b-1",
			},
			{
				Outpoint:  outpoint3,
				SettledBy: "commitment-a",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  outpoint4,
				ArkTxid:   "arktx-should-be-ignored",
				SettledBy: "commitment-b",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  missingOutpoint,
				ArkTxid:   "arktx",
				SettledBy: "commitment",
				SpentBy:   "forfeit",
			},
		}

		vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendable)

		require.Equal(t, map[string]map[clienttypes.Outpoint]string{
			"arktx-checkpoint-a": {
				outpoint1: "checkpoint-a-1",
			},
			"arktx-checkpoint-b": {
				outpoint2: "checkpoint-b-1",
			},
		}, vtxosToSpend)

		require.Equal(t, map[string]map[clienttypes.Outpoint]string{
			"commitment-a": {
				outpoint3: "forfeit",
			},
			"commitment-b": {
				outpoint4: "forfeit",
			},
		}, vtxosToSettle)
	})
}
