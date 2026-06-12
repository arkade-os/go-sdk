package arksdk

import (
	"context"
	"fmt"
	"testing"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

// TestDetectRotationRetryOnScanFailure verifies the rotation digest
// is advanced ONLY after discovery (rescan + refresh) succeeds. A transient
// ScanContracts failure must leave lastSignerSetDigest at its old value so the
// next periodic tick re-detects the change and retries; reconcile failure must
// NOT block the advance (discovery already succeeded). The seam fields on the
// wallet let us drive rescanAndReconcile without mocking the whole client /
// contract-manager surface.
func TestDetectRotationRetryOnScanFailure(t *testing.T) {
	const oldDigest = "old"
	const newDigest = "new"

	// commit mirrors detectAndHandleRotation's gated assignment.
	commit := func(w *wallet) {
		if w.rescanAndReconcile(context.Background()) {
			w.lastSignerSetDigest = newDigest
		}
	}

	t.Run("scan failure: digest unchanged, retry on next tick", func(t *testing.T) {
		scanCalls := 0
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationScanFn: func(_ context.Context, _ uint32) error {
				scanCalls++
				return fmt.Errorf("transient rescan failure")
			},
			rotationRefreshFn:   func(_ context.Context) error { return nil },
			rotationReconcileFn: func(_ context.Context) error { return nil },
		}

		// First tick: scan fails → digest must stay old.
		commit(w)
		require.Equal(t, oldDigest, w.lastSignerSetDigest,
			"digest must not advance when ScanContracts fails")
		require.Equal(t, 1, scanCalls)

		// Second tick: still old digest, so the rotation is re-detected and the
		// rescan is retried (and now succeeds).
		w.rotationScanFn = func(_ context.Context, _ uint32) error {
			scanCalls++
			return nil
		}
		commit(w)
		require.Equal(t, newDigest, w.lastSignerSetDigest,
			"digest must advance once rescan+refresh succeed on retry")
		require.Equal(t, 2, scanCalls, "rescan must be retried on the next tick")
	})

	t.Run("refresh failure: digest unchanged", func(t *testing.T) {
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationScanFn:      func(_ context.Context, _ uint32) error { return nil },
			rotationRefreshFn: func(_ context.Context) error {
				return fmt.Errorf("transient refresh failure")
			},
			rotationReconcileFn: func(_ context.Context) error { return nil },
		}
		commit(w)
		require.Equal(t, oldDigest, w.lastSignerSetDigest,
			"digest must not advance when refreshDb fails")
	})

	t.Run("reconcile failure: digest still advances", func(t *testing.T) {
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationScanFn:      func(_ context.Context, _ uint32) error { return nil },
			rotationRefreshFn:   func(_ context.Context) error { return nil },
			rotationReconcileFn: func(_ context.Context) error {
				return fmt.Errorf("migration failed")
			},
		}
		commit(w)
		require.Equal(t, newDigest, w.lastSignerSetDigest,
			"reconcile failure must not block the digest advance (discovery succeeded)")
	})

	t.Run("all succeed: digest advances", func(t *testing.T) {
		w := &wallet{
			lastSignerSetDigest: oldDigest,
			rotationScanFn:      func(_ context.Context, _ uint32) error { return nil },
			rotationRefreshFn:   func(_ context.Context) error { return nil },
			rotationReconcileFn: func(_ context.Context) error { return nil },
		}
		commit(w)
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
