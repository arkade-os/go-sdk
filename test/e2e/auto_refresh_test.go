package e2e_test

import (
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

// regtest is configured with a vtxo lifetime of ~20s (20 blocks at 1s blocktime),
// so auto-settle should fire ~18s after the vtxo is created (10% margin before expiry).
// All time bounds in this file derive from that.
const (
	// Generous bound for the refresh event so a slow CI run / scheduler
	// jitter doesn't flake the test. The 90% scheduling target is at ~18s,
	// so 40s is double the worst case.
	autoSettleRefreshTimeout = 40 * time.Second
	// For the disabled-feature case we wait long enough that the scheduled
	// time would have come and gone if the feature were on.
	autoSettleDisabledWait = 30 * time.Second
)

func TestAutoRefresh(t *testing.T) {
	// to test the auto-settle feature, we first shorten the vtxo tree expiry from 180 blocks
	// (3 mins with a 1 sec blocktime) to 20 blocks (20s) to wait a maximum reasonable time.
	setVtxoTreeExpiry(t, 20)
	t.Cleanup(func() { setVtxoTreeExpiry(t, 180) })

	time.Sleep(time.Second)

	// This test pins the common case of the auto-refresh wiring end-to-end: a wallet built with
	// the default scheduler must refresh its vtxos before they expire, without any user action.
	ctx := t.Context()
	alice := setupClient(t, "")

	initial := faucetOffchain(t, alice, 0.0001)
	require.NotEmpty(t, initial.Txid)
	require.False(
		t, initial.ExpiresAt.IsZero(),
		"initial vtxo must have a non-zero ExpiresAt for the test to be meaningful",
	)

	// Subscribe AFTER the faucet so we don't pick up the initial VtxosAdded
	// event — anything we receive from here on is the result of auto-settle.
	vtxoCh := alice.GetVtxoEventChannel(ctx)

	select {
	case event := <-vtxoCh:
		require.Equal(
			t, types.VtxosAdded, event.Type,
			"expected VtxosAdded from auto-settle, got %s", event.Type,
		)
		require.NotEmpty(t, event.Vtxos, "auto-settle event carried no vtxos")
		// Every refreshed vtxo must expire strictly later than the original
		// — that's the whole point of the renewal.
		for _, v := range event.Vtxos {
			require.True(
				t, v.ExpiresAt.After(initial.ExpiresAt),
				"refreshed vtxo %s expires at %s; expected later than initial %s",
				v.Outpoint,
				v.ExpiresAt.Format(time.RFC3339),
				initial.ExpiresAt.Format(time.RFC3339),
			)
		}
	case <-time.After(autoSettleRefreshTimeout):
		t.Fatalf(
			"timed out after %s waiting for auto-settle to refresh vtxos "+
				"(initial expired at %s)",
			autoSettleRefreshTimeout,
			initial.ExpiresAt.Format(time.RFC3339),
		)
	}
}
