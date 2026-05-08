package e2e_test

import (
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"

	arksdk "github.com/arkade-os/go-sdk"
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

func TestAutoSettle(t *testing.T) {
	// This test pins the common case of the auto-settle wiring end-to-end: a wallet built with
	// the default scheduler must refresh its vtxos before they expire, without any user action.
	t.Run("enabled", func(t *testing.T) {
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
	})

	// This test pins the WithoutAutoSettle() opt-out: a wallet built with the feature
	// disabled must NOT refresh its vtxos on its own, even past the natural settlement window.
	t.Run("disabled", func(*testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "", arksdk.WithoutAutoSettle())

		initial := faucetOffchain(t, alice, 0.0001)
		require.NotEmpty(t, initial.Txid)

		vtxoCh := alice.GetVtxoEventChannel(ctx)

		// If any VtxosAdded event arrives while auto-settle is supposedly off,
		// the opt-out is broken. Wait long enough that ~the entire vtxo
		// lifetime has elapsed — if a settlement were going to happen, it
		// would have by now.
		select {
		case event := <-vtxoCh:
			if event.Type == types.VtxosAdded {
				t.Fatalf(
					"WithoutAutoSettle was set but a VtxosAdded event fired: %d vtxos",
					len(event.Vtxos),
				)
			}
			// Other event types (sweep / spent) are fine — they're not the
			// auto-settle path under test.
		case <-time.After(autoSettleDisabledWait):
			// expected: no auto-settle, no event.
		}
	})
}
