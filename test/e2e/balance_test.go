package e2e_test

import (
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestBalance(t *testing.T) {
	t.Run("onchain (confirmed only)", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		// Before any funding, all balances should be zero.
		balance, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Zero(t, int(balance.OffchainBalance.Total))
		require.Zero(t, int(balance.Total))
		require.Zero(t, int(balance.OffchainBalance.Available))
		require.Zero(t, int(balance.OffchainBalance.Preconfirmed))
		require.Zero(t, int(balance.OffchainBalance.Recoverable))
		require.Zero(t, int(balance.OffchainBalance.Settled))
		require.Zero(t, int(balance.OnchainBalance.Confirmed))
		require.Zero(t, int(balance.OnchainBalance.Unconfirmed))
		require.Zero(t, int(balance.OnchainBalance.Total))

		// Fund Alice's boarding address and wait for the UTXO event.
		boardingAddr, err := alice.NewBoardingAddress(ctx)
		require.NoError(t, err)

		utxoCh := alice.GetUtxoEventChannel(ctx)

		faucetOnchain(t, boardingAddr, 0.00021)

		utxoEvent := waitForUtxoEvent(t, utxoCh, 30*time.Second, func(event types.UtxoEvent) bool {
			return event.Type == types.UtxosAdded && len(event.Utxos) == 1
		})
		require.Equal(t, types.UtxosAdded, utxoEvent.Type)
		require.Len(t, utxoEvent.Utxos, 1)
		require.Equal(t, 21000, int(utxoEvent.Utxos[0].Amount))

		// Offchain balance should still be zero (funds are on-chain only).
		balance, err = alice.Balance(ctx)
		require.NoError(t, err)
		require.Zero(t, int(balance.OffchainBalance.Total))
		require.Equal(t, int(21000), int(balance.Total))
		require.Zero(t, int(balance.OffchainBalance.Available))
		require.Zero(t, int(balance.OffchainBalance.Preconfirmed))
		require.Zero(t, int(balance.OffchainBalance.Recoverable))
		require.Zero(t, int(balance.OffchainBalance.Settled))
		require.Equal(t, int(21000), int(balance.OnchainBalance.Confirmed))
		require.Zero(t, int(balance.OnchainBalance.Unconfirmed))
		require.Equal(t, int(21000), int(balance.OnchainBalance.Total))

		vtxoCh := alice.GetVtxoEventChannel(ctx)

		commitmentTx, err := alice.Settle(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, commitmentTx)

		// Wait for the VTXO added event.
		vtxoEvent := waitForVtxoEvent(t, vtxoCh, 30*time.Second, func(event types.VtxoEvent) bool {
			return event.Type == types.VtxosAdded && len(event.Vtxos) == 1
		})
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 1)
		require.Equal(t, 21000, int(vtxoEvent.Vtxos[0].Amount))

		// After settlement, off-chain balance should reflect the funds.
		balance, err = alice.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)

		// Invariant: Total == Available + Preconfirmed + Recoverable
		preconfirmed := balance.OffchainBalance.Preconfirmed
		recoverable := balance.OffchainBalance.Recoverable
		settled := balance.OffchainBalance.Settled
		require.Equal(t, int(settled+preconfirmed+recoverable), int(balance.OffchainBalance.Total))
		require.Equal(t, int(settled+preconfirmed), int(balance.OffchainBalance.Available))
		require.GreaterOrEqual(t, int(balance.OffchainBalance.Total), 21000)
		require.Equal(
			t, int(balance.OnchainBalance.Total+balance.OffchainBalance.Total), int(balance.Total),
		)
	})

	t.Run("preconfirmed", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")
		bob := setupClient(t, "")
		faucetOffchain(t, alice, 0.0005)

		bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		bobVtxoCh := bob.GetVtxoEventChannel(ctx)

		_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
			To:     bobOffchainAddr,
			Amount: 21000,
		}})
		require.NoError(t, err)

		bobVtxoEvent := waitForVtxoEvent(
			t,
			bobVtxoCh,
			30*time.Second,
			func(event types.VtxoEvent) bool {
				return event.Type == types.VtxosAdded && len(event.Vtxos) == 1
			},
		)

		require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		require.Equal(t, 21000, int(bobVtxoEvent.Vtxos[0].Amount))

		balance, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Equal(t, int(21000), int(balance.OffchainBalance.Total))
		require.Zero(t, int(balance.OffchainBalance.Settled))
		require.Equal(t, int(21000), int(balance.OffchainBalance.Preconfirmed))
		require.Zero(t, int(balance.OffchainBalance.Recoverable))
		require.Equal(t, int(21000), int(balance.OffchainBalance.Available))
		require.Equal(
			t,
			int(
				balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed+
					balance.OffchainBalance.Recoverable,
			),
			int(balance.OffchainBalance.Total),
		)
		require.Equal(
			t,
			int(balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed),
			int(balance.OffchainBalance.Available),
		)
	})

	t.Run(
		"settled and preconfirmed",
		func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t, "")
			bob := setupClient(t, "")
			faucetOffchain(t, bob, 0.0005)
			faucetOffchain(t, alice, 0.0005)

			bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOffchainAddr)

			bobVtxoCh := bob.GetVtxoEventChannel(ctx)

			_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobOffchainAddr,
				Amount: 21000,
			}})
			require.NoError(t, err)

			bobVtxoEvent := waitForVtxoEvent(
				t,
				bobVtxoCh,
				30*time.Second,
				func(event types.VtxoEvent) bool {
					return event.Type == types.VtxosAdded && len(event.Vtxos) == 1
				},
			)

			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)

			balance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)
			require.Greater(t, int(balance.OffchainBalance.Settled), 0)
			require.Equal(t, int(21000), int(balance.OffchainBalance.Preconfirmed))
			require.Zero(t, int(balance.OffchainBalance.Recoverable))
			require.Equal(
				t,
				int(balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed),
				int(balance.OffchainBalance.Available),
			)
			require.Equal(
				t,
				int(
					balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed+
						balance.OffchainBalance.Recoverable,
				),
				int(balance.OffchainBalance.Total),
			)
		},
	)

	t.Run("recoverable (subdust)", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")
		bob := setupClient(t, "")
		faucetOffchain(t, alice, 0.0005)

		bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		bobVtxoCh := bob.GetVtxoEventChannel(ctx)
		_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
			To:     bobOffchainAddr,
			Amount: 100,
		}})
		require.NoError(t, err)

		bobVtxoEvent := waitForVtxoEvent(
			t,
			bobVtxoCh,
			30*time.Second,
			func(event types.VtxoEvent) bool {
				return event.Type == types.VtxosAdded && len(event.Vtxos) == 1
			},
		)

		require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		require.Equal(t, 100, int(bobVtxoEvent.Vtxos[0].Amount))

		balance, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Equal(t, int(100), int(balance.OffchainBalance.Total))
		require.Zero(t, int(balance.OffchainBalance.Settled))
		require.Zero(t, int(balance.OffchainBalance.Preconfirmed))
		require.Equal(t, int(100), int(balance.OffchainBalance.Recoverable))
		require.Zero(t, int(balance.OffchainBalance.Available))
		require.Equal(
			t,
			int(
				balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed+
					balance.OffchainBalance.Recoverable,
			),
			int(balance.OffchainBalance.Total),
		)
	})

	t.Run("onchain", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")
		bob := setupClient(t, "")

		faucetOffchain(t, alice, 0.0005)

		bobOnchainAddr, err := bob.NewBoardingAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOnchainAddr)

		bobUtxoCh := bob.GetUtxoEventChannel(ctx)

		_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
		require.NoError(t, err)

		bobUtxoEvent := waitForUtxoEvent(
			t,
			bobUtxoCh,
			30*time.Second,
			func(event types.UtxoEvent) bool {
				return event.Type == types.UtxosAdded && len(event.Utxos) == 1
			},
		)
		require.False(t, bobUtxoEvent.Utxos[0].IsConfirmed())

		balance, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Zero(t, int(balance.OnchainBalance.Confirmed))
		require.Equal(t, int(21000), int(balance.OnchainBalance.Unconfirmed))
		require.Equal(t, int(21000), int(balance.OnchainBalance.Total))
		require.Zero(t, int(balance.OnchainBalance.SpendableAmount))

		require.NoError(t, generateBlocks(1))

		bobUtxoEvent = waitForUtxoEvent(
			t,
			bobUtxoCh,
			30*time.Second,
			func(event types.UtxoEvent) bool {
				return event.Type == types.UtxosConfirmed && len(event.Utxos) == 1
			},
		)
		require.True(t, bobUtxoEvent.Utxos[0].IsConfirmed())

		balance, err = bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Equal(t, int(21000), int(balance.OnchainBalance.Confirmed))
		require.Zero(t, int(balance.OnchainBalance.Unconfirmed))
		require.Equal(t, int(21000), int(balance.OnchainBalance.Total))
	})

	t.Run("recoverable (swept)", func(t *testing.T) {
		ctx := t.Context()

		alice := setupClient(t, "")
		faucetOffchain(t, alice, 0.0005)

		// Make the funds expire and be swept by the server
		generateBlocks(21)

		vtxoCh := alice.GetVtxoEventChannel(ctx)

		require.Eventually(t, func() bool {
			balance, err := alice.Balance(ctx)
			require.NoError(t, err)
			return balance.OffchainBalance.Recoverable > 0
		}, 20*time.Second, 200*time.Millisecond)

		sawSweepEvent := false
		for !sawSweepEvent {
			select {
			case event := <-vtxoCh:
				if event.Type == types.VtxosSwept {
					sawSweepEvent = true
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for sweep event")
			}
		}

		balance, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Greater(t, int(balance.OffchainBalance.Recoverable), 0)
		require.Equal(
			t,
			int(
				balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed+
					balance.OffchainBalance.Recoverable,
			),
			int(balance.OffchainBalance.Total),
		)
	})
}
