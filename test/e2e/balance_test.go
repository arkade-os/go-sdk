package e2e

import (
	"os"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestBalanceBreakdown(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		t.Run("balance state breakdowns after settle", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)

			// Before any funding, all balances should be zero.
			balance, err := alice.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)
			require.Zero(t, balance.OffchainBalance.Total)
			require.Zero(t, balance.Total)
			require.Zero(t, balance.OffchainBalance.Available)
			require.Zero(t, balance.OffchainBalance.Preconfirmed)
			require.Zero(t, balance.OffchainBalance.Recoverable)
			require.Zero(t, balance.OffchainBalance.Settled)
			require.Zero(t, balance.OnchainBalance.Confirmed)
			require.Zero(t, balance.OnchainBalance.Unconfirmed)
			require.Zero(t, balance.OnchainBalance.Total)

			// Fund Alice's boarding address and wait for the UTXO event.
			boardingAddr, err := alice.NewBoardingAddress(ctx)
			require.NoError(t, err)

			utxoCh := alice.GetUtxoEventChannel(ctx)

			faucetOnchain(t, boardingAddr, 0.00021)

			utxoEvent := <-utxoCh
			require.Equal(t, types.UtxosAdded, utxoEvent.Type)
			require.Len(t, utxoEvent.Utxos, 1)
			require.Equal(t, 21000, int(utxoEvent.Utxos[0].Amount))

			// Offchain balance should still be zero (funds are on-chain only).
			balance, err = alice.Balance(ctx)
			require.NoError(t, err)
			require.Zero(t, balance.OffchainBalance.Total)
			require.Equal(t, uint64(21000), balance.Total)
			require.Zero(t, balance.OffchainBalance.Available)
			require.Zero(t, balance.OffchainBalance.Preconfirmed)
			require.Zero(t, balance.OffchainBalance.Recoverable)
			require.Zero(t, balance.OffchainBalance.Settled)
			require.Equal(t, uint64(21000), balance.OnchainBalance.Confirmed)
			require.Zero(t, balance.OnchainBalance.Unconfirmed)
			require.Equal(t, uint64(21000), balance.OnchainBalance.Total)

			vtxoCh := alice.GetVtxoEventChannel(ctx)

			commitmentTx, err := alice.Settle(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, commitmentTx)

			// Wait for the VTXO added event.
			vtxoEvent := <-vtxoCh
			require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
			require.Len(t, vtxoEvent.Vtxos, 1)
			require.Equal(t, 21000, int(vtxoEvent.Vtxos[0].Amount))

			// After settlement, off-chain balance should reflect the funds.
			balance, err = alice.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)

			// Invariant: Total == Available + Preconfirmed + Recoverable
			total := balance.OffchainBalance.Total
			available := balance.OffchainBalance.Available
			preconfirmed := balance.OffchainBalance.Preconfirmed
			recoverable := balance.OffchainBalance.Recoverable
			settled := balance.OffchainBalance.Settled

			t.Logf(
				"Balance breakdown — Total: %d, Available: %d, Preconfirmed: %d, Recoverable: %d, Settled: %d",
				total,
				available,
				preconfirmed,
				recoverable,
				settled,
			)

			require.Equal(t, total, settled+preconfirmed+recoverable,
				"Total must equal Settled + Preconfirmed + Recoverable")
			require.Equal(t, available, settled+preconfirmed,
				"Available must equal Settled + Preconfirmed")
			require.GreaterOrEqual(t, int(total), 21000,
				"Total offchain balance should be at least 21000 sats")
			require.Equal(t, balance.Total, balance.OnchainBalance.Total+balance.OffchainBalance.Total,
				"Wallet total must equal onchain total + offchain total")

			// After the commitment is confirmed, Available should be > 0 and
			// Preconfirmed should be 0.
			require.Greater(t, int(available+preconfirmed), 0,
				"At least some funds should be available or preconfirmed")
		})

		t.Run("recipient receives preconfirmed offchain funds", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			bob := setupClient(t)

			faucetOffchain(t, alice, 0.001)

			bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOffchainAddr)

			bobVtxoCh := bob.GetVtxoEventChannel(ctx)

			_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobOffchainAddr,
				Amount: 21000,
			}})
			require.NoError(t, err)

			bobVtxoEvent := <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			require.Equal(t, 21000, int(bobVtxoEvent.Vtxos[0].Amount))

			balance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)
			require.Equal(t, uint64(21000), balance.OffchainBalance.Total)
			require.Zero(t, balance.OffchainBalance.Settled)
			require.Equal(t, uint64(21000), balance.OffchainBalance.Preconfirmed)
			require.Zero(t, balance.OffchainBalance.Recoverable)
			require.Equal(t, uint64(21000), balance.OffchainBalance.Available)
			require.Equal(
				t,
				balance.OffchainBalance.Total,
				balance.OffchainBalance.Settled+
					balance.OffchainBalance.Preconfirmed+balance.OffchainBalance.Recoverable,
			)
			require.Equal(
				t,
				balance.OffchainBalance.Available,
				balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed,
			)
		})

		t.Run("wallet can have settled and preconfirmed funds at the same time", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			bob := setupClient(t)

			faucetOffchain(t, bob, 0.0005)
			initialBobBalance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, initialBobBalance)
			require.Greater(t, int(initialBobBalance.OffchainBalance.Settled), 0)
			require.Zero(t, initialBobBalance.OffchainBalance.Preconfirmed)

			faucetOffchain(t, alice, 0.001)

			bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOffchainAddr)

			bobVtxoCh := bob.GetVtxoEventChannel(ctx)
			_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobOffchainAddr,
				Amount: 21000,
			}})
			require.NoError(t, err)

			bobVtxoEvent := <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)

			balance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)
			require.Greater(t, int(balance.OffchainBalance.Settled), 0)
			require.Equal(t, uint64(21000), balance.OffchainBalance.Preconfirmed)
			require.Zero(t, balance.OffchainBalance.Recoverable)
			require.Equal(
				t,
				balance.OffchainBalance.Available,
				balance.OffchainBalance.Settled+balance.OffchainBalance.Preconfirmed,
			)
			require.Equal(
				t, balance.OffchainBalance.Total,
				balance.OffchainBalance.Settled+
					balance.OffchainBalance.Preconfirmed+balance.OffchainBalance.Recoverable,
			)
		})

		t.Run("subdust_offchain_funds_are_recoverable", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			bob := setupClient(t)

			faucetOffchain(t, alice, 0.001)

			bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOffchainAddr)

			bobVtxoCh := bob.GetVtxoEventChannel(ctx)
			_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobOffchainAddr,
				Amount: 100,
			}})
			require.NoError(t, err)

			bobVtxoEvent := <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			require.Equal(t, 100, int(bobVtxoEvent.Vtxos[0].Amount))

			balance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)
			require.Equal(t, uint64(100), balance.OffchainBalance.Total)
			require.Zero(t, balance.OffchainBalance.Settled)
			require.Zero(t, balance.OffchainBalance.Preconfirmed)
			require.Equal(t, uint64(100), balance.OffchainBalance.Recoverable)
			require.Zero(t, balance.OffchainBalance.Available)
			require.Equal(
				t,
				balance.OffchainBalance.Total,
				balance.OffchainBalance.Settled+
					balance.OffchainBalance.Preconfirmed+balance.OffchainBalance.Recoverable,
			)
		})

		t.Run("onchain balance tracks unconfirmed and confirmed amounts", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			bob := setupClient(t)

			faucetOffchain(t, alice, 0.001)

			bobOnchainAddr, err := bob.NewOnchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			bobUtxoCh := bob.GetUtxoEventChannel(ctx)

			_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
			require.NoError(t, err)

			bobUtxoEvent := <-bobUtxoCh
			require.Equal(t, types.UtxosAdded, bobUtxoEvent.Type)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			require.False(t, bobUtxoEvent.Utxos[0].IsConfirmed())

			balance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)
			require.Zero(t, balance.OnchainBalance.Confirmed)
			require.Equal(t, uint64(21000), balance.OnchainBalance.Unconfirmed)
			require.Equal(t, uint64(21000), balance.OnchainBalance.Total)
			require.Zero(t, balance.OnchainBalance.SpendableAmount)

			require.NoError(t, generateBlocks(1))

			bobUtxoEvent = <-bobUtxoCh
			require.Equal(t, types.UtxosConfirmed, bobUtxoEvent.Type)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			require.True(t, bobUtxoEvent.Utxos[0].IsConfirmed())

			balance, err = bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, balance)
			require.Equal(t, uint64(21000), balance.OnchainBalance.Confirmed)
			require.Zero(t, balance.OnchainBalance.Unconfirmed)
			require.Equal(t, uint64(21000), balance.OnchainBalance.Total)
		})

		t.Run("swept funds become recoverable", func(t *testing.T) {
			if os.Getenv("RUN_LONG_EXPIRY_TESTS") == "" {
				t.Skip("set RUN_LONG_EXPIRY_TESTS=1 to run sweep-expiry balance coverage")
			}

			ctx := t.Context()
			alice := setupClient(t)

			faucetOffchain(t, alice, 0.00005)

			vtxoCh := alice.GetVtxoEventChannel(ctx)

			require.Eventually(t, func() bool {
				balance, err := alice.Balance(ctx)
				require.NoError(t, err)
				return balance.OffchainBalance.Recoverable > 0
			}, 10*time.Minute, 5*time.Second)

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
				balance.OffchainBalance.Total,
				balance.OffchainBalance.Settled+
					balance.OffchainBalance.Preconfirmed+balance.OffchainBalance.Recoverable,
			)
		})
	})
}
