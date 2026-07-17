package store_test

import (
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/swap"
	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/arkade-os/go-sdk/swap/store"
	"github.com/arkade-os/go-sdk/swap/types"
	"github.com/stretchr/testify/require"
)

func TestSwapStore(t *testing.T) {
	storeSvc := newStore(t)

	ctx := t.Context()
	swapStore := storeSvc.Swaps()

	t.Run("add", func(t *testing.T) {
		fixtures := []struct {
			name string
			args types.Swap
		}{
			{
				name: "swap",
				args: types.Swap{
					Id:          "ln-swap-1",
					From:        boltz.CurrencyArk,
					To:          boltz.CurrencyBtc,
					CreatedAt:   time.Now(),
					Status:      int(swap.SwapStatusPending),
					VHTLCScript: "script",
					Amount:      5000,
					Preimage:    make([]byte, 32),
					LNSwap: &types.LNSwapInfo{
						PreimageHash: make([]byte, 32),
						Invoice:      "lnbcrt50u1invoice",
					},
				},
			},
			{
				name: "chainswap",
				args: types.Swap{
					Id:          "chain-swap-1",
					From:        boltz.CurrencyBtc,
					To:          boltz.CurrencyArk,
					CreatedAt:   time.Now(),
					Status:      int(swap.SwapStatusPending),
					VHTLCScript: "chain-swap-script",
					Amount:      7000,
					Preimage:    make([]byte, 32),
					ChainSwap: &types.ChainSwapInfo{
						FundingTxid: "user-lockup-tx",
						RedeemTxid:  "claim-tx",
						Address:     "bcrt1qlockupaddress",
						PrivateKey:  "btc-htlc-private-key",
						SwapTree: boltz.SwapTree{
							ClaimLeaf:  boltz.SwapTreeLeaf{Version: 192, Output: "claim-leaf-output"},
							RefundLeaf: boltz.SwapTreeLeaf{Version: 192, Output: "refund-leaf-output"},
						},
					},
				},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := swapStore.Add(ctx, f.args)
				require.NoError(t, err)

				// Adding a swap with the same id must fail.
				err = swapStore.Add(ctx, f.args)
				require.Error(t, err)

				got, err := swapStore.Get(ctx, f.args.Id)
				require.NoError(t, err)
				requireSwapsMatch(t, f.args, *got)
			})
		}
	})

	t.Run("update", func(t *testing.T) {
		record := types.Swap{
			Id:          "swap-to-update",
			From:        boltz.CurrencyArk,
			To:          boltz.CurrencyBtc,
			CreatedAt:   time.Now(),
			Status:      int(swap.SwapStatusPending),
			VHTLCScript: "script",
			Amount:      5000,
			Preimage:    make([]byte, 32),
			LNSwap: &types.LNSwapInfo{
				PreimageHash: make([]byte, 32),
				Invoice:      "lnbcrt50u1invoice",
			},
		}
		require.NoError(t, swapStore.Add(ctx, record))

		record.Status = int(swap.SwapStatusSuccess)
		record.FundingTxid = "funding-tx"
		record.RedeemTxid = "redeem-tx"
		require.NoError(t, swapStore.Update(ctx, record))

		got, err := swapStore.Get(ctx, record.Id)
		require.NoError(t, err)
		require.Equal(t, int(swap.SwapStatusSuccess), got.Status)
		require.Equal(t, "funding-tx", got.FundingTxid)
		require.Equal(t, "redeem-tx", got.RedeemTxid)

		// Updating a swap that doesn't exist must fail.
		missing := record
		missing.Id = "missing-swap"
		require.Error(t, swapStore.Update(ctx, missing))
	})
}

func newStore(t *testing.T) types.Store {
	t.Helper()
	storeSvc, err := store.NewService(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, storeSvc.Close()) })
	return storeSvc
}

func requireSwapsMatch(t *testing.T, expected, got types.Swap) {
	t.Helper()
	require.Equal(t, expected.CreatedAt.Unix(), got.CreatedAt.Unix())
	require.Equal(t, expected.UpdatedAt.Unix(), got.UpdatedAt.Unix())
	expected.CreatedAt, got.CreatedAt = time.Time{}, time.Time{}
	expected.UpdatedAt, got.UpdatedAt = time.Time{}, time.Time{}
	require.Equal(t, expected, got)
}
