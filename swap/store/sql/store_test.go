package sqlstore_test

import (
	"path/filepath"
	"testing"

	"github.com/arkade-os/go-sdk/swap"
	swapstore "github.com/arkade-os/go-sdk/swap/store"
	sqlstore "github.com/arkade-os/go-sdk/swap/store/sql"
	"github.com/stretchr/testify/require"
)

func TestSwapRepository(t *testing.T) {
	store, _ := newStore(t)
	defer func() { require.NoError(t, store.Close()) }()

	ctx := t.Context()
	repo := store.Swaps()
	record := swapstore.SwapRecord{
		ID:                  "swap-1",
		Amount:              42,
		Timestamp:           1700000000,
		ToCurrency:          "BTC",
		FromCurrency:        "ARK",
		Status:              int(swap.SwapPending),
		Invoice:             "invoice",
		VHTLCContractScript: "vhtlc-script",
	}

	count, err := repo.Add(ctx, []swapstore.SwapRecord{record})
	require.NoError(t, err)
	require.Equal(t, 1, count)

	count, err = repo.Add(ctx, []swapstore.SwapRecord{record})
	require.NoError(t, err)
	require.Zero(t, count)

	got, err := repo.Get(ctx, record.ID)
	require.NoError(t, err)
	require.Empty(t, got.FundingTxID)
	require.Empty(t, got.RedeemTxID)

	record.Status = int(swap.SwapSuccess)
	record.FundingTxID = "funding-tx"
	record.RedeemTxID = "redeem-tx"
	require.NoError(t, repo.Update(ctx, record))

	got, err = repo.Get(ctx, record.ID)
	require.NoError(t, err)
	require.Equal(t, int(swap.SwapSuccess), got.Status)
	require.Equal(t, "funding-tx", got.FundingTxID)
	require.Equal(t, "redeem-tx", got.RedeemTxID)
}

func TestChainSwapRepository(t *testing.T) {
	store, _ := newStore(t)
	defer func() { require.NoError(t, store.Close()) }()

	ctx := t.Context()
	repo := store.ChainSwaps()
	first := swapstore.ChainSwapRecord{
		ID:                      "chain-1",
		FromCurrency:            "ARK",
		ToCurrency:              "BTC",
		Amount:                  1000,
		Status:                  int(swap.ChainSwapPending),
		ClaimPreimage:           "preimage",
		UserBTCLockupAddress:    "btc-address",
		BTCHTLCPrivateKey:       "private-key",
		BoltzCreateResponseJSON: "{}",
		CreatedAt:               1700000000,
	}
	require.NoError(t, repo.Add(ctx, first))

	got, err := repo.Get(ctx, first.ID)
	require.NoError(t, err)
	require.Equal(t, first.ID, got.ID)
	require.Equal(t, first.UserBTCLockupAddress, got.UserBTCLockupAddress)
	require.Equal(t, first.BTCHTLCPrivateKey, got.BTCHTLCPrivateKey)

	first.Status = int(swap.ChainSwapUserLocked)
	first.UserLockupTxID = "user-lock"
	first.ServerLockupTxID = "server-lock"
	first.ClaimTxID = "claim"
	first.RefundTxID = "refund"
	first.ErrorMessage = "error"
	require.NoError(t, repo.Update(ctx, first))

	got, err = repo.Get(ctx, first.ID)
	require.NoError(t, err)
	require.Equal(t, int(swap.ChainSwapUserLocked), got.Status)
	require.Equal(t, "user-lock", got.UserLockupTxID)
	require.Equal(t, "server-lock", got.ServerLockupTxID)
	require.Equal(t, "claim", got.ClaimTxID)
	require.Equal(t, "refund", got.RefundTxID)
	require.Equal(t, "error", got.ErrorMessage)
	require.Equal(t, "private-key", got.BTCHTLCPrivateKey)
}

func newStore(t *testing.T) (swapstore.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "swap.sqlite.db")
	store, err := sqlstore.Open(dbPath)
	require.NoError(t, err)
	return store, dbPath
}
