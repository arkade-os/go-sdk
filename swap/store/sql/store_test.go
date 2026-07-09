package sqlstore_test

import (
	"path/filepath"
	"testing"

	"github.com/arkade-os/go-sdk/swap"
	sqlstore "github.com/arkade-os/go-sdk/swap/store/sql"
	"github.com/stretchr/testify/require"
)

func TestSwapRepository(t *testing.T) {
	store, _ := newStore(t)
	defer func() { require.NoError(t, store.Close()) }()

	ctx := t.Context()
	repo := store.Swaps()
	record := swap.SwapRecord{
		ID:                  "swap-1",
		Amount:              42,
		Timestamp:           1700000000,
		ToCurrency:          "BTC",
		FromCurrency:        "ARK",
		Status:              swap.SwapPending,
		Type:                swap.SwapRecordRegular,
		Invoice:             "invoice",
		VHTLCContractScript: "vhtlc-script",
	}

	count, err := repo.Add(ctx, []swap.SwapRecord{record})
	require.NoError(t, err)
	require.Equal(t, 1, count)

	count, err = repo.Add(ctx, []swap.SwapRecord{record})
	require.NoError(t, err)
	require.Zero(t, count)

	got, err := repo.Get(ctx, record.ID)
	require.NoError(t, err)
	require.Empty(t, got.FundingTxID)
	require.Empty(t, got.RedeemTxID)

	record.Status = swap.SwapSuccess
	record.FundingTxID = "funding-tx"
	record.RedeemTxID = "redeem-tx"
	require.NoError(t, repo.Update(ctx, record))

	got, err = repo.Get(ctx, record.ID)
	require.NoError(t, err)
	require.Equal(t, swap.SwapSuccess, got.Status)
	require.Equal(t, "funding-tx", got.FundingTxID)
	require.Equal(t, "redeem-tx", got.RedeemTxID)
}

func TestChainSwapRepository(t *testing.T) {
	store, _ := newStore(t)
	defer func() { require.NoError(t, store.Close()) }()

	ctx := t.Context()
	repo := store.ChainSwaps()
	first := swap.ChainSwapRecord{
		ID:                      "chain-1",
		FromCurrency:            "ARK",
		ToCurrency:              "BTC",
		Amount:                  1000,
		Status:                  swap.ChainSwapPending,
		ClaimPreimage:           "preimage",
		UserBTCLockupAddress:    "btc-address",
		BoltzCreateResponseJSON: "{}",
		CreatedAt:               1700000000,
	}
	require.NoError(t, repo.Add(ctx, first))

	got, err := repo.Get(ctx, first.ID)
	require.NoError(t, err)
	require.Equal(t, first.ID, got.ID)
	require.Equal(t, first.UserBTCLockupAddress, got.UserBTCLockupAddress)

	first.Status = swap.ChainSwapUserLocked
	first.UserLockupTxID = "user-lock"
	first.ServerLockupTxID = "server-lock"
	first.ClaimTxID = "claim"
	first.RefundTxID = "refund"
	first.ErrorMessage = "error"
	require.NoError(t, repo.Update(ctx, first))

	got, err = repo.Get(ctx, first.ID)
	require.NoError(t, err)
	require.Equal(t, swap.ChainSwapUserLocked, got.Status)
	require.Equal(t, "user-lock", got.UserLockupTxID)
	require.Equal(t, "server-lock", got.ServerLockupTxID)
	require.Equal(t, "claim", got.ClaimTxID)
	require.Equal(t, "refund", got.RefundTxID)
	require.Equal(t, "error", got.ErrorMessage)
}

func TestHTLCKeyRepository(t *testing.T) {
	store, _ := newStore(t)
	defer func() { require.NoError(t, store.Close()) }()

	ctx := t.Context()
	repo := store.HTLCKeys()
	key := swap.HTLCKeyRecord{
		Address:       "btc-lockup-address",
		PrivateKeyHex: "01",
		CreatedAt:     1700000000,
	}

	require.NoError(t, repo.Add(ctx, key))
	got, err := repo.Get(ctx, key.Address)
	require.NoError(t, err)
	require.Equal(t, key, *got)

	key.PrivateKeyHex = "02"
	key.CreatedAt = 1700000001
	require.NoError(t, repo.Add(ctx, key))

	got, err = repo.Get(ctx, key.Address)
	require.NoError(t, err)
	require.Equal(t, key, *got)
}

func newStore(t *testing.T) (swap.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "swap.sqlite.db")
	store, err := sqlstore.Open(dbPath)
	require.NoError(t, err)
	return store, dbPath
}
