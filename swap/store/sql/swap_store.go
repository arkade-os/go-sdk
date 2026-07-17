package sqlstore

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/arkade-os/go-sdk/swap/store/sql/sqlc/queries"
	"github.com/arkade-os/go-sdk/swap/types"
)

type swapStore struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewSwapStore(db *sql.DB) types.SwapStore {
	return &swapStore{
		db:      db,
		querier: queries.New(db),
	}
}

func (r *swapStore) Add(ctx context.Context, swap types.Swap) error {
	params := queries.InsertSwapParams{
		ID:           swap.Id,
		FromCurrency: string(swap.From),
		ToCurrency:   string(swap.To),
		Amount:       int64(swap.Amount),
		Status:       int64(swap.Status),
		CreatedAt:    swap.CreatedAt.Unix(),
		UpdatedAt:    nullableUnixTime(swap.UpdatedAt),
		VhtlcScript:  swap.VHTLCScript,
		FundingTxid:  nullableString(swap.FundingTxid),
		RedeemTxid:   nullableString(swap.RedeemTxid),
		Preimage:     nullableString(hex.EncodeToString(swap.Preimage)),
	}
	if swap.LNSwap != nil {
		params.LnPreimageHash = nullableString(hex.EncodeToString(swap.LNSwap.PreimageHash))
		params.LnInvoice = nullableString(swap.LNSwap.Invoice)
	}
	if swap.ChainSwap != nil {
		swapTree, err := json.Marshal(swap.ChainSwap.SwapTree)
		if err != nil {
			return fmt.Errorf("serialize swap tree for swap %s: %w", swap.Id, err)
		}
		params.ChainFundingTxid = nullableString(swap.ChainSwap.FundingTxid)
		params.ChainRedeemTxid = nullableString(swap.ChainSwap.RedeemTxid)
		params.ChainAddress = nullableString(swap.ChainSwap.Address)
		params.ChainPrivateKey = nullableString(swap.ChainSwap.PrivateKey)
		params.ChainSwapTree = nullableString(string(swapTree))
	}

	if err := r.querier.InsertSwap(ctx, params); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("swap already exists with id %s", swap.Id)
		}
		return err
	}
	return nil
}

func (r *swapStore) Get(ctx context.Context, id string) (*types.Swap, error) {
	row, err := r.querier.SelectSwap(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("swap not found with id %s", id)
		}
		return nil, err
	}
	return readRow(row)
}

func (r *swapStore) Update(ctx context.Context, swap types.Swap) error {
	updatedAt := swap.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now()
	}
	params := queries.UpdateSwapParams{
		ID:          swap.Id,
		Status:      int64(swap.Status),
		UpdatedAt:   nullableUnixTime(updatedAt),
		FundingTxid: nullableString(swap.FundingTxid),
		RedeemTxid:  nullableString(swap.RedeemTxid),
		Preimage:    nullableString(hex.EncodeToString(swap.Preimage)),
	}
	if swap.ChainSwap != nil {
		params.ChainFundingTxid = nullableString(swap.ChainSwap.FundingTxid)
		params.ChainRedeemTxid = nullableString(swap.ChainSwap.RedeemTxid)
	}

	n, err := r.querier.UpdateSwap(ctx, params)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("swap not found with id %s", swap.Id)
	}
	return nil
}

func readRow(row queries.Swap) (*types.Swap, error) {
	preimage, err := decodeNullableHex(row.Preimage)
	if err != nil {
		return nil, fmt.Errorf("decode preimage for swap %s: %w", row.ID, err)
	}

	swap := &types.Swap{
		Id:          row.ID,
		From:        boltz.Currency(row.FromCurrency),
		To:          boltz.Currency(row.ToCurrency),
		CreatedAt:   time.Unix(row.CreatedAt, 0),
		UpdatedAt:   unixTimeValue(row.UpdatedAt),
		Status:      int(row.Status),
		VHTLCScript: row.VhtlcScript,
		Amount:      uint64(row.Amount),
		FundingTxid: stringValue(row.FundingTxid),
		RedeemTxid:  stringValue(row.RedeemTxid),
		Preimage:    preimage,
	}

	if row.LnPreimageHash.Valid || row.LnInvoice.Valid {
		preimageHash, err := decodeNullableHex(row.LnPreimageHash)
		if err != nil {
			return nil, fmt.Errorf("decode ln preimage hash for swap %s: %w", row.ID, err)
		}
		swap.LNSwap = &types.LNSwapInfo{
			PreimageHash: preimageHash,
			Invoice:      stringValue(row.LnInvoice),
		}
	}

	if row.ChainSwapTree.Valid {
		var swapTree boltz.SwapTree
		if err := json.Unmarshal([]byte(row.ChainSwapTree.String), &swapTree); err != nil {
			return nil, fmt.Errorf("deserialize swap tree for swap %s: %w", row.ID, err)
		}
		swap.ChainSwap = &types.ChainSwapInfo{
			FundingTxid: stringValue(row.ChainFundingTxid),
			RedeemTxid:  stringValue(row.ChainRedeemTxid),
			Address:     stringValue(row.ChainAddress),
			PrivateKey:  stringValue(row.ChainPrivateKey),
			SwapTree:    swapTree,
		}
	}

	return swap, nil
}
