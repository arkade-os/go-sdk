package arksdk

import (
	"context"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
)

func (a *arkClient) NewOffchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	_, offchainAddr, _, err := a.Receive(ctx)
	return offchainAddr.Address, err
}

func (a *arkClient) NewBoardingAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	_, _, boardingAddr, err := a.Receive(ctx)
	if err != nil {
		return "", err
	}
	go func() {
		if err := a.Explorer().SubscribeForAddresses([]string{boardingAddr.Address}); err != nil {
			log.WithError(err).Error("failed to subscribe for boarding address")
		}
	}()
	return boardingAddr.Address, nil
}

func (a *arkClient) NewOnchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	onchainAddr, _, _, err := a.Receive(ctx)
	return onchainAddr, err
}

func (a *arkClient) Balance(ctx context.Context) (*Balance, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	balance := &Balance{
		OnchainBalance: OnchainBalance{
			Confirmed:       0,
			Unconfirmed:     0,
			Total:           0,
			SpendableAmount: 0,
			LockedAmount:    make([]LockedOnchainBalance, 0),
		},
		OffchainBalance: OffchainBalance{
			Total:          0,
			NextExpiration: "",
			Details:        make([]VtxoDetails, 0),
		},
		AssetBalances: make(map[string]uint64, 0),
	}

	// offchain balance
	offchainBal, err := a.getOffchainBalance(ctx)
	if err != nil {
		return nil, err
	}

	nextExpiration, details := getOffchainBalanceDetails(offchainBal.amountByExpiration)
	balance.OffchainBalance.Total = offchainBal.total
	balance.OffchainBalance.NextExpiration = getFancyTimeExpiration(nextExpiration)
	balance.OffchainBalance.Details = details
	balance.OffchainBalance.Available = offchainBal.settled + offchainBal.preconfirmed
	balance.OffchainBalance.Preconfirmed = offchainBal.preconfirmed
	balance.OffchainBalance.Recoverable = offchainBal.recoverable
	balance.OffchainBalance.Settled = offchainBal.settled
	balance.AssetBalances = offchainBal.assetBalances

	// onchain balance
	utxoStore := a.store.UtxoStore()
	utxos, _, err := utxoStore.GetAllUtxos(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	for _, utxo := range utxos {
		if !utxo.IsConfirmed() {
			balance.OnchainBalance.Unconfirmed += utxo.Amount
			balance.OnchainBalance.Total += utxo.Amount
			continue
		}

		balance.OnchainBalance.Confirmed += utxo.Amount
		balance.OnchainBalance.Total += utxo.Amount

		if now.After(utxo.SpendableAt) {
			balance.OnchainBalance.SpendableAmount += utxo.Amount
			continue
		}

		balance.OnchainBalance.LockedAmount = append(
			balance.OnchainBalance.LockedAmount,
			LockedOnchainBalance{
				SpendableAt: utxo.SpendableAt.Format(time.RFC3339),
				Amount:      utxo.Amount,
			},
		)
	}

	balance.Total = balance.OnchainBalance.Total + balance.OffchainBalance.Total

	return balance, nil
}

func (a *arkClient) ListSpendableVtxos(ctx context.Context) ([]clientTypes.Vtxo, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	// TODO: add safe check
	return a.store.VtxoStore().GetSpendableVtxos(ctx)
}

func (a *arkClient) ListVtxos(
	ctx context.Context,
) ([]clientTypes.Vtxo, []clientTypes.Vtxo, error) {
	if err := a.safeCheck(); err != nil {
		return nil, nil, err
	}

	// TODO: add safe check
	return a.store.VtxoStore().GetAllVtxos(ctx)
}

type offchainBalanceResult struct {
	total              uint64
	settled            uint64
	preconfirmed       uint64
	recoverable        uint64
	amountByExpiration map[int64]uint64
	assetBalances      map[string]uint64
}

func (a *arkClient) getOffchainBalance(ctx context.Context) (
	offchainBalanceResult, error,
) {
	result := offchainBalanceResult{
		amountByExpiration: make(map[int64]uint64),
		assetBalances:      make(map[string]uint64),
	}

	vtxos, _, err := a.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return result, err
	}

	for _, vtxo := range vtxos {
		if vtxo.Unrolled {
			continue
		}

		result.total += vtxo.Amount

		// Classify VTXO by state. Priority: Swept > Preconfirmed > default.
		switch {
		case vtxo.Swept:
			result.recoverable += vtxo.Amount
		case vtxo.Preconfirmed:
			result.preconfirmed += vtxo.Amount
		default:
			result.settled += vtxo.Amount
		}

		if !vtxo.ExpiresAt.IsZero() {
			expiration := vtxo.ExpiresAt.Unix()

			if _, ok := result.amountByExpiration[expiration]; !ok {
				result.amountByExpiration[expiration] = 0
			}

			result.amountByExpiration[expiration] += vtxo.Amount
		}

		for _, a := range vtxo.Assets {
			if _, ok := result.assetBalances[a.AssetId]; !ok {
				result.assetBalances[a.AssetId] = a.Amount
				continue
			}

			result.assetBalances[a.AssetId] += a.Amount
		}
	}

	return result, nil
}
