package arksdk

import (
	"context"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

func (a *arkClient) GetAddresses(ctx context.Context) (
	onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
	err error,
) {
	if err := a.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err := a.ArkClient.GetAddresses(
		ctx,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddresses = append(onchainAddresses, onchainAddrs...)
	for _, addr := range offchainAddrs {
		offchainAddresses = append(offchainAddresses, addr.Address)
	}
	for _, addr := range boardingAddrs {
		boardingAddresses = append(boardingAddresses, addr.Address)
	}
	for _, addr := range redemptionAddrs {
		redemptionAddresses = append(redemptionAddresses, addr.Address)
	}

	return onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses, nil
}

func (a *arkClient) NewOffchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	_, offchainAddr, _, err := a.Receive(ctx)
	if err != nil {
		return "", err
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return "", err
	}

	onchainAddr, err := toOnchainAddress(offchainAddr.Address, cfg.Network)
	if err != nil {
		return "", err
	}

	if err := a.registerTrackedOnchainAddress(onchainAddr, trackedAddressInfo{
		tapscripts: offchainAddr.Tapscripts,
		delay:      cfg.UnilateralExitDelay,
	}, true, cfg.Network); err != nil {
		return "", err
	}

	return offchainAddr.Address, nil
}

func (a *arkClient) NewBoardingAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	_, _, boardingAddr, err := a.Receive(ctx)
	if err != nil {
		return "", err
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return "", err
	}

	if err := a.registerTrackedOnchainAddress(boardingAddr.Address, trackedAddressInfo{
		tapscripts: boardingAddr.Tapscripts,
		delay:      cfg.BoardingExitDelay,
	}, true, cfg.Network); err != nil {
		return "", err
	}
	return boardingAddr.Address, nil
}

func (a *arkClient) NewOnchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	onchainAddr, _, _, err := a.Receive(ctx)
	if err != nil {
		return "", err
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return "", err
	}

	if err := a.registerTrackedOnchainAddress(onchainAddr, trackedAddressInfo{
		tapscripts: []string{},
		delay:      arklib.RelativeLocktime{},
	}, true, cfg.Network); err != nil {
		return "", err
	}

	return onchainAddr, nil
}

func (a *arkClient) Balance(ctx context.Context) (*client.Balance, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	balance := &client.Balance{
		OnchainBalance: client.OnchainBalance{
			SpendableAmount: 0,
			LockedAmount:    make([]client.LockedOnchainBalance, 0),
		},
		OffchainBalance: client.OffchainBalance{
			Total:          0,
			NextExpiration: "",
			Details:        make([]client.VtxoDetails, 0),
		},
		AssetBalances: make(map[string]uint64, 0),
	}

	// offchain balance
	offchainBalance, amountByExpiration, assetBalances, err := a.getOffchainBalance(ctx)
	if err != nil {
		return nil, err
	}

	nextExpiration, details := getOffchainBalanceDetails(amountByExpiration)
	balance.OffchainBalance.Total = offchainBalance
	balance.OffchainBalance.NextExpiration = getFancyTimeExpiration(nextExpiration)
	balance.OffchainBalance.Details = details
	balance.AssetBalances = assetBalances

	// onchain balance
	utxoStore := a.store.UtxoStore()
	utxos, _, err := utxoStore.GetAllUtxos(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	for _, utxo := range utxos {
		if !utxo.IsConfirmed() {
			continue // TODO handle unconfirmed balance ? (not spendable on ark)
		}

		if now.After(utxo.SpendableAt) {
			balance.OnchainBalance.SpendableAmount += utxo.Amount
			continue
		}

		balance.OnchainBalance.LockedAmount = append(
			balance.OnchainBalance.LockedAmount,
			client.LockedOnchainBalance{
				SpendableAt: utxo.SpendableAt.Format(time.RFC3339),
				Amount:      utxo.Amount,
			},
		)
	}

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

func (a *arkClient) getOffchainBalance(ctx context.Context) (
	balance uint64, amountByExpiration map[int64]uint64,
	assetBalances map[string]uint64, err error,
) {
	assetBalances = make(map[string]uint64, 0)
	amountByExpiration = make(map[int64]uint64, 0)

	vtxos, _, err := a.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return
	}

	for _, vtxo := range vtxos {
		if vtxo.Unrolled {
			continue
		}

		balance += vtxo.Amount

		if !vtxo.ExpiresAt.IsZero() {
			expiration := vtxo.ExpiresAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.Amount
		}

		for _, a := range vtxo.Assets {
			if _, ok := assetBalances[a.AssetId]; !ok {
				assetBalances[a.AssetId] = a.Amount
				continue
			}

			assetBalances[a.AssetId] += a.Amount
		}
	}

	return
}
