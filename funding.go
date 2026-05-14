package arksdk

import (
	"context"
	"time"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

func (w *wallet) GetAddresses(ctx context.Context) (
	onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
	err error,
) {
	if err := w.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	cfg, err := w.client.GetConfigData(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddrs, _, _, _, err := w.client.GetAddresses(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	contracts, err := w.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeDefault),
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	boardingContracts, err := w.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeBoarding),
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddresses = make([]string, len(onchainAddrs))
	copy(onchainAddresses, onchainAddrs)

	for _, contract := range contracts {
		offchainAddresses = append(offchainAddresses, contract.Address)
		redemptionAddresses = append(redemptionAddresses, toOnchainAddress(
			contract.Address, cfg.Network,
		))
	}
	for _, contract := range boardingContracts {
		boardingAddresses = append(boardingAddresses, contract.Address)
	}

	return
}

func (w *wallet) NewOffchainAddress(ctx context.Context) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}
	return w.newOffchainAddress(ctx)
}

func (w *wallet) NewBoardingAddress(ctx context.Context) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	contract, err := w.contractManager.NewContract(
		ctx, types.ContractTypeBoarding,
	)
	if err != nil {
		return "", err
	}

	go func() {
		if err := w.Explorer().SubscribeForAddresses([]string{contract.Address}); err != nil {
			log.WithError(err).Error("failed to subscribe for boarding address")
		}
	}()
	return contract.Address, nil
}

func (w *wallet) NewOnchainAddress(ctx context.Context) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	onchainAddr, _, _, err := w.client.Receive(ctx)
	if err != nil {
		return "", err
	}

	// listenForOnchainTxs only subscribes to boarding and offchain-translated
	// addresses at startup; plain onchain addresses from Receive() aren't
	// in either set, so faucet deposits to them wouldn't surface as UTXO
	// events. Subscribe here so the wallet's onchain pipeline tracks them too.
	go func() {
		if err := w.Explorer().SubscribeForAddresses([]string{onchainAddr}); err != nil {
			log.WithError(err).Warn("failed to subscribe for onchain address")
		}
	}()

	return onchainAddr, nil
}

func (w *wallet) Balance(ctx context.Context) (*types.Balance, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	// offchain balance
	offchainBalance, assetsBalance, err := w.getOffchainBalance(ctx)
	if err != nil {
		return nil, err
	}

	onchainBalance, err := w.getOnchainBalance(ctx)
	if err != nil {
		return nil, err
	}

	return &types.Balance{
		OnchainBalance:  *onchainBalance,
		OffchainBalance: *offchainBalance,
		AssetBalances:   assetsBalance,
		Total:           onchainBalance.Total + offchainBalance.Total,
	}, nil
}

func (w *wallet) ListSpendableVtxos(ctx context.Context) ([]clienttypes.Vtxo, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	return w.store.VtxoStore().GetSpendableVtxos(ctx)
}

func (w *wallet) ListVtxos(
	ctx context.Context,
) ([]clienttypes.Vtxo, []clienttypes.Vtxo, error) {
	if err := w.safeCheck(); err != nil {
		return nil, nil, err
	}

	return w.store.VtxoStore().GetAllVtxos(ctx)
}

func (w *wallet) NotifyIncomingFunds(
	ctx context.Context, addr string,
) ([]clienttypes.Vtxo, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}
	return w.client.NotifyIncomingFunds(ctx, addr)
}

func (w *wallet) newOffchainAddress(ctx context.Context) (string, error) {
	contract, err := w.contractManager.NewContract(ctx, types.ContractTypeDefault)
	if err != nil {
		return "", err
	}

	return contract.Address, nil
}

func (w *wallet) getOffchainBalance(
	ctx context.Context,
) (*types.OffchainBalance, map[string]uint64, error) {
	vtxos, _, err := w.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return nil, nil, err
	}

	var (
		settledBalance      uint64
		preconfirmedBalance uint64
		recoverableBalance  uint64
		assetsBalance       = make(map[string]uint64)
		amountByExpiration  = make(map[int64]uint64)
	)
	for _, vtxo := range vtxos {
		if vtxo.Spent || vtxo.Unrolled {
			continue
		}

		// Classify VTXO by state. Priority: Recoverable > Preconfirmed > default.
		switch {
		case vtxo.IsRecoverable():
			recoverableBalance += vtxo.Amount
		case vtxo.Preconfirmed:
			preconfirmedBalance += vtxo.Amount
		default:
			settledBalance += vtxo.Amount
		}

		if !vtxo.ExpiresAt.IsZero() {
			expiration := vtxo.ExpiresAt.Unix()

			if _, ok := amountByExpiration[expiration]; !ok {
				amountByExpiration[expiration] = 0
			}

			amountByExpiration[expiration] += vtxo.Amount
		}

		for _, a := range vtxo.Assets {
			if _, ok := assetsBalance[a.AssetId]; !ok {
				assetsBalance[a.AssetId] = a.Amount
				continue
			}

			assetsBalance[a.AssetId] += a.Amount
		}
	}

	nextExpiration, details := getOffchainBalanceDetails(amountByExpiration)
	balance := &types.OffchainBalance{
		Settled:        settledBalance,
		Preconfirmed:   preconfirmedBalance,
		Recoverable:    recoverableBalance,
		Available:      settledBalance + preconfirmedBalance,
		Total:          settledBalance + preconfirmedBalance + recoverableBalance,
		Details:        details,
		NextExpiration: getFancyTimeExpiration(nextExpiration),
	}
	return balance, assetsBalance, nil
}

func (w *wallet) getOnchainBalance(ctx context.Context) (*types.OnchainBalance, error) {
	// onchain balance
	utxos, _, err := w.store.UtxoStore().GetAllUtxos(ctx)
	if err != nil {
		return nil, err
	}

	var (
		now                       = time.Now()
		onchainUnconfirmedBalance uint64
		onchainConfirmedBalance   uint64
		onchainMatureBalance      uint64
		onchainLockedBalance      = make([]types.LockedOnchainBalance, 0)
	)
	for _, utxo := range utxos {
		if !utxo.IsConfirmed() {
			onchainUnconfirmedBalance += utxo.Amount
			continue
		}

		onchainConfirmedBalance += utxo.Amount
		if now.After(utxo.SpendableAt) {
			onchainMatureBalance += utxo.Amount
			continue
		}

		onchainLockedBalance = append(
			onchainLockedBalance,
			types.LockedOnchainBalance{
				SpendableAt: utxo.SpendableAt.Format(time.RFC3339),
				Amount:      utxo.Amount,
			},
		)
	}

	return &types.OnchainBalance{
		Confirmed:       onchainConfirmedBalance,
		Unconfirmed:     onchainUnconfirmedBalance,
		Total:           onchainUnconfirmedBalance + onchainConfirmedBalance,
		SpendableAmount: onchainMatureBalance,
		LockedAmount:    onchainLockedBalance,
	}, nil
}
