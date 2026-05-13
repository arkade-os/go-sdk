package arksdk

import (
	"context"
	"time"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
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
	return onchainAddr, err
}

func (w *wallet) Balance(ctx context.Context) (*clientwallet.Balance, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	balance := &clientwallet.Balance{
		OnchainBalance: clientwallet.OnchainBalance{
			SpendableAmount: 0,
			LockedAmount:    make([]clientwallet.LockedOnchainBalance, 0),
		},
		OffchainBalance: clientwallet.OffchainBalance{
			Total:          0,
			NextExpiration: "",
			Details:        make([]clientwallet.VtxoDetails, 0),
		},
		AssetBalances: make(map[string]uint64, 0),
	}

	// offchain balance
	offchainBalance, amountByExpiration, assetBalances, err := w.getOffchainBalance(ctx)
	if err != nil {
		return nil, err
	}

	nextExpiration, details := getOffchainBalanceDetails(amountByExpiration)
	balance.OffchainBalance.Total = offchainBalance
	balance.OffchainBalance.NextExpiration = getFancyTimeExpiration(nextExpiration)
	balance.OffchainBalance.Details = details
	balance.AssetBalances = assetBalances

	// onchain balance
	utxoStore := w.store.UtxoStore()
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
			clientwallet.LockedOnchainBalance{
				SpendableAt: utxo.SpendableAt.Format(time.RFC3339),
				Amount:      utxo.Amount,
			},
		)
	}

	return balance, nil
}

func (w *wallet) ListSpendableVtxos(ctx context.Context) ([]clienttypes.Vtxo, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	// TODO: add safe check
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

func (w *wallet) getOffchainBalance(ctx context.Context) (
	balance uint64, amountByExpiration map[int64]uint64,
	assetBalances map[string]uint64, err error,
) {
	assetBalances = make(map[string]uint64, 0)
	amountByExpiration = make(map[int64]uint64, 0)

	vtxos, _, err := w.store.VtxoStore().GetAllVtxos(ctx)
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
