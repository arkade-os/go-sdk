package arksdk

import (
	"context"
	"time"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

func (a *arkClient) GetAddresses(ctx context.Context) (
	onchainAddresses []string,
	offchainAddresses, boardingAddresses, redemptionAddresses []clientTypes.Address,
	err error,
) {
	if err := a.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddrs, _, _, _, err := a.ArkClient.GetAddresses(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	contracts, err := a.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeDefault),
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	boardingContracts, err := a.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeBoarding),
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	onchainAddresses = make([]string, len(onchainAddrs))
	copy(onchainAddresses, onchainAddrs)

	for _, c := range contracts {
		handler, err := a.contractManager.GetHandler(ctx, c)
		if err != nil {
			log.WithError(err).Warnf("skipping contract %s: failed to get handler", c.Script)
			continue
		}
		tapscripts, err := handler.GetTapscripts(c)
		if err != nil {
			log.WithError(err).Warnf("skipping contract %s: failed to get tapscripts", c.Script)
			continue
		}
		keyRef, err := handler.GetKeyRef(c)
		if err != nil {
			log.WithError(err).Warnf("skipping contract %s: failed to get key ref", c.Script)
			continue
		}
		addr := clientTypes.Address{
			KeyID:      keyRef.Id,
			Tapscripts: tapscripts,
			Address:    c.Address,
		}
		offchainAddresses = append(offchainAddresses, addr)
		redemptionAddresses = append(redemptionAddresses, clientTypes.Address{
			KeyID:      keyRef.Id,
			Tapscripts: tapscripts,
			Address:    toOnchainAddress(c.Address, cfg.Network),
		})
	}
	for _, c := range boardingContracts {
		handler, err := a.contractManager.GetHandler(ctx, c)
		if err != nil {
			log.WithError(err).
				Warnf("skipping boarding contract %s: failed to get handler", c.Script)
			continue
		}
		tapscripts, err := handler.GetTapscripts(c)
		if err != nil {
			log.WithError(err).Warnf(
				"skipping boarding contract %s: failed to get tapscripts", c.Script,
			)
			continue
		}
		keyRef, err := handler.GetKeyRef(c)
		if err != nil {
			log.WithError(err).Warnf(
				"skipping boarding contract %s: failed to get key ref", c.Script,
			)
			continue
		}
		boardingAddresses = append(boardingAddresses, clientTypes.Address{
			KeyID:      keyRef.Id,
			Tapscripts: tapscripts,
			Address:    c.Address,
		})
	}

	return
}

func (a *arkClient) NewOffchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	return a.newOffchainAddress(ctx)
}

func (a *arkClient) NewBoardingAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	contract, err := a.contractManager.NewContract(
		ctx, types.ContractTypeBoarding,
	)
	if err != nil {
		return "", err
	}

	go func() {
		if err := a.Explorer().SubscribeForAddresses([]string{contract.Address}); err != nil {
			log.WithError(err).Error("failed to subscribe for boarding address")
		}
	}()
	return contract.Address, nil
}

func (a *arkClient) NewOnchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	onchainAddr, _, _, err := a.Receive(ctx)
	return onchainAddr, err
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

func (a *arkClient) newOffchainAddress(ctx context.Context) (string, error) {
	contract, err := a.contractManager.NewContract(ctx, types.ContractTypeDefault)
	if err != nil {
		return "", err
	}

	return contract.Address, nil
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
