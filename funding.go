package arksdk

import (
	"context"
	"fmt"
	"time"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	log "github.com/sirupsen/logrus"
)

var errContractManagerNotReady = fmt.Errorf("contract manager not ready")

func (a *arkClient) NewOffchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	if a.contractManager == nil {
		return "", errContractManagerNotReady
	}
	c, err := a.contractManager.NewDefault(ctx)
	if err != nil {
		return "", err
	}
	return c.Address, nil
}

func (a *arkClient) NewBoardingAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	if a.contractManager == nil {
		return "", errContractManagerNotReady
	}
	primary, err := a.contractManager.NewDefault(ctx)
	if err != nil {
		return "", err
	}
	keyID := primary.Params[contract.ParamKeyID]
	boardingType := contract.TypeDefaultBoarding
	contracts, err := a.contractManager.GetContracts(ctx,
		contract.WithType(boardingType),
		contract.WithKeyID(keyID),
	)
	if err != nil {
		return "", err
	}
	if len(contracts) == 0 {
		return "", fmt.Errorf("no boarding contract for key %s", keyID)
	}
	addr := contracts[0].Address
	go func() {
		if err := a.Explorer().SubscribeForAddresses([]string{addr}); err != nil {
			log.WithError(err).Error("failed to subscribe for boarding address")
		}
	}()
	return addr, nil
}

func (a *arkClient) NewOnchainAddress(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}
	if a.contractManager == nil {
		return "", errContractManagerNotReady
	}
	primary, err := a.contractManager.NewDefault(ctx)
	if err != nil {
		return "", err
	}
	keyID := primary.Params[contract.ParamKeyID]
	onchainType := contract.TypeDefaultOnchain
	contracts, err := a.contractManager.GetContracts(ctx,
		contract.WithType(onchainType),
		contract.WithKeyID(keyID),
	)
	if err != nil {
		return "", err
	}
	if len(contracts) == 0 {
		return "", fmt.Errorf("no onchain contract for key %s", keyID)
	}
	return contracts[0].Address, nil
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
