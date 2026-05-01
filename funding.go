package arksdk

import (
	"context"
	"strconv"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

func (a *arkClient) GetAddresses(ctx context.Context) (
	onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
	err error,
) {
	if err := a.safeCheck(); err != nil {
		return nil, nil, nil, nil, err
	}

	return a.getAllocatedAddresses(ctx)
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

// TODO: Drop me in https://github.com/arkade-os/go-sdk/pull/145
func (a *arkClient) getAllocatedAddresses(ctx context.Context) (
	onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
	err error,
) {
	keyRefs, err := a.Wallet().ListKeys(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	nextIndex, err := a.Wallet().NextIndex(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	data, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for _, keyRef := range keyRefs {
		if getIndex(keyRef.Id) >= nextIndex {
			continue
		}
		onchainAddr, offchainAddr, boardingAddr, redemptionAddr, err := a.deriveDefaultAddresses(
			keyRef, data,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		onchainAddresses = append(onchainAddresses, onchainAddr)
		offchainAddresses = append(offchainAddresses, offchainAddr.Address)
		boardingAddresses = append(boardingAddresses, boardingAddr.Address)
		redemptionAddresses = append(redemptionAddresses, redemptionAddr.Address)
	}
	return
}

func (a *arkClient) deriveDefaultAddresses(
	key wallet.KeyRef, data *clientTypes.Config,
) (onchainAddr string, offchainAddr, boardingAddr, redemptionAddr *clientTypes.Address, err error) {
	netParams := toBitcoinNetwork(data.Network)

	defaultVtxoScript := script.NewDefaultVtxoScript(
		key.PubKey, data.SignerPubKey, data.UnilateralExitDelay,
	)
	vtxoTapKey, _, err := defaultVtxoScript.TapTree()
	if err != nil {
		return "", nil, nil, nil, err
	}

	offchainAddress := &arklib.Address{
		HRP:        data.Network.Addr,
		Signer:     data.SignerPubKey,
		VtxoTapKey: vtxoTapKey,
	}
	encodedOffchainAddr, err := offchainAddress.EncodeV0()
	if err != nil {
		return "", nil, nil, nil, err
	}

	tapscripts, err := defaultVtxoScript.Encode()
	if err != nil {
		return "", nil, nil, nil, err
	}

	boardingVtxoScript := script.NewDefaultVtxoScript(
		key.PubKey, data.SignerPubKey, data.BoardingExitDelay,
	)
	boardingTapKey, _, err := boardingVtxoScript.TapTree()
	if err != nil {
		return "", nil, nil, nil, err
	}

	boardingTaprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(boardingTapKey), &netParams,
	)
	if err != nil {
		return "", nil, nil, nil, err
	}

	boardingTapscripts, err := boardingVtxoScript.Encode()
	if err != nil {
		return "", nil, nil, nil, err
	}

	redemptionTaprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey), &netParams,
	)
	if err != nil {
		return "", nil, nil, nil, err
	}

	onchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
	onchainTaprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(onchainTapKey), &netParams,
	)
	if err != nil {
		return "", nil, nil, nil, err
	}

	onchainAddr = onchainTaprootAddr.EncodeAddress()
	offchainAddr = &clientTypes.Address{
		KeyID:      key.Id,
		Tapscripts: tapscripts,
		Address:    encodedOffchainAddr,
	}
	boardingAddr = &clientTypes.Address{
		KeyID:      key.Id,
		Tapscripts: boardingTapscripts,
		Address:    boardingTaprootAddr.EncodeAddress(),
	}
	redemptionAddr = &clientTypes.Address{
		KeyID:      key.Id,
		Tapscripts: tapscripts,
		Address:    redemptionTaprootAddr.EncodeAddress(),
	}

	return
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

		// Classify VTXO by state. Priority: Recoverable > Preconfirmed > default.
		switch {
		case vtxo.IsRecoverable():
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

func getIndex(path string) uint32 {
	str := strings.Split(path, "/")
	idx, _ := strconv.ParseUint(str[len(str)-1], 10, 32)
	return uint32(idx)
}
