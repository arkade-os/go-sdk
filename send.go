package arksdk

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
)

func (a *arkClient) SendOffChain(
	ctx context.Context, receivers []clientTypes.Receiver,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := a.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", err
	}

	return a.sendOffChain(ctx, receivers, vtxos, false)
}

func (a *arkClient) sendOffChain(
	ctx context.Context,
	receivers []clientTypes.Receiver, vtxos []clientTypes.VtxoWithTapTree, selfSend bool,
) (string, error) {
	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return "", err
	}

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	// ensure asset-carrying receivers have at least dust sats as a carrier
	clone := make([]clientTypes.Receiver, len(receivers))
	copy(clone, receivers)
	dust := cfg.Dust
	for i, receiver := range clone {
		if len(receiver.Assets) > 0 && receiver.Amount < dust {
			clone[i].Amount = dust
		}
	}

	res, err := a.ArkClient.SendOffChain(
		ctx,
		clone,
		client.WithVtxos(vtxos),
		client.WithKeys(signingKeys),
	)
	if err != nil {
		return "", err
	}

	if selfSend {
		res.Outputs = receivers
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := a.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
}

func (a *arkClient) getSpendableVtxos(
	ctx context.Context, withRecoverable bool,
) ([]clientTypes.VtxoWithTapTree, error) {
	a.dbMu.Lock()
	spendableVtxos, err := a.store.VtxoStore().GetSpendableVtxos(ctx)
	a.dbMu.Unlock()
	if err != nil {
		return nil, err
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}

	offchainAddrs, err := a.getAddresses(ctx, cfg)
	if err != nil {
		return nil, err
	}

	vtxos := make([]clientTypes.VtxoWithTapTree, 0, len(spendableVtxos))
	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			if v.Unrolled || (!withRecoverable && v.IsRecoverable()) {
				continue
			}

			vtxoAddr, err := v.Address(offchainAddr.SignerPubKey, cfg.Network)
			if err != nil {
				return nil, err
			}

			if vtxoAddr == offchainAddr.Address.Address {
				vtxos = append(vtxos, clientTypes.VtxoWithTapTree{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
			}
		}
	}

	return vtxos, nil
}

type addressWithSignerkey struct {
	clientTypes.Address
	SignerPubKey *btcec.PublicKey
}

func (a *arkClient) getAddresses(
	ctx context.Context, cfgData *clientTypes.Config,
) ([]addressWithSignerkey, error) {
	keys := make([]wallet.KeyRef, 0)
	seenKeys := make(map[string]struct{})

	keyRefs, err := a.Wallet().ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	for _, key := range keyRefs {
		if _, ok := seenKeys[key.Id]; ok {
			continue
		}
		seenKeys[key.Id] = struct{}{}
		keys = append(keys, key)
	}

	signerKeys := []*btcec.PublicKey{cfgData.SignerPubKey}
	for _, ds := range cfgData.DeprecatedSigners {
		signerKeys = append(signerKeys, ds.PubKey)
	}

	offchainAddrs := make([]addressWithSignerkey, 0, len(keys))
	for _, key := range keys {
		for _, signerKey := range signerKeys {
			defaultVtxoScript := script.NewDefaultVtxoScript(
				key.PubKey, signerKey, cfgData.UnilateralExitDelay,
			)
			vtxoTapKey, _, err := defaultVtxoScript.TapTree()
			if err != nil {
				return nil, err
			}

			offchainAddress := &arklib.Address{
				HRP:        cfgData.Network.Addr,
				Signer:     signerKey,
				VtxoTapKey: vtxoTapKey,
			}
			encodedOffchainAddr, err := offchainAddress.EncodeV0()
			if err != nil {
				return nil, err
			}

			tapscripts, err := defaultVtxoScript.Encode()
			if err != nil {
				return nil, err
			}

			offchainAddrs = append(offchainAddrs, addressWithSignerkey{
				Address: clientTypes.Address{
					KeyID:      key.Id,
					Tapscripts: tapscripts,
					Address:    encodedOffchainAddr,
				},
				SignerPubKey: signerKey,
			})
		}
	}

	return offchainAddrs, nil
}
