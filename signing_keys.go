package arksdk

import (
	"context"
	"encoding/hex"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
)

func (a *arkClient) getSigningKeyRefs(
	ctx context.Context, vtxos []clientTypes.VtxoWithTapTree, utxos []clientTypes.Utxo,
) (map[string]string, error) {
	keys, err := a.getKeysForVtxos(ctx, vtxos)
	if err != nil {
		return nil, err
	}
	utxoKeys, err := a.getKeysForUtxos(ctx, utxos)
	if err != nil {
		return nil, err
	}

	for k, v := range utxoKeys {
		keys[k] = v
	}
	return keys, nil
}

func (a *arkClient) getKeysForVtxos(
	ctx context.Context, vtxos []clientTypes.VtxoWithTapTree,
) (map[string]string, error) {
	scripts := make([]string, 0, len(vtxos))
	for _, vtxo := range vtxos {
		scripts = append(scripts, vtxo.Script)
	}
	return a.getKeys(ctx, scripts)
}

func (a *arkClient) getKeysForUtxos(ctx context.Context, utxos []clientTypes.Utxo) (map[string]string, error) {
	scripts := make([]string, 0, len(utxos))
	for _, utxo := range utxos {
		scripts = append(scripts, utxo.Script)
	}
	return a.getKeys(ctx, scripts)
}

func (a *arkClient) getKeys(ctx context.Context, scripts []string) (map[string]string, error) {
	var opts []contract.FilterOption
	if len(scripts) > 0 {
		opts = append(opts, contract.WithScripts(scripts))
	}

	contracts, err := a.contractManager.GetContracts(ctx, opts...)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]string)
	for _, contract := range contracts {
		contractKeys, err := a.contractManager.GetKeyRefs(ctx, contract)
		if err != nil {
			return nil, err
		}
		for k, v := range contractKeys {
			keys[k] = v
		}
	}
	return keys, nil
}

func addSigningKeyForOnchainAddress(
	keys map[string]string,
	address, keyID string,
	network arklib.Network,
) error {
	if keyID == "" {
		return nil
	}

	script, err := toOutputScript(address, network)
	if err != nil {
		return err
	}

	keys[hex.EncodeToString(script)] = keyID
	return nil
}
