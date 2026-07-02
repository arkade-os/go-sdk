package arksdk

import (
	"context"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
)

func (w *wallet) getSigningKeyRefs(
	ctx context.Context, vtxos []clienttypes.VtxoWithTapTree, utxos []clienttypes.Utxo,
) (map[string]string, error) {
	vtxoKeys, err := w.getKeysForVtxos(ctx, vtxos)
	if err != nil {
		return nil, err
	}
	utxoKeys, err := w.getKeysForUtxos(ctx, utxos)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]string)
	for k, v := range vtxoKeys {
		keys[k] = v
	}
	for k, v := range utxoKeys {
		keys[k] = v
	}
	return keys, nil
}

func (w *wallet) getKeysForVtxos(
	ctx context.Context, vtxos []clienttypes.VtxoWithTapTree,
) (map[string]string, error) {
	if len(vtxos) == 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(vtxos))
	for _, vtxo := range vtxos {
		scripts = append(scripts, vtxo.Script)
	}
	return w.getKeys(ctx, scripts)
}

func (w *wallet) getKeysForUtxos(
	ctx context.Context, utxos []clienttypes.Utxo,
) (map[string]string, error) {
	if len(utxos) == 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(utxos))
	for _, utxo := range utxos {
		scripts = append(scripts, utxo.Script)
	}
	return w.getKeys(ctx, scripts)
}

func (w *wallet) getKeys(ctx context.Context, scripts []string) (map[string]string, error) {
	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	keys := make(map[string]string)
	if err := w.addContractKeys(ctx, keys, contracts, nil); err != nil {
		return nil, err
	}

	missing := missingScripts(keys, scripts)
	if len(missing) == 0 {
		return keys, nil
	}

	contracts, err = w.contractManager.GetContracts(ctx)
	if err != nil {
		return nil, err
	}
	if err := w.addContractKeys(ctx, keys, contracts, missing); err != nil {
		return nil, err
	}
	return keys, nil
}

func (w *wallet) addContractKeys(
	ctx context.Context,
	keys map[string]string,
	contracts []types.Contract,
	only map[string]struct{},
) error {
	for _, contract := range contracts {
		handler, err := w.contractManager.GetHandler(ctx, contract)
		if err != nil {
			return err
		}
		contractKeys, err := handler.GetKeyRefs(contract)
		if err != nil {
			return err
		}
		for k, v := range contractKeys {
			if only != nil {
				if _, ok := only[k]; !ok {
					continue
				}
			}
			keys[k] = v
		}
	}
	return nil
}

func missingScripts(keys map[string]string, scripts []string) map[string]struct{} {
	missing := make(map[string]struct{})
	for _, script := range scripts {
		if _, ok := keys[script]; !ok {
			missing[script] = struct{}{}
		}
	}
	return missing
}
