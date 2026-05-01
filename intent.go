package arksdk

import (
	"context"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

func (a *arkClient) RegisterIntent(
	ctx context.Context,
	vtxos []clientTypes.Vtxo,
	boardingUtxos []clientTypes.Utxo,
	notes []string,
	outputs []clientTypes.Receiver,
	cosignersPublicKeys []string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	return a.ArkClient.RegisterIntent(
		ctx,
		vtxos,
		boardingUtxos,
		notes,
		outputs,
		cosignersPublicKeys,
		client.WithKeys(signingKeys),
	)
}

func (a *arkClient) DeleteIntent(
	ctx context.Context,
	vtxos []clientTypes.Vtxo,
	boardingUtxos []clientTypes.Utxo,
	notes []string,
) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return err
	}

	return a.ArkClient.DeleteIntent(
		ctx,
		vtxos,
		boardingUtxos,
		notes,
		client.WithKeys(signingKeys),
	)
}
