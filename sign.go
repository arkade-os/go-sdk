package arksdk

import (
	"context"
	"time"

	client "github.com/arkade-os/arkd/pkg/client-lib"
)

func (a *arkClient) SignTransaction(ctx context.Context, tx string) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	return a.ArkClient.SignTransaction(ctx, tx, client.WithKeys(signingKeys))
}

func (a *arkClient) FinalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	return a.finalizePendingTxs(ctx, createdAfter)
}

func (a *arkClient) finalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return nil, err
	}

	txids, err := a.ArkClient.FinalizePendingTxs(ctx, createdAfter, client.WithKeys(signingKeys))
	if err != nil {
		return nil, err
	}

	if len(txids) == 0 {
		return nil, nil
	}

	if err := a.refreshDb(ctx); err != nil {
		return nil, err
	}

	return txids, nil
}
