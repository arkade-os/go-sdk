package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

func (a *arkClient) Unroll(ctx context.Context) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	allVtxos, err := a.getSpendableVtxos(ctx, false)
	if err != nil {
		return err
	}

	if len(allVtxos) == 0 {
		return fmt.Errorf("no vtxos to unroll")
	}

	res, err := a.ArkClient.Unroll(ctx, client.WithVtxos(allVtxos))
	if err != nil {
		return err
	}

	for _, rr := range res {
		var parentTx wire.MsgTx
		if err := parentTx.Deserialize(hex.NewDecoder(strings.NewReader(rr.ParentTx))); err != nil {
			return err
		}

		parentTxid := parentTx.TxID()
		vtxosToUpdate := make([]clientTypes.Vtxo, 0, len(allVtxos))
		for _, vtxo := range allVtxos {
			if vtxo.Txid == parentTxid {
				v := vtxo.Vtxo
				v.Unrolled = true
				vtxosToUpdate = append(vtxosToUpdate, v)
			}
		}
		count, err := a.store.VtxoStore().UnrollVtxos(ctx, vtxosToUpdate)
		if err != nil {
			return fmt.Errorf("failed to update vtxos: %w", err)
		}
		if count > 0 {
			log.Debugf("unrolled %d vtxos", count)
		}
	}
	return nil
}

func (a *arkClient) CompleteUnroll(ctx context.Context, to string) (string, error) {
	return a.ArkClient.CompleteUnroll(ctx, to)
}

func (a *arkClient) OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error) {
	return a.ArkClient.OnboardAgainAllExpiredBoardings(ctx)
}

func (a *arkClient) WithdrawFromAllExpiredBoardings(
	ctx context.Context,
	to string,
) (string, error) {
	return a.ArkClient.WithdrawFromAllExpiredBoardings(ctx, to)
}
