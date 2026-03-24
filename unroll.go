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

	vtxos := make([]clientTypes.Vtxo, 0, len(allVtxos))
	for _, vtxo := range allVtxos {
		vtxos = append(vtxos, vtxo.Vtxo)
	}

	res, err := a.ArkClient.Unroll(ctx, client.WithVtxosToUnroll(vtxos))
	if err != nil {
		return err
	}

	for _, rr := range res {
		var parentTx wire.MsgTx
		if err := parentTx.Deserialize(hex.NewDecoder(strings.NewReader(rr.ParentTx))); err != nil {
			return err
		}

		parentTxid := parentTx.TxID()
		vtxosToUpdate := make([]clientTypes.Vtxo, 0, len(vtxos))
		for _, vtxo := range vtxos {
			if vtxo.Txid == parentTxid {
				vtxo.Unrolled = true
				vtxosToUpdate = append(vtxosToUpdate, vtxo)
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
