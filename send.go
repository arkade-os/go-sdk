package arksdk

import (
	"context"
	"sort"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

func (w *wallet) SendOffChain(
	ctx context.Context, receivers []clienttypes.Receiver,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	// Synchronize: wait for any in-flight spend to finish, then proceed
	// with fresh VTXOs.
	send := func() (any, error) {
		vtxos, err := w.getSpendableVtxos(ctx, false)
		if err != nil {
			return nil, err
		}

		signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
		if err != nil {
			return nil, err
		}

		// Ensure asset-carrying receivers have at least dust sats as a carrier
		clone := make([]clienttypes.Receiver, len(receivers))
		copy(clone, receivers)
		for i, receiver := range clone {
			if len(receiver.Assets) > 0 && receiver.Amount < w.dustAmount {
				clone[i].Amount = w.dustAmount
			}
		}

		opts := []clientwallet.SendOption{
			clientwallet.WithVtxos(vtxos),
			clientwallet.WithKeys(signingKeyRefs),
		}

		outAmount := uint64(0)
		for _, r := range clone {
			outAmount += r.Amount
		}
		inAmount := uint64(0)
		for _, v := range vtxos {
			inAmount += v.Amount
		}
		var changeAddr string
		if inAmount > outAmount {
			changeAddr, err = w.newOffchainAddress(ctx)
			if err != nil {
				return nil, err
			}
			opts = append(opts, clientwallet.WithReceiver(changeAddr))
		}

		// Subscribe to the change address before submitting so we don't miss
		// the indexer notification once the server tracks the tx.
		var tracked <-chan error
		if changeAddr != "" {
			var cancel context.CancelFunc
			tracked, cancel = w.notifyTracked(ctx, changeAddr)
			defer cancel()
		}

		res, err := w.client.SendOffChain(ctx, clone, opts...)
		if err != nil {
			return nil, err
		}

		// Persist within the critical section so the next queued operation
		// sees the spent VTXOs and freshly created change before it runs.
		if err := w.saveSendTransaction(ctx, *res); err != nil {
			return nil, err
		}

		// Wait until the server/indexer has tracked our change before releasing
		// the slot, so the next queued operation can spend it without hitting
		// VTXO_NOT_FOUND.
		if tracked != nil {
			if err := <-tracked; err != nil {
				return nil, err
			}
		}
		return res.Txid, nil
	}

	rr, err := w.txHandler.handleTx(send)
	if err != nil {
		return "", err
	}

	return rr.(string), nil
}

// buildConsolidatedReceiver constructs the SINGLE Receiver that consolidates an
// entire set of migrated vtxos into one current-signer output (destAddr): all
// BTC and every asset collapse into one vtxo.
//
// Receiver.Amount is the exact sum of v.Amount across ALL vtxos in the set. For
// a pure-sats vtxo that is its balance; for an asset-carrying vtxo v.Amount is
// the BTC "carrier" dust that rides along with the asset. Summing every input's
// sats makes the migration a balanced exact self-send (input sats == output
// sats), so the client-lib coin selection produces no change output (see
// createOffchainTx: btcAmountToSelect reaches exactly zero once the pinned
// inputs are consumed). Dropping any carrier would be silent sat loss, so the
// full sum is mandatory.
//
// Receiver.Assets has one entry per distinct assetId present across all inputs,
// each with Amount = sum of that asset's amounts across every input that carries
// it. A single vtxo carrying N distinct assets contributes to all N entries; an
// assetId carried by several vtxos is summed into one entry. createAssetPacket
// balances purely on per-assetId input/output totals, so one receiver declaring
// every assetId emits a balanced packet (inputs == outputs per asset) and no
// asset value is stripped. The entries are sorted by assetId for a deterministic
// output. When the input set carries no assets the result is a pure-sats
// receiver with a nil Assets slice.
//
// dustAmount is the per-output protocol floor: if the summed sats ever fall
// below it (defensive — a migration batch is normally well above dust), Amount
// is raised to the floor so the output is not sub-dust.
func buildConsolidatedReceiver(
	vtxos []clienttypes.VtxoWithTapTree, destAddr string, dustAmount uint64,
) clienttypes.Receiver {
	var amount uint64
	totals := make(map[string]uint64)
	for _, v := range vtxos {
		amount += v.Amount
		for _, a := range v.Assets {
			totals[a.AssetId] += a.Amount
		}
	}

	if amount < dustAmount {
		amount = dustAmount
	}

	if len(totals) == 0 {
		// No assets in the batch: a plain sats consolidation, no Assets declared.
		return clienttypes.Receiver{To: destAddr, Amount: amount}
	}

	ids := make([]string, 0, len(totals))
	for id := range totals {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic asset ordering on the receiver
	assets := make([]clienttypes.Asset, 0, len(ids))
	for _, id := range ids {
		assets = append(assets, clienttypes.Asset{AssetId: id, Amount: totals[id]})
	}

	return clienttypes.Receiver{To: destAddr, Amount: amount, Assets: assets}
}

// sendOffchainConsolidated migrates a set of vtxos onto the given receiver (a
// fresh current-signer destination consolidating the whole batch) via the
// SubmitTx/FinalizeTx (SendOffChain) path. It is the safeCheck-free counterpart
// of the public SendOffChain, mirroring the settle/Settle split: it is
// unexported and called ONLY from reconcileDeprecatedSigners, which runs
// synchronously during Unlock — BEFORE the wallet is marked synced — so it must
// bypass safeCheck (which would otherwise return ErrIsSyncing and silently skip
// the migration).
//
// The input vtxos are pinned explicitly via clientwallet.WithVtxos, bypassing
// the client-lib auto coin-selection (which would only pick current-signer
// vtxos and never the deprecated-signer set we are migrating). The receiver
// commits to the current signer (newOffchainAddress → NewContract under the
// current signer), satisfying the arkd #822 invariant. The receiver also
// declares the per-asset totals so createAssetPacket emits a balanced packet
// (inputs == outputs per asset) and no asset value is stripped.
func (w *wallet) sendOffchainConsolidated(
	ctx context.Context,
	vtxos []clienttypes.VtxoWithTapTree,
	receiver clienttypes.Receiver,
) (string, error) {
	if len(vtxos) == 0 {
		return "", nil
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	// Subscribe to the destination address before submitting so we don't miss
	// the indexer notification once the server tracks the migrated vtxo.
	tracked, cancel := w.notifyTracked(ctx, receiver.To)
	defer cancel()

	res, err := w.client.SendOffChain(
		ctx,
		[]clienttypes.Receiver{receiver},
		clientwallet.WithVtxos(vtxos),
		clientwallet.WithKeys(signingKeyRefs),
	)
	if err != nil {
		return "", err
	}

	if err := w.saveSendTransaction(ctx, withMigrationOutput(*res, receiver)); err != nil {
		return "", err
	}

	if tracked != nil {
		if err := <-tracked; err != nil {
			return "", err
		}
	}

	return res.Txid, nil
}

func withMigrationOutput(
	res clientwallet.OffchainTxRes, receiver clienttypes.Receiver,
) clientwallet.OffchainTxRes {
	for _, output := range res.Outputs {
		if sameReceiver(output, receiver) {
			return res
		}
	}

	res.Outputs = append(res.Outputs, receiver)
	return res
}

func sameReceiver(a, b clienttypes.Receiver) bool {
	if a.To != b.To || a.Amount != b.Amount || len(a.Assets) != len(b.Assets) {
		return false
	}

	for i := range a.Assets {
		if a.Assets[i] != b.Assets[i] {
			return false
		}
	}
	return true
}

// sendOffchain migrates the given deprecated-signer vtxos onto current-signer
// outputs via the SubmitTx/FinalizeTx (SendOffChain) path, consolidating the
// WHOLE set into ONE output: all BTC plus every asset collapse into a single
// vtxo at one fresh current-signer address (buildConsolidatedReceiver +
// sendOffchainConsolidated), honoring the arkd #822 invariant. Asset-bearing
// vtxos migrate with Receiver.Assets populated so no asset value is stripped.
//
// This is the safeCheck-bypass entry exercised by the unit test; the empty-slice
// case is a no-op ("", nil). The caller (reconcileDeprecatedSigners) performs the
// same single send directly so it can inactivate the migrated contracts only
// after the send succeeds.
func (w *wallet) sendOffchain(
	ctx context.Context, toMigrate []clienttypes.VtxoWithTapTree,
) (string, error) {
	if len(toMigrate) == 0 {
		return "", nil
	}

	destAddr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	receiver := buildConsolidatedReceiver(toMigrate, destAddr, w.dustAmount)
	return w.sendOffchainConsolidated(ctx, toMigrate, receiver)
}

func (w *wallet) getSpendableVtxos(
	ctx context.Context, withRecoverable bool,
) ([]clienttypes.VtxoWithTapTree, error) {
	w.dbMu.Lock()
	spendableVtxos, err := w.store.VtxoStore().GetSpendableOrRecoverableVtxos(ctx)
	w.dbMu.Unlock()
	if err != nil {
		return nil, err
	}

	eligible := make([]clienttypes.Vtxo, 0, len(spendableVtxos))
	scripts := make([]string, 0, len(spendableVtxos))
	for _, v := range spendableVtxos {
		if v.Unrolled || (!withRecoverable && v.IsRecoverable()) {
			continue
		}
		eligible = append(eligible, v)
		scripts = append(scripts, v.Script)
	}

	// No eligible vtxos → nothing to look up. Skip the manager call so we
	// don't hand contract.WithScripts an empty slice (which it rightly
	// rejects as a programmer error). Callers (Unroll, Settle, …) already
	// handle a (nil, nil) return as "no vtxos available".
	if len(scripts) == 0 {
		return nil, nil
	}

	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	contractsByScript := make(map[string]types.Contract, len(contracts))
	for _, c := range contracts {
		contractsByScript[c.Script] = c
	}

	vtxos := make([]clienttypes.VtxoWithTapTree, 0, len(eligible))
	for _, v := range eligible {
		contract, ok := contractsByScript[v.Script]
		if !ok {
			log.Warnf("skipping vtxo %s: no matching contract", v.Script)
			continue
		}

		handler, err := w.contractManager.GetHandler(ctx, contract)
		if err != nil {
			log.WithError(err).Warnf("failed to get handler for contract %s", contract.Script)
			continue
		}
		tapscripts, err := handler.GetTapscripts(contract)
		if err != nil {
			log.WithError(err).Warnf("failed to get tapscripts for contract %s", contract.Script)
			continue
		}

		vtxos = append(vtxos, clienttypes.VtxoWithTapTree{
			Vtxo:       v,
			Tapscripts: tapscripts,
		})
	}

	return vtxos, nil
}
