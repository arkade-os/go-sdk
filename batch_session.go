package arksdk

import (
	"context"
	"fmt"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

var (
	ErrNoFundsToSettle = fmt.Errorf("no funds to settle")
)

// Settle is the public settlement entrypoint. It guards on safeCheck (returns
// ErrIsSyncing while the wallet is still restoring) and then delegates to the
// unexported settle. External callers always go through this guarded path; the
// behavior of the public API is unchanged.
func (w *wallet) Settle(ctx context.Context, opts ...BatchSessionOption) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}
	return w.settle(ctx, opts...)
}

// settle performs a settlement WITHOUT the safeCheck guard. It is the shared
// body of the public Settle and is also invoked by reconcileDeprecatedSigners,
// which runs the deprecated-signer migration synchronously during Unlock —
// BEFORE the wallet is marked synced — so it must bypass safeCheck (which would
// otherwise return ErrIsSyncing and silently skip the migration). It is
// unexported and reachable only from Settle and reconcileDeprecatedSigners; no
// other caller bypasses safeCheck.
func (w *wallet) settle(ctx context.Context, opts ...BatchSessionOption) (string, error) {
	settle := func() (string, error) {
		batchSessionOpts, err := applyBatchSessionOptions(opts...)
		if err != nil {
			return "", fmt.Errorf("invalid options: %v", (err))
		}

		var vtxos []clienttypes.VtxoWithTapTree
		var utxos []clienttypes.Utxo
		if batchSessionOpts.settleVtxos != nil {
			// Subset settle: resolve contracts for exactly the provided vtxos
			// and settle only those. No boarding UTXOs are included — this path
			// is offchain-only (used by reconcileDeprecatedSigners migration).
			vtxos, err = w.buildVtxosWithTapTree(ctx, batchSessionOpts.settleVtxos)
			if err != nil {
				return "", err
			}
			if len(vtxos) == 0 {
				return "", ErrNoFundsToSettle
			}
		} else {
			vtxos, err = w.getSpendableVtxos(ctx, true)
			if err != nil {
				return "", err
			}
			w.dbMu.Lock()
			utxos, _, err = w.store.UtxoStore().GetAllUtxos(ctx)
			w.dbMu.Unlock()
			if err != nil {
				return "", err
			}
			if len(vtxos)+len(utxos) == 0 {
				return "", ErrNoFundsToSettle
			}
		}

		signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, utxos)
		if err != nil {
			return "", err
		}

		changeAddr, err := w.newOffchainAddress(ctx)
		if err != nil {
			return "", err
		}

		clientOpts := []client.BatchSessionOption{
			client.WithFunds(utxos, vtxos),
			client.WithKeys(signingKeyRefs),
			client.WithReceiver(changeAddr),
		}
		if batchSessionOpts.retryNum > 0 {
			clientOpts = append(clientOpts, client.WithRetries(batchSessionOpts.retryNum))
		}

		// Subscribe to the change address before submitting so we don't miss
		// the indexer notification once the server tracks the settled vtxo.
		tracked, cancel := w.notifyTracked(ctx, changeAddr)
		defer cancel()

		res, err := w.client.Settle(ctx, clientOpts...)
		if err != nil {
			return "", err
		}

		// Persist within the critical section so the next queued operation
		// sees the refreshed VTXOs before it runs. A deduping settle returns
		// this same result without re-running, so it won't save twice.
		if err := w.saveBatchTransaction(ctx, *res); err != nil {
			return "", err
		}

		// Wait until the indexer has tracked our settled vtxo before releasing
		// the slot, so the next queued operation can spend it.
		if len(res.VtxoOutputs) > 0 {
			if err := <-tracked; err != nil {
				return "", err
			}
		}
		return res.CommitmentTxid, nil
	}

	return w.txHandler.handleBatchTx(settleType, settle)
}

// buildVtxosWithTapTree enriches a plain []clienttypes.Vtxo subset into the
// []clienttypes.VtxoWithTapTree shape that getSpendableVtxos produces, by
// resolving each vtxo's contract and extracting its tapscripts. Vtxos whose
// contract is not found in the store (or whose handler/tapscripts cannot be
// resolved) are skipped with a warning — the same behavior getSpendableVtxos
// exhibits for vtxos missing a contract. Used by the WithSettleVtxos subset
// path in Settle.
func (w *wallet) buildVtxosWithTapTree(
	ctx context.Context, subset []clienttypes.Vtxo,
) ([]clienttypes.VtxoWithTapTree, error) {
	if len(subset) == 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(subset))
	for _, v := range subset {
		scripts = append(scripts, v.Script)
	}

	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	contractsByScript := make(map[string]types.Contract, len(contracts))
	for _, c := range contracts {
		contractsByScript[c.Script] = c
	}

	vtxos := make([]clienttypes.VtxoWithTapTree, 0, len(subset))
	for _, v := range subset {
		c, ok := contractsByScript[v.Script]
		if !ok {
			log.Warnf("skipping vtxo %s: no matching contract", v.Script)
			continue
		}
		handler, err := w.contractManager.GetHandler(ctx, c)
		if err != nil {
			log.WithError(err).Warnf("failed to get handler for contract %s", c.Script)
			continue
		}
		tapscripts, err := handler.GetTapscripts(c)
		if err != nil {
			log.WithError(err).Warnf("failed to get tapscripts for contract %s", c.Script)
			continue
		}
		vtxos = append(vtxos, clienttypes.VtxoWithTapTree{
			Vtxo:       v,
			Tapscripts: tapscripts,
		})
	}

	return vtxos, nil
}

func (w *wallet) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, opts ...BatchSessionOption,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	collabExit := func() (string, error) {
		vtxos, err := w.getSpendableVtxos(ctx, true)
		if err != nil {
			return "", err
		}

		batchSessionOpts, err := applyBatchSessionOptions(opts...)
		if err != nil {
			return "", fmt.Errorf("invalid options: %v", (err))
		}

		signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
		if err != nil {
			return "", err
		}

		changeAddr, err := w.newOffchainAddress(ctx)
		if err != nil {
			return "", err
		}

		clientOpts := []client.BatchSessionOption{
			client.WithFunds(nil, vtxos),
			client.WithKeys(signingKeyRefs),
			client.WithReceiver(changeAddr),
		}
		if batchSessionOpts.retryNum > 0 {
			clientOpts = append(clientOpts, client.WithRetries(batchSessionOpts.retryNum))
		}

		// Subscribe to the change address before submitting so we don't miss
		// the indexer notification once the server tracks any change vtxo.
		tracked, cancel := w.notifyTracked(ctx, changeAddr)
		defer cancel()

		res, err := w.client.CollaborativeExit(ctx, addr, amount, clientOpts...)
		if err != nil {
			return "", err
		}

		// Persist within the critical section so the next queued operation
		// sees the spent VTXOs before it runs.
		if err := w.saveBatchTransaction(ctx, *res); err != nil {
			return "", err
		}

		// If the exit left change, wait until the indexer has tracked it
		// before releasing the slot so the next queued operation can spend it.
		if len(res.VtxoOutputs) > 0 {
			if err := <-tracked; err != nil {
				return "", err
			}
		}
		return res.CommitmentTxid, nil
	}

	return w.txHandler.handleBatchTx(collabExitType, collabExit)
}

func (w *wallet) RegisterIntent(
	ctx context.Context,
	vtxos []clienttypes.Vtxo, boardingUtxos []clienttypes.Utxo, notes []string,
	outputs []clienttypes.Receiver, cosignersPublicKeys []string,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	vv := make([]clienttypes.VtxoWithTapTree, 0, len(vtxos))
	for _, vtxo := range vtxos {
		vv = append(vv, clienttypes.VtxoWithTapTree{Vtxo: vtxo})
	}
	keys, err := w.getSigningKeyRefs(ctx, vv, boardingUtxos)
	if err != nil {
		return "", err
	}

	return w.client.RegisterIntent(
		ctx, vtxos, boardingUtxos, notes, outputs, cosignersPublicKeys, client.WithKeys(keys),
	)
}

func (w *wallet) DeleteIntent(
	ctx context.Context,
	vtxos []clienttypes.Vtxo, boardingUtxos []clienttypes.Utxo, notes []string,
) error {
	if err := w.safeCheck(); err != nil {
		return err
	}
	return w.client.DeleteIntent(ctx, vtxos, boardingUtxos, notes)
}

func (w *wallet) RedeemNotes(
	ctx context.Context, notes []string,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	addr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	res, err := w.client.RedeemNotes(ctx, notes, client.WithReceiver(addr))
	if err != nil {
		return "", err
	}

	if err := w.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}
