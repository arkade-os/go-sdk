package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/go-sdk/client"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

const (
	start = iota
	batchStarted
	treeSigningStarted
	treeNoncesAggregated
	batchFinalization
)

type BatchEventHandlers interface {
	OnBatchStarted(ctx context.Context, event client.BatchStartedEvent) (bool, error)
	OnBatchFinalized(ctx context.Context, event client.BatchFinalizedEvent) error
	OnBatchFailed(ctx context.Context, event client.BatchFailedEvent) error
	OnTreeTxEvent(ctx context.Context, event client.TreeTxEvent) error
	OnTreeSignatureEvent(ctx context.Context, event client.TreeSignatureEvent) error
	OnTreeSigningStarted(ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error)
	OnTreeNoncesAggregated(ctx context.Context, event client.TreeNoncesAggregatedEvent) error
	OnBatchFinalization(
		ctx context.Context, event client.BatchFinalizationEvent,
		vtxoTree *tree.TxTree, connectorTree *tree.TxTree,
	) error
}

type options struct {
	signVtxoTree   bool            // default: true
	replayEventsCh chan<- any      // default: nil
	cancelCh       <-chan struct{} // default: nil
}

func newOptions() *options {
	return &options{
		signVtxoTree:   true,
		replayEventsCh: nil,
		cancelCh:       nil,
	}
}

type BatchSessionOption func(*options)

func WithSkipVtxoTreeSigning() BatchSessionOption {
	return func(o *options) {
		o.signVtxoTree = false
	}
}

func WithReplay(ch chan<- any) BatchSessionOption {
	return func(o *options) {
		o.replayEventsCh = ch
	}
}

func WithCancel(cancelCh <-chan struct{}) BatchSessionOption {
	return func(o *options) {
		o.cancelCh = cancelCh
	}
}

func HandleBatchEvents(
	ctx context.Context,
	eventsCh <-chan client.BatchEventChannel,
	handlers BatchEventHandlers,
	opts ...BatchSessionOption,
) (string, error) {
	options := newOptions()

	for _, opt := range opts {
		opt(options)
	}

	step := start

	// the txs of the tree are received one after the other via TxTreeEvent
	// we collect them and then build the tree when necessary.
	flatVtxoTree := make([]tree.TxTreeNode, 0)
	flatConnectorTree := make([]tree.TxTreeNode, 0)

	var vtxoTree, connectorTree *tree.TxTree

	for {
		select {
		case <-options.cancelCh:
			return "", fmt.Errorf("canceled")
		case <-ctx.Done():
			return "", fmt.Errorf("context done %s", ctx.Err())
		case notify := <-eventsCh:
			if notify.Err != nil {
				return "", notify.Err
			}

			if options.replayEventsCh != nil {
				go func() {
					options.replayEventsCh <- notify.Event
				}()
			}

			switch event := notify.Event; event.(type) {
			case client.BatchStartedEvent:
				e := event.(client.BatchStartedEvent)
				skip, err := handlers.OnBatchStarted(ctx, e)
				if err != nil {
					return "", err
				}
				if !skip {
					step++

					// if we don't want to sign the vtxo tree, we can skip the tree signing phase
					if !options.signVtxoTree {
						step = treeNoncesAggregated
					}
					continue
				}
			case client.BatchFinalizedEvent:
				if step != batchFinalization {
					continue
				}
				event := event.(client.BatchFinalizedEvent)
				if err := handlers.OnBatchFinalized(ctx, event); err != nil {
					return "", err
				}
				return event.Txid, nil
			// the batch session failed, return error only if we joined.
			case client.BatchFailedEvent:
				e := event.(client.BatchFailedEvent)
				if err := handlers.OnBatchFailed(ctx, e); err != nil {
					return "", err
				}
				continue
			// we received a tree tx event msg, let's update the vtxo/connector tree.
			case client.TreeTxEvent:
				if step != batchStarted && step != treeNoncesAggregated {
					continue
				}

				treeTxEvent := event.(client.TreeTxEvent)

				if err := handlers.OnTreeTxEvent(ctx, treeTxEvent); err != nil {
					return "", err
				}

				if treeTxEvent.BatchIndex == 0 {
					flatVtxoTree = append(flatVtxoTree, treeTxEvent.Node)
				} else {
					flatConnectorTree = append(flatConnectorTree, treeTxEvent.Node)
				}

				continue
			case client.TreeSignatureEvent:
				if step != treeNoncesAggregated {
					continue
				}
				if vtxoTree == nil {
					return "", fmt.Errorf("vtxo tree not initialized")
				}

				event := event.(client.TreeSignatureEvent)
				if err := handlers.OnTreeSignatureEvent(ctx, event); err != nil {
					return "", err
				}

				if err := addSignatureToTxTree(event, vtxoTree); err != nil {
					return "", err
				}
				continue
			// the musig2 session started, let's send our nonces.
			case client.TreeSigningStartedEvent:
				if step != batchStarted {
					continue
				}

				var err error
				vtxoTree, err = tree.NewTxTree(flatVtxoTree)
				if err != nil {
					return "", fmt.Errorf("failed to create branch of vtxo tree: %s", err)
				}

				event := event.(client.TreeSigningStartedEvent)
				skip, err := handlers.OnTreeSigningStarted(ctx, event, vtxoTree)
				if err != nil {
					return "", err
				}

				if !skip {
					step++
				}
				continue
			// we received the aggregated nonces, let's send our signatures.
			case client.TreeNoncesAggregatedEvent:
				if step != treeSigningStarted {
					continue
				}

				event := event.(client.TreeNoncesAggregatedEvent)
				if err := handlers.OnTreeNoncesAggregated(ctx, event); err != nil {
					return "", err
				}

				step++
				continue
			// we received the fully signed vtxo and connector trees, let's send our signed forfeit
			// txs and optionally signed boarding utxos included in the commitment tx.
			case client.BatchFinalizationEvent:
				if step != treeNoncesAggregated {
					continue
				}

				if vtxoTree == nil {
					return "", fmt.Errorf("vtxo tree not initialized")
				}

				if len(flatConnectorTree) > 0 {
					var err error
					connectorTree, err = tree.NewTxTree(flatConnectorTree)
					if err != nil {
						return "", fmt.Errorf("failed to create branch of connector tree: %s", err)
					}
				}

				event := event.(client.BatchFinalizationEvent)
				if err := handlers.OnBatchFinalization(ctx, event, vtxoTree, connectorTree); err != nil {
					return "", err
				}

				log.Info("done.")
				log.Info("waiting for batch finalization...")
				step++
				continue
			}
		}
	}
}

func addSignatureToTxTree(
	event client.TreeSignatureEvent, txTree *tree.TxTree,
) error {
	if event.BatchIndex != 0 {
		return fmt.Errorf("batch index %d is not 0", event.BatchIndex)
	}

	decodedSig, err := hex.DecodeString(event.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %s", err)
	}

	sig, err := schnorr.ParseSignature(decodedSig)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %s", err)
	}

	return txTree.Apply(func(g *tree.TxTree) (bool, error) {
		if g.Root.UnsignedTx.TxID() != event.Txid {
			return true, nil
		}

		g.Root.Inputs[0].TaprootKeySpendSig = sig.Serialize()
		return false, nil
	})
}
