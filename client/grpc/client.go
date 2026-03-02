package grpcclient

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	arkclient "github.com/arkade-os/arkd/pkg/client-lib/client"
	arkgrpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	arktypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdkclient "github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/types"
)

type clientAdapter struct {
	inner arkclient.TransportClient
}

func NewClient(serverUrl string) (sdkclient.TransportClient, error) {
	inner, err := arkgrpcclient.NewClient(serverUrl)
	if err != nil {
		return nil, err
	}

	return &clientAdapter{inner: inner}, nil
}

func (a *clientAdapter) GetInfo(ctx context.Context) (*sdkclient.Info, error) {
	info, err := a.inner.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	return toSDKInfo(info), nil
}

func (a *clientAdapter) RegisterIntent(ctx context.Context, proof, message string) (string, error) {
	return a.inner.RegisterIntent(ctx, proof, message)
}

func (a *clientAdapter) DeleteIntent(ctx context.Context, proof, message string) error {
	return a.inner.DeleteIntent(ctx, proof, message)
}

func (a *clientAdapter) EstimateIntentFee(ctx context.Context, proof, message string) (int64, error) {
	return a.inner.EstimateIntentFee(ctx, proof, message)
}

func (a *clientAdapter) ConfirmRegistration(ctx context.Context, intentID string) error {
	return a.inner.ConfirmRegistration(ctx, intentID)
}

func (a *clientAdapter) SubmitTreeNonces(
	ctx context.Context,
	batchId, cosignerPubkey string,
	nonces tree.TreeNonces,
) error {
	return a.inner.SubmitTreeNonces(ctx, batchId, cosignerPubkey, nonces)
}

func (a *clientAdapter) SubmitTreeSignatures(
	ctx context.Context,
	batchId, cosignerPubkey string,
	signatures tree.TreePartialSigs,
) error {
	return a.inner.SubmitTreeSignatures(ctx, batchId, cosignerPubkey, signatures)
}

func (a *clientAdapter) SubmitSignedForfeitTxs(
	ctx context.Context,
	signedForfeitTxs []string,
	signedCommitmentTx string,
) error {
	return a.inner.SubmitSignedForfeitTxs(ctx, signedForfeitTxs, signedCommitmentTx)
}

func (a *clientAdapter) GetEventStream(
	ctx context.Context,
	topics []string,
) (<-chan sdkclient.BatchEventChannel, func(), error) {
	innerCh, closeFn, err := a.inner.GetEventStream(ctx, topics)
	if err != nil {
		return nil, nil, err
	}

	outCh := make(chan sdkclient.BatchEventChannel)
	go func() {
		defer close(outCh)

		for event := range innerCh {
			mapped := sdkclient.BatchEventChannel{Err: event.Err}
			if event.Event != nil {
				converted, convErr := toSDKBatchEvent(event.Event)
				if convErr != nil {
					if mapped.Err == nil {
						mapped.Err = convErr
					}
				} else {
					mapped.Event = converted
				}
			}

			select {
			case <-ctx.Done():
				return
			case outCh <- mapped:
			}
		}
	}()

	return outCh, closeFn, nil
}

func (a *clientAdapter) SubmitTx(
	ctx context.Context,
	signedArkTx string,
	checkpointTxs []string,
) (string, string, []string, error) {
	return a.inner.SubmitTx(ctx, signedArkTx, checkpointTxs)
}

func (a *clientAdapter) FinalizeTx(
	ctx context.Context,
	arkTxid string,
	finalCheckpointTxs []string,
) error {
	return a.inner.FinalizeTx(ctx, arkTxid, finalCheckpointTxs)
}

func (a *clientAdapter) GetPendingTx(
	ctx context.Context,
	proof, message string,
) ([]sdkclient.AcceptedOffchainTx, error) {
	pendingTxs, err := a.inner.GetPendingTx(ctx, proof, message)
	if err != nil {
		return nil, err
	}

	res := make([]sdkclient.AcceptedOffchainTx, 0, len(pendingTxs))
	for _, tx := range pendingTxs {
		res = append(res, sdkclient.AcceptedOffchainTx{
			Txid:                tx.Txid,
			FinalArkTx:          tx.FinalArkTx,
			SignedCheckpointTxs: tx.SignedCheckpointTxs,
		})
	}
	return res, nil
}

func (a *clientAdapter) GetTransactionsStream(
	ctx context.Context,
) (<-chan sdkclient.TransactionEvent, func(), error) {
	innerCh, closeFn, err := a.inner.GetTransactionsStream(ctx)
	if err != nil {
		return nil, nil, err
	}

	outCh := make(chan sdkclient.TransactionEvent)
	go func() {
		defer close(outCh)

		for event := range innerCh {
			mapped := sdkclient.TransactionEvent{
				CommitmentTx: toSDKTxNotification(event.CommitmentTx),
				ArkTx:        toSDKTxNotification(event.ArkTx),
				Err:          event.Err,
			}

			select {
			case <-ctx.Done():
				return
			case outCh <- mapped:
			}
		}
	}()

	return outCh, closeFn, nil
}

func (a *clientAdapter) ModifyStreamTopics(
	ctx context.Context,
	addTopics, removeTopics []string,
) (addedTopics, removedTopics, allTopics []string, err error) {
	return a.inner.ModifyStreamTopics(ctx, addTopics, removeTopics)
}

func (a *clientAdapter) OverwriteStreamTopics(
	ctx context.Context,
	topics []string,
) (addedTopics, removedTopics, allTopics []string, err error) {
	return a.inner.OverwriteStreamTopics(ctx, topics)
}

func (a *clientAdapter) Close() {
	a.inner.Close()
}

func toSDKInfo(info *arkclient.Info) *sdkclient.Info {
	if info == nil {
		return nil
	}

	deprecatedSigners := make([]sdkclient.DeprecatedSigner, 0, len(info.DeprecatedSignerPubKeys))
	for _, signer := range info.DeprecatedSignerPubKeys {
		deprecatedSigners = append(deprecatedSigners, sdkclient.DeprecatedSigner{
			PubKey:     signer.PubKey,
			CutoffDate: signer.CutoffDate,
		})
	}

	return &sdkclient.Info{
		Version:                   info.Version,
		SignerPubKey:              info.SignerPubKey,
		ForfeitPubKey:             info.ForfeitPubKey,
		UnilateralExitDelay:       info.UnilateralExitDelay,
		BoardingExitDelay:         info.BoardingExitDelay,
		SessionDuration:           info.SessionDuration,
		Network:                   info.Network,
		Dust:                      info.Dust,
		ForfeitAddress:            info.ForfeitAddress,
		ScheduledSessionStartTime: info.ScheduledSessionStartTime,
		ScheduledSessionEndTime:   info.ScheduledSessionEndTime,
		ScheduledSessionPeriod:    info.ScheduledSessionPeriod,
		ScheduledSessionDuration:  info.ScheduledSessionDuration,
		ScheduledSessionFees:      toSDKFeeInfo(info.ScheduledSessionFees),
		UtxoMinAmount:             info.UtxoMinAmount,
		UtxoMaxAmount:             info.UtxoMaxAmount,
		VtxoMinAmount:             info.VtxoMinAmount,
		VtxoMaxAmount:             info.VtxoMaxAmount,
		CheckpointTapscript:       info.CheckpointTapscript,
		Fees:                      toSDKFeeInfo(info.Fees),
		DeprecatedSignerPubKeys:   deprecatedSigners,
		ServiceStatus:             info.ServiceStatus,
		Digest:                    info.Digest,
	}
}

func toSDKFeeInfo(feeInfo arktypes.FeeInfo) types.FeeInfo {
	return types.FeeInfo{
		IntentFees: feeInfo.IntentFees,
		TxFeeRate:  feeInfo.TxFeeRate,
	}
}

func toSDKBatchEvent(event any) (any, error) {
	switch e := event.(type) {
	case arkclient.BatchFinalizationEvent:
		return sdkclient.BatchFinalizationEvent{Id: e.Id, Tx: e.Tx}, nil
	case *arkclient.BatchFinalizationEvent:
		return sdkclient.BatchFinalizationEvent{Id: e.Id, Tx: e.Tx}, nil
	case arkclient.BatchFinalizedEvent:
		return sdkclient.BatchFinalizedEvent{Id: e.Id, Txid: e.Txid}, nil
	case *arkclient.BatchFinalizedEvent:
		return sdkclient.BatchFinalizedEvent{Id: e.Id, Txid: e.Txid}, nil
	case arkclient.BatchFailedEvent:
		return sdkclient.BatchFailedEvent{Id: e.Id, Reason: e.Reason}, nil
	case *arkclient.BatchFailedEvent:
		return sdkclient.BatchFailedEvent{Id: e.Id, Reason: e.Reason}, nil
	case arkclient.TreeSigningStartedEvent:
		return sdkclient.TreeSigningStartedEvent{
			Id:                   e.Id,
			UnsignedCommitmentTx: e.UnsignedCommitmentTx,
			CosignersPubkeys:     e.CosignersPubkeys,
		}, nil
	case *arkclient.TreeSigningStartedEvent:
		return sdkclient.TreeSigningStartedEvent{
			Id:                   e.Id,
			UnsignedCommitmentTx: e.UnsignedCommitmentTx,
			CosignersPubkeys:     e.CosignersPubkeys,
		}, nil
	case arkclient.TreeNoncesAggregatedEvent:
		return sdkclient.TreeNoncesAggregatedEvent{Id: e.Id, Nonces: e.Nonces}, nil
	case *arkclient.TreeNoncesAggregatedEvent:
		return sdkclient.TreeNoncesAggregatedEvent{Id: e.Id, Nonces: e.Nonces}, nil
	case arkclient.TreeTxEvent:
		return sdkclient.TreeTxEvent{Id: e.Id, Topic: e.Topic, BatchIndex: e.BatchIndex, Node: e.Node}, nil
	case *arkclient.TreeTxEvent:
		return sdkclient.TreeTxEvent{Id: e.Id, Topic: e.Topic, BatchIndex: e.BatchIndex, Node: e.Node}, nil
	case arkclient.TreeSignatureEvent:
		return sdkclient.TreeSignatureEvent{
			Id:         e.Id,
			Topic:      e.Topic,
			BatchIndex: e.BatchIndex,
			Txid:       e.Txid,
			Signature:  e.Signature,
		}, nil
	case *arkclient.TreeSignatureEvent:
		return sdkclient.TreeSignatureEvent{
			Id:         e.Id,
			Topic:      e.Topic,
			BatchIndex: e.BatchIndex,
			Txid:       e.Txid,
			Signature:  e.Signature,
		}, nil
	case arkclient.TreeNoncesEvent:
		return sdkclient.TreeNoncesEvent{
			Id: e.Id, Topic: e.Topic, Txid: e.Txid, Nonces: e.Nonces,
		}, nil
	case *arkclient.TreeNoncesEvent:
		return sdkclient.TreeNoncesEvent{
			Id: e.Id, Topic: e.Topic, Txid: e.Txid, Nonces: e.Nonces,
		}, nil
	case arkclient.BatchStartedEvent:
		return sdkclient.BatchStartedEvent{
			Id: e.Id, HashedIntentIds: e.HashedIntentIds, BatchExpiry: e.BatchExpiry,
		}, nil
	case *arkclient.BatchStartedEvent:
		return sdkclient.BatchStartedEvent{
			Id: e.Id, HashedIntentIds: e.HashedIntentIds, BatchExpiry: e.BatchExpiry,
		}, nil
	case arkclient.StreamStartedEvent:
		return sdkclient.StreamStartedEvent{Id: e.Id}, nil
	case *arkclient.StreamStartedEvent:
		return sdkclient.StreamStartedEvent{Id: e.Id}, nil
	default:
		return nil, fmt.Errorf("unsupported batch event type %T", event)
	}
}

func toSDKTxNotification(notification *arkclient.TxNotification) *sdkclient.TxNotification {
	if notification == nil {
		return nil
	}

	checkpointTxs := make(map[types.Outpoint]sdkclient.TxData, len(notification.CheckpointTxs))
	for outpoint, tx := range notification.CheckpointTxs {
		checkpointTxs[toSDKOutpoint(outpoint)] = sdkclient.TxData{
			Txid: tx.Txid,
			Tx:   tx.Tx,
		}
	}

	return &sdkclient.TxNotification{
		TxData: sdkclient.TxData{
			Txid: notification.Txid,
			Tx:   notification.Tx,
		},
		SpentVtxos:     toSDKVtxos(notification.SpentVtxos),
		SpendableVtxos: toSDKVtxos(notification.SpendableVtxos),
		CheckpointTxs:  checkpointTxs,
	}
}

func toSDKOutpoint(outpoint arktypes.Outpoint) types.Outpoint {
	return types.Outpoint{Txid: outpoint.Txid, VOut: outpoint.VOut}
}

func toSDKVtxos(vtxos []arktypes.Vtxo) []types.Vtxo {
	mapped := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		mapped = append(mapped, toSDKVtxo(vtxo))
	}
	return mapped
}

func toSDKVtxo(vtxo arktypes.Vtxo) types.Vtxo {
	return types.Vtxo{
		Outpoint:        types.Outpoint{Txid: vtxo.Txid, VOut: vtxo.VOut},
		Script:          vtxo.Script,
		Amount:          vtxo.Amount,
		CommitmentTxids: vtxo.CommitmentTxids,
		ExpiresAt:       vtxo.ExpiresAt,
		CreatedAt:       vtxo.CreatedAt,
		Preconfirmed:    vtxo.Preconfirmed,
		Swept:           vtxo.Swept,
		Unrolled:        vtxo.Unrolled,
		Spent:           vtxo.Spent,
		SpentBy:         vtxo.SpentBy,
		SettledBy:       vtxo.SettledBy,
		ArkTxid:         vtxo.ArkTxid,
		Assets:          toSDKAssets(vtxo.Assets),
	}
}

func toSDKAssets(assets []arktypes.Asset) []types.Asset {
	mapped := make([]types.Asset, 0, len(assets))
	for _, asset := range assets {
		mapped = append(mapped, types.Asset{AssetId: asset.AssetId, Amount: asset.Amount})
	}
	return mapped
}
