package indexer

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	arkindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer"
	arkgrpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	arktypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdkindexer "github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
)

type indexerAdapter struct {
	inner arkindexer.Indexer
}

func NewClient(serverUrl string) (sdkindexer.Indexer, error) {
	inner, err := arkgrpcindexer.NewClient(serverUrl)
	if err != nil {
		return nil, err
	}

	return &indexerAdapter{inner: inner}, nil
}

func (a *indexerAdapter) GetCommitmentTx(
	ctx context.Context,
	txid string,
) (*sdkindexer.CommitmentTx, error) {
	commitmentTx, err := a.inner.GetCommitmentTx(ctx, txid)
	if err != nil {
		return nil, err
	}

	return toSDKCommitmentTx(commitmentTx), nil
}

func (a *indexerAdapter) GetVtxoTree(
	ctx context.Context,
	batchOutpoint types.Outpoint,
	opts ...sdkindexer.RequestOption,
) (*sdkindexer.VtxoTreeResponse, error) {
	vtxoTree, err := a.inner.GetVtxoTree(
		ctx,
		toArkOutpoint(batchOutpoint),
		toArkRequestOptions(opts)...,
	)
	if err != nil {
		return nil, err
	}

	return toSDKVtxoTreeResponse(vtxoTree), nil
}

func (a *indexerAdapter) GetFullVtxoTree(
	ctx context.Context,
	batchOutpoint types.Outpoint,
	opts ...sdkindexer.RequestOption,
) ([]tree.TxTreeNode, error) {
	return a.inner.GetFullVtxoTree(ctx, toArkOutpoint(batchOutpoint), toArkRequestOptions(opts)...)
}

func (a *indexerAdapter) GetVtxoTreeLeaves(
	ctx context.Context,
	batchOutpoint types.Outpoint,
	opts ...sdkindexer.RequestOption,
) (*sdkindexer.VtxoTreeLeavesResponse, error) {
	leaves, err := a.inner.GetVtxoTreeLeaves(
		ctx,
		toArkOutpoint(batchOutpoint),
		toArkRequestOptions(opts)...,
	)
	if err != nil {
		return nil, err
	}

	return toSDKVtxoTreeLeavesResponse(leaves), nil
}

func (a *indexerAdapter) GetForfeitTxs(
	ctx context.Context,
	txid string,
	opts ...sdkindexer.RequestOption,
) (*sdkindexer.ForfeitTxsResponse, error) {
	forfeits, err := a.inner.GetForfeitTxs(ctx, txid, toArkRequestOptions(opts)...)
	if err != nil {
		return nil, err
	}

	return &sdkindexer.ForfeitTxsResponse{
		Txids: forfeits.Txids,
		Page:  toSDKPage(forfeits.Page),
	}, nil
}

func (a *indexerAdapter) GetConnectors(
	ctx context.Context,
	txid string,
	opts ...sdkindexer.RequestOption,
) (*sdkindexer.ConnectorsResponse, error) {
	connectors, err := a.inner.GetConnectors(ctx, txid, toArkRequestOptions(opts)...)
	if err != nil {
		return nil, err
	}

	treeNodes := make([]sdkindexer.TxNode, 0, len(connectors.Tree))
	for _, node := range connectors.Tree {
		treeNodes = append(treeNodes, sdkindexer.TxNode{Txid: node.Txid, Children: node.Children})
	}

	return &sdkindexer.ConnectorsResponse{Tree: treeNodes, Page: toSDKPage(connectors.Page)}, nil
}

func (a *indexerAdapter) GetVtxos(
	ctx context.Context,
	opts ...sdkindexer.GetVtxosRequestOption,
) (*sdkindexer.VtxosResponse, error) {
	arkOpts, err := toArkGetVtxosOptions(opts)
	if err != nil {
		return nil, err
	}

	vtxos, err := a.inner.GetVtxos(ctx, arkOpts...)
	if err != nil {
		return nil, err
	}

	return &sdkindexer.VtxosResponse{
		Vtxos: toSDKVtxos(vtxos.Vtxos),
		Page:  toSDKPage(vtxos.Page),
	}, nil
}

func (a *indexerAdapter) GetVtxoChain(
	ctx context.Context,
	outpoint types.Outpoint,
	opts ...sdkindexer.RequestOption,
) (*sdkindexer.VtxoChainResponse, error) {
	chain, err := a.inner.GetVtxoChain(ctx, toArkOutpoint(outpoint), toArkRequestOptions(opts)...)
	if err != nil {
		return nil, err
	}

	mapped := make([]sdkindexer.ChainWithExpiry, 0, len(chain.Chain))
	for _, item := range chain.Chain {
		mapped = append(mapped, sdkindexer.ChainWithExpiry{
			Txid:      item.Txid,
			ExpiresAt: item.ExpiresAt,
			Type:      sdkindexer.IndexerChainedTxType(item.Type),
			Spends:    item.Spends,
		})
	}

	return &sdkindexer.VtxoChainResponse{Chain: mapped, Page: toSDKPage(chain.Page)}, nil
}

func (a *indexerAdapter) GetVirtualTxs(
	ctx context.Context,
	txids []string,
	opts ...sdkindexer.RequestOption,
) (*sdkindexer.VirtualTxsResponse, error) {
	virtualTxs, err := a.inner.GetVirtualTxs(ctx, txids, toArkRequestOptions(opts)...)
	if err != nil {
		return nil, err
	}

	return &sdkindexer.VirtualTxsResponse{
		Txs:  virtualTxs.Txs,
		Page: toSDKPage(virtualTxs.Page),
	}, nil
}

func (a *indexerAdapter) GetBatchSweepTxs(
	ctx context.Context,
	batchOutpoint types.Outpoint,
) ([]string, error) {
	return a.inner.GetBatchSweepTxs(ctx, toArkOutpoint(batchOutpoint))
}

func (a *indexerAdapter) SubscribeForScripts(
	ctx context.Context,
	subscriptionId string,
	scripts []string,
) (string, error) {
	return a.inner.SubscribeForScripts(ctx, subscriptionId, scripts)
}

func (a *indexerAdapter) UnsubscribeForScripts(
	ctx context.Context,
	subscriptionId string,
	scripts []string,
) error {
	return a.inner.UnsubscribeForScripts(ctx, subscriptionId, scripts)
}

func (a *indexerAdapter) GetSubscription(
	ctx context.Context,
	subscriptionId string,
) (<-chan *sdkindexer.ScriptEvent, func(), error) {
	innerCh, closeFn, err := a.inner.GetSubscription(ctx, subscriptionId)
	if err != nil {
		return nil, nil, err
	}

	outCh := make(chan *sdkindexer.ScriptEvent)
	go func() {
		defer close(outCh)

		for event := range innerCh {
			mapped := toSDKScriptEvent(event)
			select {
			case <-ctx.Done():
				return
			case outCh <- mapped:
			}
		}
	}()

	return outCh, closeFn, nil
}

func (a *indexerAdapter) GetAsset(
	ctx context.Context,
	assetID string,
) (*sdkindexer.AssetInfo, error) {
	assetInfo, err := a.inner.GetAsset(ctx, assetID)
	if err != nil {
		return nil, err
	}

	if assetInfo == nil {
		return nil, nil
	}

	return &sdkindexer.AssetInfo{
		AssetId:        assetInfo.AssetId,
		Supply:         assetInfo.Supply,
		ControlAssetId: assetInfo.ControlAssetId,
		Metadata:       assetInfo.Metadata,
	}, nil
}

func (a *indexerAdapter) Close() {
	a.inner.Close()
}

func toArkOutpoint(outpoint types.Outpoint) arktypes.Outpoint {
	return arktypes.Outpoint{Txid: outpoint.Txid, VOut: outpoint.VOut}
}

func toSDKOutpoint(outpoint arktypes.Outpoint) types.Outpoint {
	return types.Outpoint{Txid: outpoint.Txid, VOut: outpoint.VOut}
}

func toArkRequestOptions(opts []sdkindexer.RequestOption) []arkindexer.RequestOption {
	mapped := make([]arkindexer.RequestOption, 0, len(opts))
	for _, opt := range opts {
		var mappedOpt arkindexer.RequestOption
		if page := opt.GetPage(); page != nil {
			mappedOpt.WithPage(&arkindexer.PageRequest{Size: page.Size, Index: page.Index})
		}
		mapped = append(mapped, mappedOpt)
	}
	return mapped
}

func toArkGetVtxosOptions(
	opts []sdkindexer.GetVtxosRequestOption,
) ([]arkindexer.GetVtxosRequestOption, error) {
	mapped := make([]arkindexer.GetVtxosRequestOption, 0, len(opts))

	for _, opt := range opts {
		var mappedOpt arkindexer.GetVtxosRequestOption

		if page := opt.GetPage(); page != nil {
			mappedOpt.WithPage(&arkindexer.PageRequest{Size: page.Size, Index: page.Index})
		}

		if scripts := opt.GetScripts(); len(scripts) > 0 {
			if err := mappedOpt.WithScripts(scripts); err != nil {
				return nil, err
			}
		}

		if outpoints := opt.GetOutpoints(); len(outpoints) > 0 {
			parsed := make([]arktypes.Outpoint, 0, len(outpoints))
			for _, outpoint := range outpoints {
				out, err := parseOutpoint(outpoint)
				if err != nil {
					return nil, err
				}
				parsed = append(parsed, out)
			}
			if err := mappedOpt.WithOutpoints(parsed); err != nil {
				return nil, err
			}
		}

		if opt.GetSpentOnly() {
			mappedOpt.WithSpentOnly()
		}
		if opt.GetSpendableOnly() {
			mappedOpt.WithSpendableOnly()
		}
		if opt.GetRecoverableOnly() {
			mappedOpt.WithRecoverableOnly()
		}
		if opt.GetPendingOnly() {
			mappedOpt.WithPendingOnly()
		}

		mapped = append(mapped, mappedOpt)
	}

	return mapped, nil
}

func parseOutpoint(outpoint string) (arktypes.Outpoint, error) {
	txid, voutStr, ok := strings.Cut(outpoint, ":")
	if !ok {
		return arktypes.Outpoint{}, fmt.Errorf("invalid outpoint %q", outpoint)
	}

	vout, err := strconv.ParseUint(voutStr, 10, 32)
	if err != nil {
		return arktypes.Outpoint{}, fmt.Errorf("invalid outpoint %q: %w", outpoint, err)
	}

	return arktypes.Outpoint{Txid: txid, VOut: uint32(vout)}, nil
}

func toSDKCommitmentTx(commitmentTx *arkindexer.CommitmentTx) *sdkindexer.CommitmentTx {
	if commitmentTx == nil {
		return nil
	}

	batches := make(map[uint32]*sdkindexer.Batch, len(commitmentTx.Batches))
	for vout, batch := range commitmentTx.Batches {
		if batch == nil {
			continue
		}
		batches[vout] = &sdkindexer.Batch{
			TotalOutputAmount: batch.TotalOutputAmount,
			TotalOutputVtxos:  batch.TotalOutputVtxos,
			ExpiresAt:         batch.ExpiresAt,
			Swept:             batch.Swept,
		}
	}

	return &sdkindexer.CommitmentTx{
		StartedAt:         commitmentTx.StartedAt,
		EndedAt:           commitmentTx.EndedAt,
		TotalInputAmount:  commitmentTx.TotalInputAmount,
		TotalInputVtxos:   commitmentTx.TotalInputVtxos,
		TotalOutputAmount: commitmentTx.TotalOutputAmount,
		TotalOutputVtxos:  commitmentTx.TotalOutputVtxos,
		Batches:           batches,
	}
}

func toSDKVtxoTreeResponse(resp *arkindexer.VtxoTreeResponse) *sdkindexer.VtxoTreeResponse {
	if resp == nil {
		return nil
	}

	nodes := make([]sdkindexer.TxNode, 0, len(resp.Tree))
	for _, node := range resp.Tree {
		nodes = append(nodes, sdkindexer.TxNode{Txid: node.Txid, Children: node.Children})
	}

	return &sdkindexer.VtxoTreeResponse{Tree: nodes, Page: toSDKPage(resp.Page)}
}

func toSDKVtxoTreeLeavesResponse(
	resp *arkindexer.VtxoTreeLeavesResponse,
) *sdkindexer.VtxoTreeLeavesResponse {
	if resp == nil {
		return nil
	}

	leaves := make([]types.Outpoint, 0, len(resp.Leaves))
	for _, leaf := range resp.Leaves {
		leaves = append(leaves, toSDKOutpoint(leaf))
	}

	return &sdkindexer.VtxoTreeLeavesResponse{Leaves: leaves, Page: toSDKPage(resp.Page)}
}

func toSDKPage(page *arkindexer.PageResponse) *sdkindexer.PageResponse {
	if page == nil {
		return nil
	}

	return &sdkindexer.PageResponse{Current: page.Current, Next: page.Next, Total: page.Total}
}

func toSDKScriptEvent(event arkindexer.ScriptEvent) *sdkindexer.ScriptEvent {
	checkpointTxs := make(map[string]sdkindexer.TxData, len(event.CheckpointTxs))
	for outpoint, txData := range event.CheckpointTxs {
		checkpointTxs[outpoint] = sdkindexer.TxData{Txid: txData.Txid, Tx: txData.Tx}
	}

	return &sdkindexer.ScriptEvent{
		Txid:          event.Txid,
		Tx:            event.Tx,
		Scripts:       event.Scripts,
		NewVtxos:      toSDKVtxos(event.NewVtxos),
		SpentVtxos:    toSDKVtxos(event.SpentVtxos),
		CheckpointTxs: checkpointTxs,
		Err:           event.Err,
	}
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
		Spent:           vtxo.Spent,
		Unrolled:        vtxo.Unrolled,
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
