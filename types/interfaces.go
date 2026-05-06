package types

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
)

type Store interface {
	TransactionStore() TransactionStore
	UtxoStore() UtxoStore
	VtxoStore() VtxoStore
	AssetStore() AssetStore
	// ContractStore returns the contract persistence layer.
	// Returns nil for store backends that do not persist contracts (e.g. kv, in-memory).
	ContractStore() ContractStore
	Clean(ctx context.Context)
	Close()
}

type TransactionStore interface {
	AddTransactions(ctx context.Context, txs []types.Transaction) (int, error)
	SettleTransactions(ctx context.Context, txids []string, settledBy string) (int, error)
	ConfirmTransactions(ctx context.Context, txids []string, timestamp time.Time) (int, error)
	RbfTransactions(ctx context.Context, rbfTxs map[string]string) (int, error)
	GetAllTransactions(ctx context.Context) ([]types.Transaction, error)
	GetTransactions(ctx context.Context, txids []string) ([]types.Transaction, error)
	UpdateTransactions(ctx context.Context, txs []types.Transaction) (int, error)
	Clean(ctx context.Context) error
	GetEventChannel() <-chan TransactionEvent
	Close()
}

type UtxoStore interface {
	AddUtxos(ctx context.Context, utxos []types.Utxo) (int, error)
	ReplaceUtxo(ctx context.Context, from, to types.Outpoint) error
	ConfirmUtxos(ctx context.Context, confirmedUtxos map[types.Outpoint]int64) (int, error)
	SpendUtxos(ctx context.Context, spentUtxos map[types.Outpoint]string) (int, error)
	DeleteUtxos(ctx context.Context, outpoints []types.Outpoint) (int, error)
	GetAllUtxos(ctx context.Context) (spendable, spent []types.Utxo, err error)
	GetUtxos(ctx context.Context, keys []types.Outpoint) ([]types.Utxo, error)
	GetUtxosByTxid(ctx context.Context, txid string) ([]types.Utxo, error)
	Clean(ctx context.Context) error
	GetEventChannel() <-chan UtxoEvent
	Close()
}

type VtxoStore interface {
	AddVtxos(ctx context.Context, vtxos []types.Vtxo) (int, error)
	SpendVtxos(
		ctx context.Context, spentVtxos map[types.Outpoint]string, arkTxid string,
	) (int, error)
	SettleVtxos(
		ctx context.Context, spentVtxos map[types.Outpoint]string, settledBy string,
	) (int, error)
	SweepVtxos(ctx context.Context, vtxosToSweep []types.Vtxo) (int, error)
	UnrollVtxos(ctx context.Context, vtxosToUnroll []types.Vtxo) (int, error)
	GetAllVtxos(ctx context.Context) (spendable, spent []types.Vtxo, err error)
	GetSpendableVtxos(ctx context.Context) ([]types.Vtxo, error)
	GetVtxos(ctx context.Context, keys []types.Outpoint) ([]types.Vtxo, error)
	Clean(ctx context.Context) error
	GetEventChannel() <-chan VtxoEvent
	Close()
}

type AssetStore interface {
	GetAsset(ctx context.Context, assetId string) (*types.AssetInfo, error)
	UpsertAsset(ctx context.Context, asset types.AssetInfo) error
	Clean(ctx context.Context) error
	Close()
}

type ContractStore interface {
	AddContract(ctx context.Context, c Contract) error
	ListContracts(ctx context.Context, onchain bool) ([]Contract, error)
	GetContractsByScripts(ctx context.Context, scripts []string) ([]Contract, error)
	GetContractsByState(ctx context.Context, state ContractState) ([]Contract, error)
	GetContractsByType(ctx context.Context, contractType ContractType) ([]Contract, error)
	GetOnchainContracts(ctx context.Context) ([]Contract, error)
	GetContractsByKeyIds(ctx context.Context, keyIds []string) ([]Contract, error)
	UpdateContractState(ctx context.Context, script string, state ContractState) error
	Clean(ctx context.Context) error
	Close()
}
