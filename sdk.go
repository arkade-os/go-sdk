package arksdk

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	transport "github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
)

var Version string

type ArkClient interface {
	Store() types.Store
	Wallet() wallet.WalletService
	Explorer() explorer.Explorer
	Indexer() indexer.Indexer
	Client() transport.TransportClient
	ContractManager() contract.Manager

	GetVersion() string
	GetConfigStore() clientTypes.ConfigStore
	GetConfigData(ctx context.Context) (*clientTypes.Config, error)
	Init(ctx context.Context, serverUrl, seed, password string, opts ...InitOption) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	IsSynced(ctx context.Context) <-chan types.SyncEvent
	Balance(ctx context.Context) (*client.Balance, error)
	GetAddresses(ctx context.Context) (
		onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
		err error,
	)
	NewOffchainAddress(ctx context.Context) (string, error)
	NewBoardingAddress(ctx context.Context) (string, error)
	NewOnchainAddress(ctx context.Context) (string, error)
	IssueAsset(
		ctx context.Context,
		amount uint64, controlAsset clientTypes.ControlAsset, metadata []asset.Metadata,
	) (string, []asset.AssetId, error)
	ReissueAsset(
		ctx context.Context, assetId string, amount uint64,
	) (string, error)
	BurnAsset(
		ctx context.Context, assetID string, amount uint64,
	) (string, error)
	SendOffChain(ctx context.Context, receivers []clientTypes.Receiver) (string, error)
	RegisterIntent(
		ctx context.Context,
		vtxos []clientTypes.Vtxo, boardingUtxos []clientTypes.Utxo, notes []string,
		outputs []clientTypes.Receiver, cosignersPublicKeys []string,
	) (intentID string, err error)
	DeleteIntent(
		ctx context.Context,
		vtxos []clientTypes.Vtxo, boardingUtxos []clientTypes.Utxo, notes []string,
	) error
	Settle(ctx context.Context, opts ...BatchSessionOption) (string, error)
	CollaborativeExit(
		ctx context.Context, addr string, amount uint64, opts ...BatchSessionOption,
	) (string, error)
	Unroll(ctx context.Context) error
	CompleteUnroll(ctx context.Context, to string) (string, error)
	OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error)
	WithdrawFromAllExpiredBoardings(ctx context.Context, to string) (string, error)
	ListVtxos(ctx context.Context, page types.Page, filter types.VtxoFilter) ([]clientTypes.Vtxo, error)
	Dump(ctx context.Context) (seed string, err error)
	GetTransactionHistory(ctx context.Context) ([]clientTypes.Transaction, error)
	GetTransactionEventChannel(ctx context.Context) <-chan types.TransactionEvent
	GetVtxoEventChannel(ctx context.Context) <-chan types.VtxoEvent
	GetUtxoEventChannel(ctx context.Context) <-chan types.UtxoEvent
	RedeemNotes(ctx context.Context, notes []string) (string, error)
	SignTransaction(ctx context.Context, tx string) (string, error)
	NotifyIncomingFunds(ctx context.Context, address string) ([]clientTypes.Vtxo, error)
	FinalizePendingTxs(ctx context.Context, createdAfter *time.Time) ([]string, error)
	Reset(ctx context.Context)
	Stop()
	// WhenNextSettlement returns the time at which the next automatic settlement
	// is scheduled to fire. Returns the zero time.Time when auto-settle is
	// disabled or no settlement is currently scheduled.
	WhenNextSettlement() time.Time
}

type InitArgs struct {
	WalletType  string
	ServerUrl   string
	Seed        string
	Password    string
	ExplorerURL string
}

type InitWithWalletArgs struct {
	Wallet      wallet.WalletService
	ServerUrl   string
	Seed        string
	Password    string
	ExplorerURL string
}
