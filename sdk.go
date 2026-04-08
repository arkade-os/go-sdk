package arksdk

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	transport "github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/types"
)

var Version string

type ArkClient interface {
	Explorer() explorer.Explorer
	Indexer() indexer.Indexer
	Client() transport.TransportClient

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
	SendOffChain(
		ctx context.Context, receivers []clientTypes.Receiver, opts ...SendOffChainOption,
	) (string, error)
	// GetAssetDetails returns the AssetInfo (id, control asset id, metadata)
	// that was persisted to the local AssetStore at issuance time. It queries
	// the local store only — it does NOT make an indexer round-trip. Callers
	// that need supply or remote-only data should use the Indexer() directly.
	//
	// Returns an error if the asset is not present in the local store.
	GetAssetDetails(ctx context.Context, assetId string) (*clientTypes.AssetInfo, error)
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
	ListVtxos(ctx context.Context) (spendable, spent []clientTypes.Vtxo, err error)
	ListSpendableVtxos(ctx context.Context) ([]clientTypes.Vtxo, error)
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

type SendOffChainOption = client.SendOption

// WithExtension re-exports the client-lib option to append additional
// extension.Packet values to the OP_RETURN extension blob written by
// SendOffChain.
//
// 0x00 is reserved type for asset packet (auto-generated)
func WithExtension(packets ...extension.Packet) SendOffChainOption {
	return client.WithExtraCustomPacket(packets...)
}
