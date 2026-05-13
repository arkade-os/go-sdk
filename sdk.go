package arksdk

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
)

// modulePath identifies the SDK to the build-info reader. Must match
// the module path declared in go.mod.
const modulePath = "github.com/arkade-os/go-sdk"

// Version reports the SDK's module version as resolved by the Go module
// system at build time of the importing binary. Populated from
// runtime/debug.ReadBuildInfo on package init:
//
//   - For a binary that imported the SDK via `go get …@vX.Y.Z`, returns
//     "vX.Y.Z".
//   - For a pseudo-version (commit / branch import), returns
//     "v0.0.0-<utc-timestamp>-<short-commit-sha>".
//   - For a local replace directive (or `go test ./…` inside the SDK
//     repo itself), returns "(devel)".
//   - When build info is unavailable (vendored builds without modules,
//     certain test harnesses), returns "unknown".
//
// Wallet.Version() proxies this value, so callers can read either.
var Version = readSDKVersion()

type Wallet interface {
	Version() string
	Store() types.Store
	Identity() identity.Identity
	Explorer() explorer.Explorer
	Indexer() indexer.Indexer
	Client() client.Client
	ContractManager() contract.Manager

	Init(ctx context.Context, serverUrl, seed, password string, opts ...InitOption) error
	IsLocked(ctx context.Context) bool
	Unlock(ctx context.Context, password string) error
	Lock(ctx context.Context) error
	IsSynced(ctx context.Context) <-chan types.SyncEvent
	Balance(ctx context.Context) (*types.Balance, error)
	GetAddresses(ctx context.Context) (
		onchainAddresses, offchainAddresses, boardingAddresses, redemptionAddresses []string,
		err error,
	)
	NewOffchainAddress(ctx context.Context) (string, error)
	NewBoardingAddress(ctx context.Context) (string, error)
	NewOnchainAddress(ctx context.Context) (string, error)
	IssueAsset(
		ctx context.Context,
		amount uint64, controlAsset clienttypes.ControlAsset, metadata []asset.Metadata,
	) (string, []asset.AssetId, error)
	ReissueAsset(
		ctx context.Context, assetId string, amount uint64,
	) (string, error)
	BurnAsset(
		ctx context.Context, assetID string, amount uint64,
	) (string, error)
	SendOffChain(ctx context.Context, receivers []clienttypes.Receiver) (string, error)
	RegisterIntent(
		ctx context.Context,
		vtxos []clienttypes.Vtxo, boardingUtxos []clienttypes.Utxo, notes []string,
		outputs []clienttypes.Receiver, cosignersPublicKeys []string,
	) (intentID string, err error)
	DeleteIntent(
		ctx context.Context,
		vtxos []clienttypes.Vtxo, boardingUtxos []clienttypes.Utxo, notes []string,
	) error
	Settle(ctx context.Context, opts ...BatchSessionOption) (string, error)
	CollaborativeExit(
		ctx context.Context, addr string, amount uint64, opts ...BatchSessionOption,
	) (string, error)
	Unroll(ctx context.Context) error
	CompleteUnroll(ctx context.Context, to string) (string, error)
	OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error)
	WithdrawFromAllExpiredBoardings(ctx context.Context, to string) (string, error)
	ListVtxos(ctx context.Context) (spendable, spent []clienttypes.Vtxo, err error)
	ListSpendableVtxos(ctx context.Context) ([]clienttypes.Vtxo, error)
	Dump(ctx context.Context) (seed string, err error)
	GetTransactionHistory(ctx context.Context) ([]clienttypes.Transaction, error)
	GetTransactionEventChannel(ctx context.Context) <-chan types.TransactionEvent
	GetVtxoEventChannel(ctx context.Context) <-chan types.VtxoEvent
	GetUtxoEventChannel(ctx context.Context) <-chan types.UtxoEvent
	RedeemNotes(ctx context.Context, notes []string) (string, error)
	SignTransaction(ctx context.Context, tx string) (string, error)
	NotifyIncomingFunds(ctx context.Context, address string) ([]clienttypes.Vtxo, error)
	FinalizePendingTxs(ctx context.Context, createdAfter *time.Time) ([]string, error)
	Reset(ctx context.Context)
	Stop()
	// WhenNextSettlement returns the time at which the next automatic settlement
	// is scheduled to fire. Returns the zero time.Time when auto-settle is
	// disabled or no settlement is currently scheduled.
	WhenNextSettlement() time.Time
}
