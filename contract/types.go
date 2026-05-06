package contract

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Manager manages the lifecycle of contracts derived from wallet keys.
type Manager interface {
	// GetSupportedContractTypes returns the list of contract types supported by the manager.
	GetSupportedContractTypes(ctx context.Context) []types.ContractType
	// NewContract creates and stores a new contract from the given key and optional label.
	// All required contract params are fetched by the proper handler based on the contract type.
	NewContract(
		ctx context.Context,
		contractType types.ContractType, keyRef wallet.KeyRef, opts ...ContractOption,
	) (*types.Contract, error)
	// GetContracts returns all contracts matching the given filter option.
	// All filters are mutually exclusive, i.e. only one filter can be set at a time.
	// Pass no options to return all contracts.
	GetContracts(ctx context.Context, opts ...FilterOption) ([]types.Contract, error)
	// GetLatestContractKeyId returns the key id of the latest contract of the given type,
	// or an empty string if no contract of that type exists.
	GetLatestContractKeyId(
		ctx context.Context, contractType types.ContractType, opts ...ContractOption,
	) (string, error)
	// GetKeyRefs returns a map script -> key ID for the given contract.
	// If the contract is offchain, the map includes also an entry for the eventual checkpoint
	// to be signed in an offchain tx.
	GetKeyRefs(ctx context.Context, contract types.Contract) (map[string]string, error)
	// GetSignerKey returns the signer key for the given contract.
	GetSignerKey(ctx context.Context, contract types.Contract) (*btcec.PublicKey, error)
	// GetTapscripts returns the tapscripts for the given contract.
	GetTapscripts(ctx context.Context, contract types.Contract) ([]string, error)
	// GetExitDelay returns the exit delay from the params of the given contract
	GetExitDelay(ctx context.Context, contract types.Contract) (*arklib.RelativeLocktime, error)
	// Clean removes all contracts from the store. Must be used only at wallet reset.
	Clean(ctx context.Context) error
	// Close releases any resources held by the manager.
	Close()
}
