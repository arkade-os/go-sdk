package contract

import (
	"context"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Manager manages the lifecycle of contracts derived from wallet keys.
type Manager interface {
	// GetSupportedContractTypes returns the list of contract types supported by the manager.
	GetSupportedContractTypes(ctx context.Context) []types.ContractType
	// ScanContracts
	ScanContracts(ctx context.Context, gapLimit uint32) error
	// NewContract creates and stores a new contract. The key is derived from the key provider,
	// all required parameters are fetched by the proper handler based on the contract type.
	NewContract(
		ctx context.Context, contractType types.ContractType, opts ...ContractOption,
	) (*types.Contract, error)
	// GetContracts returns all contracts matching the given filter option.
	// All filters are mutually exclusive, i.e. only one filter can be set at a time.
	// Pass no options to return all contracts.
	GetContracts(ctx context.Context, opts ...FilterOption) ([]types.Contract, error)
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

// Args contains all services and params required to create a new contract manager.
type Args struct {
	Store       types.ContractStore
	KeyProvider keyProvider
	Client      client.TransportClient
	Indexer     offchainDataProvider
	Explorer    onchainDataProvider
	Network     arklib.Network
}

// validate ensures the contract manager arguments are valid.
func (a Args) validate() error {
	if a.Store == nil {
		return fmt.Errorf("missing contracts store")
	}
	if a.KeyProvider == nil {
		return fmt.Errorf("missing key provider")
	}
	if a.Client == nil {
		return fmt.Errorf("missing client")
	}
	if a.Indexer == nil {
		return fmt.Errorf("missing indexer")
	}
	if a.Explorer == nil {
		return fmt.Errorf("missing explorer")
	}
	emptyNetwork := arklib.Network{}
	if a.Network == emptyNetwork {
		return fmt.Errorf("missing network")
	}
	return nil
}

// keyProvider is the subset of the wallet interface the manager needs to
// resolve, derive, and fetch keys for contracts. Kept unexported so the
// manager owns its dependency surface and we can grow it as needed.
type keyProvider interface {
	GetKeyIndex(ctx context.Context, id string) (uint32, error)
	NextKeyId(ctx context.Context, id string) (string, error)
	GetKey(ctx context.Context, id string) (*wallet.KeyRef, error)
}

type onchainDataProvider interface {
	GetTxs(address string) ([]explorer.Tx, error)
}

type offchainDataProvider interface {
	GetVtxos(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error)
}
