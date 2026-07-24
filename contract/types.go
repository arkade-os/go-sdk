package contract

import (
	"context"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Manager manages the lifecycle of contracts derived from wallet keys.
// Constructed by NewManager; the registered handler set is sealed at that point — see Registry()
// and contract.WithHandler.
type Manager interface {
	// Registry returns the sealed handler registry. Use it to discover which contract types this
	// manager supports.
	Registry() Registry
	// ScanContracts looks for untracked contracts to store of any type, and for each of them stops
	// when gapLimit consecutive unused contracts have been found.
	ScanContracts(ctx context.Context, gapLimit uint32) error
	// NewContract creates and stores a new contract. By default the key is derived
	// from the wallet's identity provider. Callers that must advertise a wallet
	// key before all contract params are known can pass WithKeyRef to store the
	// contract with that preselected key. Non-derivable types (HTLC, VHTLC,
	// delegate) require WithParams with handler-specific parameters.
	NewContract(
		ctx context.Context, contractType types.ContractType, opts ...ContractOption,
	) (*types.Contract, error)
	// ImportContract allows to load into the contract manager a contract that was created
	// externally.
	// Example: a client requests a swap to Boltz and gets a taproot tree with vhtlc params in
	// response. Since that contract contains an identity key, the client can and should import
	// that contract with this API and handle the claim/refund flow with the manager.
	ImportContract(ctx context.Context, contract types.Contract) error
	// GetContracts returns all contracts matching the given filter option.
	// All filters are mutually exclusive, i.e. only one filter can be set at a time.
	// Pass no options to return all contracts.
	GetContracts(ctx context.Context, opts ...FilterOption) ([]types.Contract, error)
	// GetHandler returns the handler responsible for the given contract's type.
	// Errors when the contract type is not registered.
	// Delegates to Registry().GetHandler(contract.Type).
	GetHandler(ctx context.Context, contract types.Contract) (handlers.Handler, error)
	// Clean removes all contracts from the store. Must be used only at
	// wallet reset.
	Clean(ctx context.Context) error
	// Close releases any resources held by the manager.
	Close()
}

// Args contains all services and params required to create a new contract manager.
type Args struct {
	Store       types.ContractStore
	KeyProvider keyProvider
	Client      client.Client
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

type VHTLCContractArgs struct {
	Sender                               *btcec.PublicKey
	Receiver                             *btcec.PublicKey
	PreimageHash                         []byte
	RefundLocktime                       arklib.AbsoluteLocktime
	UnilateralClaimDelay                 arklib.RelativeLocktime
	UnilateralRefundDelay                arklib.RelativeLocktime
	UnilateralRefundWithoutReceiverDelay arklib.RelativeLocktime
	NonInteractiveReceiver               []byte
	NonInteractiveEmulator               *btcec.PublicKey
}

func (a VHTLCContractArgs) validate(withNonInteractiveValidation bool) error {
	senderSet := a.Sender != nil
	receiverSet := a.Receiver != nil
	if senderSet == receiverSet {
		if !senderSet {
			return fmt.Errorf("missing external sender or receiver")
		}
		return fmt.Errorf("sender and receiver must not be both specified")
	}
	if len(a.PreimageHash) <= 0 {
		return fmt.Errorf("missing preimage hash")
	}
	if a.RefundLocktime == 0 {
		return fmt.Errorf("missing refund locktime")
	}
	if a.UnilateralClaimDelay.Value == 0 {
		return fmt.Errorf("missing unilateral claim delay")
	}
	if a.UnilateralRefundDelay.Value == 0 {
		return fmt.Errorf("missing unilateral refund delay")
	}
	if a.UnilateralRefundWithoutReceiverDelay.Value == 0 {
		return fmt.Errorf("missing unilateral refund without receiver delay")
	}
	if withNonInteractiveValidation {
		if len(a.NonInteractiveReceiver) <= 0 {
			return fmt.Errorf("missing non-interactive receiver script")
		}
		if a.NonInteractiveEmulator == nil {
			return fmt.Errorf("missing non-interactive emulator")
		}
	}
	return nil
}

// keyProvider is the subset of the wallet interface the manager needs to
// resolve, derive, and fetch keys for contracts. Kept unexported so the
// manager owns its dependency surface and we can grow it as needed.
type keyProvider interface {
	GetType() string
	GetKeyIndex(ctx context.Context, id string) (uint32, error)
	NextKeyId(ctx context.Context, id string) (string, error)
	GetKey(ctx context.Context, id string) (*identity.KeyRef, error)
}

type onchainDataProvider interface {
	GetTxs(address string) ([]explorer.Tx, error)
}

type offchainDataProvider interface {
	GetVtxos(
		ctx context.Context, opts ...indexer.GetVtxosOption,
	) (*indexer.VtxosResponse, error)
}
