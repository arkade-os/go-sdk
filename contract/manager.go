package contract

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract/handlers"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
)

const logPrefix = "contract manager:"

// keyIndexResolver is the subset of wallet.WalletService the manager needs to
// reason about contract ordering by derivation index. Kept unexported so the
// manager owns its dependency surface and we can grow it as needed.
type keyIndexResolver interface {
	GetKeyIndex(ctx context.Context, id string) (uint32, error)
}

type managerImpl struct {
	store    types.ContractStore
	resolver keyIndexResolver
	network  arklib.Network
	// TODO: this must become a registry so that users can register their custom handlers at will.
	handlers map[types.ContractType]handlers.Handler
	mu       sync.RWMutex
}

func NewManager(
	store types.ContractStore,
	network arklib.Network,
	client client.TransportClient,
	resolver keyIndexResolver,
) (Manager, error) {
	// TODO: 1. support also delegate and vhtlc handlers
	// TODO: 2. make use of a register to allow extending the contract manager with custom handlers
	handlers := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault: defaultHandler.NewHandler(client, network),
	}
	return &managerImpl{
		store:    store,
		resolver: resolver,
		handlers: handlers,
		network:  network,
		mu:       sync.RWMutex{},
	}, nil
}

func (m *managerImpl) NewContract(
	ctx context.Context,
	contractType types.ContractType, keyRef wallet.KeyRef, opts ...ContractOption,
) (*types.Contract, error) {
	if len(contractType) <= 0 {
		return nil, fmt.Errorf("missing contract type")
	}
	if len(keyRef.Id) <= 0 {
		return nil, fmt.Errorf("missing public key id")
	}
	if keyRef.PubKey == nil {
		return nil, fmt.Errorf("missing public key")
	}

	o := newDefaultContractOption()
	for _, opt := range opts {
		if err := opt.applyContract(o); err != nil {
			return nil, fmt.Errorf("invalid contract option: %w", err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	handler, ok := m.handlers[contractType]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contractType)
	}

	contract, err := handler.NewContract(ctx, keyRef, toHandlerOpts(o)...)
	if err != nil {
		return nil, err
	}
	contract.Label = o.label

	if o.dryRun {
		return contract, nil
	}

	if err := m.store.AddContract(ctx, *contract); err != nil {
		return nil, fmt.Errorf("failed to store contract: %w", err)
	}

	log.Debugf("%s added new contract %s", logPrefix, contract.Script)

	return contract, nil
}

func (m *managerImpl) GetSupportedContractTypes(_ context.Context) []types.ContractType {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return slices.Collect(maps.Keys(m.handlers))
}

func (m *managerImpl) GetContracts(
	ctx context.Context, opts ...FilterOption,
) ([]types.Contract, error) {
	f := newDefaultFilter()
	for _, opt := range opts {
		if err := opt.applyFilter(f); err != nil {
			return nil, err
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch {
	case len(f.scripts) > 0:
		return m.store.GetContractsByScripts(ctx, f.scripts)
	case len(f.state) > 0:
		return m.store.GetContractsByState(ctx, f.state)
	case len(f.keyIds) > 0:
		return m.store.GetContractsByKeyIds(ctx, f.keyIds)
	case len(f.contractType) > 0:
		return m.store.GetContractsByType(ctx, f.contractType)
	case f.isOnchain:
		return m.store.GetOnchainContracts(ctx)
	default:
		return m.store.ListContracts(ctx, false)
	}
}

func (m *managerImpl) GetLatestContractKeyId(
	ctx context.Context, contractType types.ContractType, opts ...ContractOption,
) (string, error) {
	if len(contractType) <= 0 {
		return "", fmt.Errorf("missing contract type")
	}
	o := newDefaultContractOption()
	for _, opt := range opts {
		if err := opt.applyContract(o); err != nil {
			return "", fmt.Errorf("invalid contract option: %w", err)
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	handler, ok := m.handlers[contractType]
	if !ok {
		return "", fmt.Errorf("unsupported contract type: %s", contractType)
	}
	contracts, err := m.store.GetContractsByType(ctx, contractType)
	if err != nil {
		return "", err
	}

	var (
		latestKeyID    string
		latestKeyIndex uint32
		found          bool
	)
	for _, c := range contracts {
		var isOnchain bool
		if val, ok := c.Params[types.ContractParamIsOnchain]; ok {
			isOnchain, err = strconv.ParseBool(val)
			if err != nil {
				return "", fmt.Errorf(
					"invalid %s param format: epxected bool, got %s",
					types.ContractParamIsOnchain, val,
				)
			}
			if isOnchain != o.isOnchain {
				continue
			}
		}
		keyRef, err := handler.GetKeyRef(c)
		if err != nil {
			return "", err
		}
		index, err := m.resolver.GetKeyIndex(ctx, keyRef.Id)
		if err != nil {
			return "", fmt.Errorf("failed to resolve key index for id %s: %w", keyRef.Id, err)
		}
		if !found || index > latestKeyIndex {
			latestKeyID = keyRef.Id
			latestKeyIndex = index
			found = true
		}
	}
	return latestKeyID, nil
}

func (m *managerImpl) GetKeyRefs(
	_ context.Context, contract types.Contract,
) (map[string]string, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}

	return handler.GetKeyRefs(contract)
}

func (m *managerImpl) GetSignerKey(
	_ context.Context, contract types.Contract,
) (*btcec.PublicKey, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}
	return handler.GetSignerKey(contract)
}

func (m *managerImpl) GetExitDelay(
	_ context.Context, contract types.Contract,
) (*arklib.RelativeLocktime, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}
	return handler.GetExitDelay(contract)
}

func (m *managerImpl) GetTapscripts(_ context.Context, contract types.Contract) ([]string, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}
	return handler.GetTapscripts(contract)
}

func (m *managerImpl) Clean(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.store.Clean(ctx); err != nil {
		return err
	}

	log.Debugf("%s cleaned contract store", logPrefix)
	return nil
}

func (m *managerImpl) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.store.Close()

	log.Debugf("%s closed contract store", logPrefix)
}

func toHandlerOpts(opts *contractOption) []handlers.ContractOption {
	handlerOpts := make([]handlers.ContractOption, 0)
	if opts.isOnchain {
		handlerOpts = append(handlerOpts, handlers.WithIsOnchain())
	}
	return handlerOpts
}
