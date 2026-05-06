package contract

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/go-sdk/contract/handlers"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
)

const logPrefix = "contract manager:"

type contractManager struct {
	store       types.ContractStore
	keyProvider keyProvider
	indexer     offchainDataProvider
	explorer    onchainDataProvider
	network     arklib.Network
	// TODO: this must become a registry so that users can register their custom handlers at will.
	handlers map[types.ContractType]handlers.Handler
	mu       sync.RWMutex
}

func NewManager(args Args) (Manager, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}
	// TODO: 1. support also delegate and vhtlc handlers
	// TODO: 2. make use of a register to allow extending the contract manager with custom handlers
	handlers := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault: defaultHandler.NewHandler(args.Client, args.Network),
	}
	return &contractManager{
		store:       args.Store,
		keyProvider: args.KeyProvider,
		indexer:     args.Indexer,
		explorer:    args.Explorer,
		handlers:    handlers,
		network:     args.Network,
		mu:          sync.RWMutex{},
	}, nil
}

func (m *contractManager) ScanContracts(ctx context.Context, gapLimit uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for contractType, handler := range m.handlers {
		if err := m.scanContracts(ctx, contractType, gapLimit, handler); err != nil {
			return err
		}
		if contractType == types.ContractTypeDefault {
			if err := m.scanBoardingContracts(ctx, contractType, gapLimit, handler); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *contractManager) NewContract(
	ctx context.Context, contractType types.ContractType, opts ...ContractOption,
) (*types.Contract, error) {
	if len(contractType) <= 0 {
		return nil, fmt.Errorf("missing contract type")
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

	contract, err := m.newContract(ctx, contractType, handler, o)
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

func (m *contractManager) GetSupportedContractTypes(_ context.Context) []types.ContractType {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return slices.Collect(maps.Keys(m.handlers))
}

func (m *contractManager) GetContracts(
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

func (m *contractManager) GetKeyRefs(
	_ context.Context, contract types.Contract,
) (map[string]string, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}

	return handler.GetKeyRefs(contract)
}

func (m *contractManager) GetSignerKey(
	_ context.Context, contract types.Contract,
) (*btcec.PublicKey, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}
	return handler.GetSignerKey(contract)
}

func (m *contractManager) GetExitDelay(
	_ context.Context, contract types.Contract,
) (*arklib.RelativeLocktime, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}
	return handler.GetExitDelay(contract)
}

func (m *contractManager) GetTapscripts(_ context.Context, contract types.Contract) ([]string, error) {
	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}
	return handler.GetTapscripts(contract)
}

func (m *contractManager) Clean(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.store.Clean(ctx); err != nil {
		return err
	}

	log.Debugf("%s cleaned contract store", logPrefix)
	return nil
}

func (m *contractManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.store.Close()

	log.Debugf("%s closed contract store", logPrefix)
}

func (m *contractManager) scanContracts(
	ctx context.Context,
	contractType types.ContractType, gapLimit uint32, handler handlers.Handler,
) error {
	opts := newDefaultContractOption()
	currentLastUsedKeyID, err := m.getLatestContractKeyId(ctx, contractType, handler, opts)
	if err != nil {
		return fmt.Errorf(
			"failed to get latest key id for contract type %s: %w", contractType, err,
		)
	}

	// Where to start scanning. For a fresh wallet (no contracts of this
	// type stored yet) we scan from index 0; otherwise strictly after
	// the last stored index, since everything up to it is already
	// allocated.
	var startIdx uint32
	if currentLastUsedKeyID != "" {
		currentIdx, err := m.keyProvider.GetKeyIndex(ctx, currentLastUsedKeyID)
		if err != nil {
			return fmt.Errorf("failed to parse latest key id: %w", err)
		}
		startIdx = currentIdx + 1
	}

	// Gap-limit scan. `lastUsedIdx` stays at the sentinel value until
	// an indexer hit promotes it; if no key is ever flagged as used we
	// leave the contract store untouched.
	const noUsage int64 = -1
	var (
		lastUsedIdx       = noUsage
		currentKeyId      = currentLastUsedKeyID
		consecutiveUnused uint32
		contractByIndex   = make(map[uint32]types.Contract, gapLimit)
	)
scan:
	for consecutiveUnused < gapLimit {
		contractBatch := make([]types.Contract, 0, gapLimit)
		keyIndexByScript := make(map[string]uint32, gapLimit)
		for range gapLimit {
			nextKeyId, err := m.keyProvider.NextKeyId(ctx, currentKeyId)
			if err != nil {
				return err
			}
			idx, err := m.keyProvider.GetKeyIndex(ctx, nextKeyId)
			if err != nil {
				return err
			}
			keyRef, err := m.keyProvider.GetKey(ctx, nextKeyId)
			if err != nil {
				return err
			}
			contract, err := handler.NewContract(ctx, *keyRef)
			if err != nil {
				return fmt.Errorf("failed to derive contract for key %s: %w", nextKeyId, err)
			}
			contractBatch = append(contractBatch, *contract)
			keyIndexByScript[contract.Script] = idx
			currentKeyId = nextKeyId
			contractByIndex[idx] = *contract
		}

		used, err := m.findUsedContracts(ctx, contractBatch)
		if err != nil {
			return err
		}

		for _, c := range contractBatch {
			idx := keyIndexByScript[c.Script]
			if _, isUsed := used[c.Script]; isUsed {
				if int64(idx) > lastUsedIdx {
					lastUsedIdx = int64(idx)
				}
				consecutiveUnused = 0
				continue
			}
			consecutiveUnused++
			if consecutiveUnused >= gapLimit {
				break scan
			}
		}
	}

	if lastUsedIdx == noUsage {
		return nil
	}

	// Persist contracts from the start of the scan range up to the
	// highest used index (inclusive).
	for i := startIdx; i <= uint32(lastUsedIdx); i++ {
		contract := contractByIndex[i]
		if err := m.store.AddContract(ctx, contract); err != nil {
			return fmt.Errorf("failed to store contract: %w", err)
		}

		log.Debugf("%s added new contract %s", logPrefix, contract.Script)
	}
	return nil
}

func (m *contractManager) scanBoardingContracts(
	ctx context.Context,
	contractType types.ContractType, gapLimit uint32, handler handlers.Handler,
) error {
	opts := newDefaultContractOption()
	opts.isOnchain = true
	handlerOpts := toHandlerOpts(opts)

	currentLastUsedKeyID, err := m.getLatestContractKeyId(ctx, contractType, handler, opts)
	if err != nil {
		return fmt.Errorf(
			"failed to get latest key id for contract type %s: %w", contractType, err,
		)
	}

	// Where to start scanning. For a fresh wallet (no contracts of this
	// type stored yet) we scan from index 0; otherwise strictly after
	// the last stored index, since everything up to it is already
	// allocated.
	var startIdx uint32
	if currentLastUsedKeyID != "" {
		currentIdx, err := m.keyProvider.GetKeyIndex(ctx, currentLastUsedKeyID)
		if err != nil {
			return fmt.Errorf("failed to parse latest key id: %w", err)
		}
		startIdx = currentIdx + 1
	}

	// Gap-limit scan. `lastUsedIdx` stays at the sentinel value until
	// an indexer hit promotes it; if no key is ever flagged as used we
	// leave the contract store untouched.
	const noUsage int64 = -1
	var (
		lastUsedIdx       = noUsage
		currentKeyId      = currentLastUsedKeyID
		consecutiveUnused uint32
		contractByIndex   = make(map[uint32]types.Contract, gapLimit)
	)
scan:
	for consecutiveUnused < gapLimit {
		contractBatch := make([]types.Contract, 0, gapLimit)
		keyIndexByScript := make(map[string]uint32, gapLimit)
		for range gapLimit {
			nextKeyId, err := m.keyProvider.NextKeyId(ctx, currentKeyId)
			if err != nil {
				return err
			}
			idx, err := m.keyProvider.GetKeyIndex(ctx, nextKeyId)
			if err != nil {
				return err
			}
			keyRef, err := m.keyProvider.GetKey(ctx, nextKeyId)
			if err != nil {
				return err
			}
			contract, err := handler.NewContract(ctx, *keyRef, handlerOpts...)
			if err != nil {
				return fmt.Errorf(
					"failed to create boarding contract for key %s: %w", nextKeyId, err,
				)
			}
			contractBatch = append(contractBatch, *contract)
			keyIndexByScript[contract.Script] = idx
			currentKeyId = nextKeyId
			contractByIndex[idx] = *contract
		}

		used, err := m.findUsedBoardingContracts(ctx, contractBatch)
		if err != nil {
			return err
		}

		for _, c := range contractBatch {
			idx := keyIndexByScript[c.Script]
			if _, isUsed := used[c.Script]; isUsed {
				if int64(idx) > lastUsedIdx {
					lastUsedIdx = int64(idx)
				}
				consecutiveUnused = 0
				continue
			}
			consecutiveUnused++
			if consecutiveUnused >= gapLimit {
				break scan
			}
		}
	}

	if lastUsedIdx == noUsage {
		return nil
	}

	// Persist contracts from the start of the scan range up to the
	// highest used index (inclusive).
	for i := startIdx; i <= uint32(lastUsedIdx); i++ {
		contract := contractByIndex[i]
		if err := m.store.AddContract(ctx, contract); err != nil {
			return fmt.Errorf("failed to store boarding contract: %w", err)
		}

		log.Debugf("%s added new boarding contract %s", logPrefix, contract.Script)
	}
	return nil
}

func (m *contractManager) newContract(
	ctx context.Context,
	contractType types.ContractType, handler handlers.Handler, opts *contractOption,
) (*types.Contract, error) {
	keyId, err := m.getLatestContractKeyId(ctx, types.ContractTypeDefault, handler, opts)
	if err != nil {
		return nil, err
	}

	nextKeyID, err := m.keyProvider.NextKeyId(ctx, keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to compute next key index: %w", err)
	}

	keyRef, err := m.keyProvider.GetKey(ctx, nextKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key for contract: %w", err)
	}

	return handler.NewContract(ctx, *keyRef, toHandlerOpts(opts)...)
}

func (m *contractManager) getLatestContractKeyId(
	ctx context.Context,
	contractType types.ContractType, handler handlers.Handler, o *contractOption,
) (string, error) {
	if len(contractType) <= 0 {
		return "", fmt.Errorf("missing contract type")
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
		index, err := m.keyProvider.GetKeyIndex(ctx, keyRef.Id)
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

func (m *contractManager) findUsedContracts(
	ctx context.Context, contracts []types.Contract,
) (map[string]struct{}, error) {
	if len(contracts) <= 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(contracts))
	for _, c := range contracts {
		scripts = append(scripts, c.Script)
	}

	resp, err := m.indexer.GetVtxos(ctx, indexer.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	used := make(map[string]struct{})
	for _, vtxo := range resp.Vtxos {
		used[vtxo.Script] = struct{}{}
	}
	return used, nil
}

func (m *contractManager) findUsedBoardingContracts(
	ctx context.Context, contracts []types.Contract,
) (map[string]struct{}, error) {
	used := make(map[string]struct{})
	for i, c := range contracts {
		txs, err := m.explorer.GetTxs(c.Address)
		if err != nil {
			return nil, err
		}

		if len(txs) > 0 {
			used[c.Script] = struct{}{}
		}

		// Throttle to avoid rate limiting (20 reqs/sec)
		if (i+1)%20 == 0 {
			time.Sleep(time.Second)
		}
	}
	return used, nil
}

func toHandlerOpts(opts *contractOption) []handlers.ContractOption {
	handlerOpts := make([]handlers.ContractOption, 0)
	if opts.isOnchain {
		handlerOpts = append(handlerOpts, handlers.WithIsOnchain())
	}
	return handlerOpts
}
