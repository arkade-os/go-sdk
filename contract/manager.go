package contract

import (
	"context"
	"fmt"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/go-sdk/contract/handlers"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

const logPrefix = "contract manager:"

type contractManager struct {
	store       types.ContractStore
	keyProvider keyProvider
	indexer     offchainDataProvider
	explorer    onchainDataProvider
	network     arklib.Network
	registry    Registry
	mu          sync.RWMutex
	infoCache   *infoCache
}

func NewManager(args Args, opts ...ManagerOption) (Manager, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}
	o := newDefaultManagerOption()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("manager option cannot be nil")
		}
		if err := opt(o); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	// Wrap the transport client once with a shared GetInfo cache so all
	// built-in handlers reuse the same cached server info. Custom handlers
	// supplied via WithHandler are constructed outside the manager and own
	// their own client wiring.
	cache := newInfoCache(infoCacheTTL)
	cachedClient := newCachingClient(args.Client, cache)
	builtins := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault:  defaultHandler.NewHandler(cachedClient, args.Network, false),
		types.ContractTypeBoarding: defaultHandler.NewHandler(cachedClient, args.Network, true),
	}
	reg, err := newRegistry(builtins, o.customHandlers)
	if err != nil {
		return nil, err
	}
	return &contractManager{
		store:       args.Store,
		keyProvider: args.KeyProvider,
		indexer:     args.Indexer,
		explorer:    args.Explorer,
		network:     args.Network,
		registry:    reg,
		mu:          sync.RWMutex{},
		infoCache:   cache,
	}, nil
}

func (m *contractManager) Registry() Registry { return m.registry }

func (m *contractManager) ScanContracts(ctx context.Context, gapLimit uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.keyProvider.GetType() == identity.SingleKeyIdentity {
		// A single-key identity has only one derivable contract per type, so the
		// gap-limit loop would just churn on the same script. Derive each type's
		// one contract and batch the offchain probe into a single indexer call;
		// boarding still goes per-address through the explorer.
		return m.scanSingleKeyContracts(ctx)
	}

	for _, contractType := range m.registry.SupportedTypes() {
		handler, err := m.registry.GetHandler(contractType)
		if err != nil {
			return err
		}
		// Pick the "is this contract used externally?" probe for the type:
		// boarding contracts are looked up via the explorer per-address (and
		// throttled), offchain ones via the indexer's batch GetVtxos.
		findUsed := m.findUsedContracts
		if contractType == types.ContractTypeBoarding {
			findUsed = m.findUsedBoardingContracts
		}
		if err := m.scanContracts(ctx, contractType, gapLimit, handler, findUsed); err != nil {
			return err
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

	handler, err := m.registry.GetHandler(contractType)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if o.serverInfo != nil {
		// Force a cache update if the caller provided a server info.
		m.infoCache.set(o.serverInfo)
	}

	if m.keyProvider.GetType() == identity.SingleKeyIdentity {
		// A single-key identity reuses the same key for every contract of a given type, so the
		// derived script is identical across calls. Treat a repeat as idempotent reuse and return
		// the stored contract.
		contracts, err := m.store.GetActiveContractsByType(ctx, contractType)
		if err != nil {
			return nil, err
		}
		if len(contracts) > 0 {
			contract := contracts[0]
			return &contract, nil
		}
	}

	contract, err := m.newContract(ctx, contractType, handler)
	if err != nil {
		return nil, err
	}
	contract.Label = o.label

	keyRef, err := handler.GetKeyRef(*contract)
	if err != nil {
		return nil, fmt.Errorf("failed to get key ref for contract %s: %w", contract.Script, err)
	}

	keyIndex, err := m.keyProvider.GetKeyIndex(ctx, keyRef.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to get key index for contract %s: %w", contract.Script, err)
	}

	if err := m.store.AddContract(ctx, *contract, keyIndex); err != nil {
		return nil, fmt.Errorf("failed to store contract: %w", err)
	}

	log.Debugf("%s added new contract %s", logPrefix, contract.Script)

	return contract, nil
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
	case len(f.contractType) > 0:
		return m.store.GetActiveContractsByType(ctx, f.contractType)
	default:
		return m.store.ListContracts(ctx)
	}
}

func (m *contractManager) GetHandler(
	_ context.Context, c types.Contract,
) (handlers.Handler, error) {
	return m.registry.GetHandler(c.Type)
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

	log.Debugf("%s closed contract manager", logPrefix)
}

// findUsedFn returns the subset of `contracts`, keyed by Script, that have
// been used externally — i.e. that the corresponding data source (indexer
// for offchain, explorer for boarding) has any record of. Defined as a
// callback so the gap-limit scan body below stays generic across contract
// types.
type findUsedFn func(
	ctx context.Context, contracts []types.Contract,
) (map[string]struct{}, error)

func (m *contractManager) scanContracts(
	ctx context.Context, contractType types.ContractType,
	gapLimit uint32, handler handlers.Handler, findUsed findUsedFn,
) error {
	contract, err := m.store.GetLatestActiveContract(ctx, contractType)
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
	var currentKeyId string
	if contract != nil {
		keyRef, err := handler.GetKeyRef(*contract)
		if err != nil {
			return fmt.Errorf("failed to get key ref for contract %s: %w", contract.Script, err)
		}
		currentKeyId = keyRef.Id
		currentIdx, err := m.keyProvider.GetKeyIndex(ctx, currentKeyId)
		if err != nil {
			return fmt.Errorf("failed to parse key id for contract %s: %w", contract.Script, err)
		}
		startIdx = currentIdx + 1
	}

	// Gap-limit scan. `lastUsedIdx` stays at the sentinel value until a
	// hit promotes it; if no key is ever flagged as used we leave the
	// contract store untouched.
	const noUsage int64 = -1
	var (
		lastUsedIdx       = noUsage
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
				return fmt.Errorf(
					"failed to derive %s contract for key %s: %w",
					contractType, nextKeyId, err,
				)
			}
			contractBatch = append(contractBatch, *contract)
			keyIndexByScript[contract.Script] = idx
			currentKeyId = nextKeyId
			contractByIndex[idx] = *contract
		}

		used, err := findUsed(ctx, contractBatch)
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
		if err := m.store.AddContract(ctx, contract, i); err != nil {
			return fmt.Errorf("failed to store %s contract: %w", contractType, err)
		}

		log.Debugf("%s added new %s contract %s", logPrefix, contractType, contract.Script)
	}
	return nil
}

func (m *contractManager) newContract(
	ctx context.Context,
	contractType types.ContractType, handler handlers.Handler,
) (*types.Contract, error) {
	contract, err := m.store.GetLatestActiveContract(ctx, contractType)
	if err != nil {
		return nil, err
	}

	var keyId string
	if contract != nil {
		keyRef, err := handler.GetKeyRef(*contract)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get key ref for contract %s: %w", contract.Script, err,
			)
		}
		keyId = keyRef.Id
	}

	nextKeyId, err := m.keyProvider.NextKeyId(ctx, keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to compute next key index: %w", err)
	}

	keyRef, err := m.keyProvider.GetKey(ctx, nextKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key for contract: %w", err)
	}

	return handler.NewContract(ctx, *keyRef)
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

// scanSingleKeyContracts derives the one contract each registered type can
// produce under a single-key identity and probes external state to decide
// which to persist. Offchain types are batched into a single indexer call;
// boarding types go through the per-address explorer probe (one call per
// type — at most one boarding handler is registered today).
func (m *contractManager) scanSingleKeyContracts(ctx context.Context) error {
	type pending struct {
		typ      types.ContractType
		contract types.Contract
		keyIdx   uint32
	}
	var offchain, boarding []pending

	for _, contractType := range m.registry.SupportedTypes() {
		handler, err := m.registry.GetHandler(contractType)
		if err != nil {
			return err
		}
		contracts, err := m.store.GetActiveContractsByType(ctx, contractType)
		if err != nil {
			return err
		}
		if len(contracts) > 0 {
			continue
		}
		keyId, err := m.keyProvider.NextKeyId(ctx, "")
		if err != nil {
			return err
		}
		idx, err := m.keyProvider.GetKeyIndex(ctx, keyId)
		if err != nil {
			return err
		}
		keyRef, err := m.keyProvider.GetKey(ctx, keyId)
		if err != nil {
			return err
		}
		c, err := handler.NewContract(ctx, *keyRef)
		if err != nil {
			return fmt.Errorf(
				"failed to derive %s contract for key %s: %w", contractType, keyId, err,
			)
		}
		p := pending{typ: contractType, contract: *c, keyIdx: idx}
		if contractType == types.ContractTypeBoarding {
			boarding = append(boarding, p)
		} else {
			offchain = append(offchain, p)
		}
	}

	// One indexer round-trip for every offchain type at once.
	var offchainUsed map[string]struct{}
	if len(offchain) > 0 {
		batch := make([]types.Contract, len(offchain))
		for i, p := range offchain {
			batch[i] = p.contract
		}
		used, err := m.findUsedContracts(ctx, batch)
		if err != nil {
			return err
		}
		offchainUsed = used
	}

	persist := func(p pending) error {
		if err := m.store.AddContract(ctx, p.contract, p.keyIdx); err != nil {
			return fmt.Errorf("failed to store %s contract: %w", p.typ, err)
		}
		log.Debugf("%s added new %s contract %s", logPrefix, p.typ, p.contract.Script)
		return nil
	}

	for _, p := range offchain {
		if _, isUsed := offchainUsed[p.contract.Script]; !isUsed {
			continue
		}
		if err := persist(p); err != nil {
			return err
		}
	}

	for _, p := range boarding {
		used, err := m.findUsedBoardingContracts(ctx, []types.Contract{p.contract})
		if err != nil {
			return err
		}
		if _, isUsed := used[p.contract.Script]; !isUsed {
			continue
		}
		if err := persist(p); err != nil {
			return err
		}
	}

	return nil
}
