package contract

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
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
	client      client.Client
	indexer     offchainDataProvider
	explorer    onchainDataProvider
	network     arklib.Network
	// TODO: this must become a registry so that users can register their custom handlers at will.
	handlers map[types.ContractType]handlers.Handler
	mu       sync.RWMutex

	cbMu   sync.RWMutex
	cbs    map[int]func(types.Contract)
	cbNext int
}

func NewManager(args Args) (Manager, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}
	// Wrap the transport client once with a shared GetInfo cache so all
	// handlers (default, boarding, and any future vhtlc/delegate kinds)
	// reuse the same cached server info instead of fanning out a
	// per-handler cache.
	cachedClient := newCachingClient(args.Client, newInfoCache(infoCacheTTL))
	// TODO: 1. support also delegate and vhtlc handlers
	// TODO: 2. make use of a register to allow extending the contract manager with custom handlers
	handlers := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault:  defaultHandler.NewHandler(cachedClient, args.Network, false),
		types.ContractTypeBoarding: defaultHandler.NewHandler(cachedClient, args.Network, true),
	}
	return &contractManager{
		store:       args.Store,
		keyProvider: args.KeyProvider,
		client:      cachedClient,
		indexer:     args.Indexer,
		explorer:    args.Explorer,
		handlers:    handlers,
		network:     args.Network,
		mu:          sync.RWMutex{},
		cbs:         make(map[int]func(types.Contract)),
	}, nil
}

func (m *contractManager) OnContractEvent(cb func(types.Contract)) func() {
	m.cbMu.Lock()
	id := m.cbNext
	m.cbNext++
	m.cbs[id] = cb
	m.cbMu.Unlock()
	return func() {
		m.cbMu.Lock()
		delete(m.cbs, id)
		m.cbMu.Unlock()
	}
}

func (m *contractManager) emit(c types.Contract) {
	m.cbMu.RLock()
	cbs := make([]func(types.Contract), 0, len(m.cbs))
	for _, cb := range m.cbs {
		cbs = append(cbs, cb)
	}
	m.cbMu.RUnlock()
	for _, cb := range cbs {
		cb(c)
	}
}

func (m *contractManager) ScanContracts(ctx context.Context, gapLimit uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for contractType, handler := range m.handlers {
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

	m.mu.Lock()

	handler, ok := m.handlers[contractType]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("unsupported contract type: %s", contractType)
	}

	contract, err := m.newContract(ctx, contractType, handler)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	contract.Label = o.label

	keyRef, err := handler.GetKeyRef(*contract)
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to get key ref for contract %s: %w", contract.Script, err)
	}

	keyIndex, err := m.keyProvider.GetKeyIndex(ctx, keyRef.Id)
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to get key index for contract %s: %w", contract.Script, err)
	}

	if err := m.store.AddContract(ctx, *contract, keyIndex); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to store contract: %w", err)
	}

	log.Debugf("%s added new contract %s", logPrefix, contract.Script)
	m.mu.Unlock()

	m.emit(*contract)

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
	case len(f.contractType) > 0:
		return m.store.GetContractsByType(ctx, f.contractType)
	default:
		return m.store.ListContracts(ctx)
	}
}

func (m *contractManager) GetHandler(
	_ context.Context, contract types.Contract,
) (handlers.Handler, error) {
	if contract.Type == types.ContractTypeDelegate {
		return &DelegateHandler{}, nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	handler, ok := m.handlers[contract.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported contract type: %s", contract.Type)
	}
	return handler, nil
}

func (m *contractManager) NewDelegate(
	ctx context.Context, delegateKey *btcec.PublicKey,
) (*types.Contract, error) {
	if delegateKey == nil {
		return nil, fmt.Errorf("delegate key must not be nil")
	}

	info, err := m.client.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}

	signerKeyBytes, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signer pubkey: invalid format")
	}
	signerKey, err := btcec.ParsePubKey(signerKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signer pubkey: %w", err)
	}

	delay := info.UnilateralExitDelay
	exitDelay := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeSecond,
		Value: uint32(delay),
	}
	if delay < 512 {
		exitDelay = arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: uint32(delay),
		}
	}

	cfg := DelegateConfig{
		SignerKey: signerKey,
		Network:   m.network,
		ExitDelay: exitDelay,
	}

	contract, isNew, err := m.newDelegateLocked(ctx, delegateKey, cfg)
	if err != nil {
		return nil, err
	}
	if isNew {
		m.emit(*contract)
	}
	return contract, nil
}

func (m *contractManager) newDelegateLocked(
	ctx context.Context, delegateKey *btcec.PublicKey, cfg DelegateConfig,
) (*types.Contract, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delegateKeyHex := hex.EncodeToString(delegateKey.SerializeCompressed())
	existing, err := m.findDelegateContractByKey(ctx, delegateKeyHex)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		return existing, false, nil
	}

	latestContract, err := m.store.GetLatestContract(ctx, types.ContractTypeDelegate)
	if err != nil {
		return nil, false, err
	}

	var keyId string
	if latestContract != nil {
		dh := &DelegateHandler{}
		keyRef, err := dh.GetKeyRef(*latestContract)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get key ref for latest delegate contract: %w", err)
		}
		keyId = keyRef.Id
	}

	nextKeyId, err := m.keyProvider.NextKeyId(ctx, keyId)
	if err != nil {
		return nil, false, fmt.Errorf("failed to compute next key index: %w", err)
	}

	keyRef, err := m.keyProvider.GetKey(ctx, nextKeyId)
	if err != nil {
		return nil, false, fmt.Errorf("failed to derive key for contract: %w", err)
	}

	dh := &DelegateHandler{}
	contract, err := dh.DeriveContract(ctx, *keyRef, cfg, delegateKey)
	if err != nil {
		return nil, false, err
	}

	keyIndex, err := m.keyProvider.GetKeyIndex(ctx, keyRef.Id)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get key index: %w", err)
	}

	if err := m.store.AddContract(ctx, *contract, keyIndex); err != nil {
		return nil, false, fmt.Errorf("failed to store delegate contract: %w", err)
	}

	log.Debugf("%s added new delegate contract %s", logPrefix, contract.Script)
	return contract, true, nil
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
	contract, err := m.store.GetLatestContract(ctx, contractType)
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
	contract, err := m.store.GetLatestContract(ctx, contractType)
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

func (m *contractManager) findDelegateContractByKey(
	ctx context.Context, delegateKeyHex string,
) (*types.Contract, error) {
	contracts, err := m.store.GetContractsByType(ctx, types.ContractTypeDelegate)
	if err != nil {
		return nil, fmt.Errorf("failed to query delegate contracts: %w", err)
	}
	for i := range contracts {
		if contracts[i].Params[ParamDelegateKey] == delegateKeyHex {
			return &contracts[i], nil
		}
	}
	return nil, nil
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
