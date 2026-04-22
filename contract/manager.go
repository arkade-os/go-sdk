package contract

import (
	"context"
	"fmt"
	"sync"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

// Manager manages the lifecycle of contracts derived from wallet keys.
type Manager interface {
	// Load loads contracts for all existing keys; call after wallet unlock.
	Load(ctx context.Context) error
	// NewDefault returns the most recently created active default contract, or
	// creates one with a fresh wallet key if none exists.
	NewDefault(ctx context.Context) (*Contract, error)
	// GetContracts returns all contracts matching the given filter.
	GetContracts(ctx context.Context, f Filter) ([]Contract, error)
	// GetContractsForVtxos returns the contracts whose Script matches any of the
	// provided vtxo script hex strings. Unknown scripts are silently omitted.
	GetContractsForVtxos(ctx context.Context, scripts []string) ([]Contract, error)
	// OnContractEvent registers a callback; returns an unsubscribe func.
	OnContractEvent(cb func(Event)) func()
	// Close releases resources and clears the in-memory contract map.
	Close() error
}

// NewManager returns a Manager that keeps contracts in memory and optionally
// persists them via store (pass nil to use in-memory only).
// Call Load after unlocking the wallet to populate from existing keys.
func NewManager(ks Keystore, cfg *clientTypes.Config, store ContractStore) Manager {
	return &managerImpl{
		ks:        ks,
		cfg:       cfg,
		store:     store,
		contracts: make(map[string]Contract),
		cbs:       make(map[int]func(Event)),
	}
}

type managerImpl struct {
	ks    Keystore            // wallet key operations (new / get / list)
	cfg   *clientTypes.Config // server config used by the default handler
	store ContractStore       // nil = in-memory only

	mu        sync.RWMutex
	contracts map[string]Contract // scriptHex → Contract (write-through cache)

	defaultCreateMu sync.Mutex // serializes the check-mint-persist sequence in NewDefault

	cbMu   sync.RWMutex
	cbs    map[int]func(Event) // event subscribers, keyed by monotonic ID
	cbNext int                 // next subscriber ID
}

func (m *managerImpl) Load(ctx context.Context) error {
	// Seed in-memory cache from the persistent store.
	if m.store != nil {
		stored, err := m.store.ListContracts(ctx, Filter{})
		if err != nil {
			return fmt.Errorf("bootstrap: load contracts from store: %w", err)
		}
		m.mu.Lock()
		for _, c := range stored {
			m.contracts[c.Script] = c
		}
		m.mu.Unlock()
	}

	// Derive contracts for any wallet keys that don't already have one.
	h := &DefaultHandler{}
	keys, err := m.ks.ListKeys(ctx)
	if err != nil {
		return err
	}
	for _, key := range keys {
		c, err := h.DeriveContract(ctx, key, m.cfg)
		if err != nil {
			return fmt.Errorf("bootstrap: derive contract for key %s: %w", key.Id, err)
		}
		m.mu.RLock()
		_, exists := m.contracts[c.Script]
		m.mu.RUnlock()
		if exists {
			continue
		}
		if err := m.persistAndCache(ctx, *c); err != nil {
			return fmt.Errorf("bootstrap: persist contract for key %s: %w", key.Id, err)
		}
	}
	return nil
}

func (m *managerImpl) NewDefault(ctx context.Context) (*Contract, error) {
	m.defaultCreateMu.Lock()
	defer m.defaultCreateMu.Unlock()

	typ := TypeDefault
	active := string(StateActive)
	existing, err := m.GetContracts(ctx, Filter{Type: &typ, State: &active})
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		latest := existing[0]
		for _, c := range existing[1:] {
			if c.CreatedAt.After(latest.CreatedAt) {
				latest = c
			}
		}
		return &latest, nil
	}

	key, err := m.ks.NewKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("keystore returned nil key")
	}
	c, err := (&DefaultHandler{}).DeriveContract(ctx, *key, m.cfg)
	if err != nil {
		return nil, err
	}
	c.CreatedAt = time.Now()
	if err := m.persistAndCache(ctx, *c); err != nil {
		return nil, err
	}
	m.emit(Event{Type: "contract_created", Contract: *c})
	return c, nil
}

func (m *managerImpl) persistAndCache(ctx context.Context, c Contract) error {
	if m.store != nil {
		if err := m.store.UpsertContract(ctx, c); err != nil {
			return fmt.Errorf("persist contract: %w", err)
		}
	}
	m.mu.Lock()
	m.contracts[c.Script] = c
	m.mu.Unlock()
	return nil
}

func (m *managerImpl) GetContracts(ctx context.Context, f Filter) ([]Contract, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []Contract
	for _, c := range m.contracts {
		if f.Type != nil && c.Type != *f.Type {
			continue
		}
		if f.State != nil && string(c.State) != *f.State {
			continue
		}
		if f.Script != nil && c.Script != *f.Script {
			continue
		}
		result = append(result, c)
	}
	return result, nil
}

func (m *managerImpl) GetContractsForVtxos(
	ctx context.Context,
	scripts []string,
) ([]Contract, error) {
	lookup := make(map[string]struct{}, len(scripts))
	for _, s := range scripts {
		lookup[s] = struct{}{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []Contract
	for _, c := range m.contracts {
		if _, ok := lookup[c.Script]; ok {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *managerImpl) OnContractEvent(cb func(Event)) func() {
	m.cbMu.Lock()
	idx := m.cbNext
	m.cbNext++
	m.cbs[idx] = cb
	m.cbMu.Unlock()
	return func() {
		m.cbMu.Lock()
		delete(m.cbs, idx)
		m.cbMu.Unlock()
	}
}

func (m *managerImpl) Close() error {
	m.mu.Lock()
	m.contracts = make(map[string]Contract)
	m.mu.Unlock()
	return nil
}

func (m *managerImpl) emit(e Event) {
	m.cbMu.RLock()
	cbs := make([]func(Event), 0, len(m.cbs))
	for _, cb := range m.cbs {
		cbs = append(cbs, cb)
	}
	m.cbMu.RUnlock()
	for _, cb := range cbs {
		cb(e)
	}
}
