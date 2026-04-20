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
	// Bootstrap loads contracts for all existing keys; call after wallet unlock.
	Bootstrap(ctx context.Context) error
	// NewDefault creates a new default contract by generating a fresh wallet key.
	NewDefault(ctx context.Context) (*Contract, error)
	// GetContracts returns all contracts matching the given filter.
	GetContracts(ctx context.Context, f Filter) ([]Contract, error)
	// CreateContract creates a contract of any registered type with a fresh key.
	CreateContract(ctx context.Context, p CreateParams) (*Contract, error)
	// OnContractEvent registers a callback; returns an unsubscribe func.
	OnContractEvent(cb func(Event)) func()
	// EmitEvent broadcasts an event to all registered callbacks.
	// Used by the Watcher to surface vtxo_received / vtxo_spent events.
	EmitEvent(e Event)
	// Close releases resources and clears the in-memory contract map.
	Close() error
}

// NewManager returns a Manager that keeps contracts in memory and optionally
// persists them via store (pass nil to use in-memory only).
// Call Bootstrap after unlocking the wallet to populate from existing keys.
func NewManager(ks Keystore, cfg *clientTypes.Config, r *Registry, store ContractStore) Manager {
	return &managerImpl{
		ks:        ks,
		cfg:       cfg,
		registry:  r,
		store:     store,
		contracts: make(map[string]Contract),
	}
}

type managerImpl struct {
	ks       Keystore
	cfg      *clientTypes.Config
	registry *Registry
	store    ContractStore // nil = in-memory only

	mu        sync.RWMutex
	contracts map[string]Contract // scriptHex → Contract (write-through cache)

	cbMu sync.RWMutex
	cbs  []func(Event)
}

func (m *managerImpl) Bootstrap(ctx context.Context) error {
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
	h, ok := m.registry.Get("default")
	if !ok {
		return nil
	}
	keys, err := m.ks.ListKeys(ctx)
	if err != nil {
		return err
	}
	for _, key := range keys {
		c, err := h.DeriveContract(ctx, key, m.cfg, nil)
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
	return m.createWithHandler(ctx, "default", "", nil)
}

func (m *managerImpl) CreateContract(ctx context.Context, p CreateParams) (*Contract, error) {
	return m.createWithHandler(ctx, p.Type, p.Label, p.Params)
}

func (m *managerImpl) createWithHandler(
	ctx context.Context, typ, label string, rawParams map[string]string,
) (*Contract, error) {
	h, ok := m.registry.Get(typ)
	if !ok {
		return nil, fmt.Errorf("no contract handler registered for type %q", typ)
	}
	key, err := m.ks.NewKey(ctx)
	if err != nil {
		return nil, err
	}
	c, err := h.DeriveContract(ctx, *key, m.cfg, rawParams)
	if err != nil {
		return nil, err
	}
	c.Label = label
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
	if m.store != nil {
		return m.store.ListContracts(ctx, f)
	}
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

func (m *managerImpl) OnContractEvent(cb func(Event)) func() {
	m.cbMu.Lock()
	idx := len(m.cbs)
	m.cbs = append(m.cbs, cb)
	m.cbMu.Unlock()
	return func() {
		m.cbMu.Lock()
		if idx < len(m.cbs) {
			m.cbs[idx] = nil
		}
		m.cbMu.Unlock()
	}
}

func (m *managerImpl) EmitEvent(e Event) { m.emit(e) }

func (m *managerImpl) Close() error {
	m.mu.Lock()
	m.contracts = make(map[string]Contract)
	m.mu.Unlock()
	return nil
}

func (m *managerImpl) emit(e Event) {
	m.cbMu.RLock()
	defer m.cbMu.RUnlock()
	for _, cb := range m.cbs {
		if cb != nil {
			cb(e)
		}
	}
}
