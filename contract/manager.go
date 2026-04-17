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
	// Close releases resources and clears the in-memory contract map.
	Close() error
}

// NewManager returns a Manager that keeps contracts in memory.
// Call Bootstrap after unlocking the wallet to populate from existing keys.
func NewManager(ks Keystore, cfg *clientTypes.Config, r *Registry) Manager {
	return &managerImpl{
		ks:        ks,
		cfg:       cfg,
		registry:  r,
		contracts: make(map[string]Contract),
	}
}

type managerImpl struct {
	ks       Keystore
	cfg      *clientTypes.Config
	registry *Registry

	mu        sync.RWMutex
	contracts map[string]Contract // scriptHex → Contract

	cbMu sync.RWMutex
	cbs  []func(Event)
}

func (m *managerImpl) Bootstrap(ctx context.Context) error {
	keys, err := m.ks.ListKeys(ctx)
	if err != nil {
		return err
	}
	h, ok := m.registry.Get("default")
	if !ok {
		return nil
	}
	for _, key := range keys {
		c, err := h.DeriveContract(ctx, key, m.cfg)
		if err != nil {
			return fmt.Errorf("bootstrap: derive contract for key %s: %w", key.Id, err)
		}
		m.mu.Lock()
		m.contracts[c.Script] = *c
		m.mu.Unlock()
	}
	return nil
}

func (m *managerImpl) NewDefault(ctx context.Context) (*Contract, error) {
	return m.createWithHandler(ctx, "default", "")
}

func (m *managerImpl) CreateContract(ctx context.Context, p CreateParams) (*Contract, error) {
	return m.createWithHandler(ctx, p.Type, p.Label)
}

func (m *managerImpl) createWithHandler(ctx context.Context, typ, label string) (*Contract, error) {
	h, ok := m.registry.Get(typ)
	if !ok {
		return nil, fmt.Errorf("no contract handler registered for type %q", typ)
	}
	key, err := m.ks.NewKey(ctx)
	if err != nil {
		return nil, err
	}
	c, err := h.DeriveContract(ctx, *key, m.cfg)
	if err != nil {
		return nil, err
	}
	c.Label = label
	c.CreatedAt = time.Now()
	m.mu.Lock()
	m.contracts[c.Script] = *c
	m.mu.Unlock()
	m.emit(Event{Type: "contract_created", Contract: *c})
	return c, nil
}

func (m *managerImpl) GetContracts(_ context.Context, f Filter) ([]Contract, error) {
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
