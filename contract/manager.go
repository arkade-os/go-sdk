package contract

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Manager manages the lifecycle of contracts derived from wallet keys.
type Manager interface {
	// Load loads contracts for all existing keys; call after wallet unlock.
	Load(ctx context.Context) error
	// NewDefault returns the most recently created active offchain (TypeDefault)
	// contract, or creates one with a fresh wallet key if none exists. Boarding
	// and onchain contracts for the same key are derived and persisted as a
	// side effect; retrieve them via GetContracts with a KeyID filter.
	//
	// Address reuse is intentional here: the Ark server already knows all VTXOs
	// and their scripts, so rotating keys per request does not improve privacy
	// against the server. A stable boarding address is also preferable for
	// deposit UX. Per-payment key derivation (e.g. for HTLC-style contracts)
	// will be introduced via the handler registry in a follow-up PR.
	NewDefault(ctx context.Context) (*Contract, error)
	// GetContracts returns all contracts matching the given options.
	// Pass no options to return all contracts.
	GetContracts(ctx context.Context, opts ...FilterOption) ([]Contract, error)
	// GetContractsForVtxos returns the contracts whose Script matches any of the
	// provided vtxo script hex strings. Unknown scripts are silently omitted.
	GetContractsForVtxos(ctx context.Context, scripts []string) ([]Contract, error)
	// NewDelegate returns the most recently created active delegate contract for
	// the given delegate public key, or creates one with a fresh wallet key if
	// none exists. Only an offchain contract is produced.
	NewDelegate(ctx context.Context, delegateKey *btcec.PublicKey) (*Contract, error)
	// SelectPath selects the appropriate tapscript leaf for the contract type and spend context.
	SelectPath(ctx context.Context, c *Contract, pctx PathContext) (*PathSelection, error)
	// GetSpendablePaths returns all spendable tapscript paths for the contract type and spend context.
	GetSpendablePaths(ctx context.Context, c *Contract, pctx PathContext) ([]PathSelection, error)
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

	defaultCreateMu  sync.Mutex // serializes the check-mint-persist sequence in NewDefault
	delegateCreateMu sync.Mutex // serializes the check-mint-persist sequence in NewDelegate

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
		// Check which contract types already exist for this key. We expect all
		// three (offchain, boarding, onchain). If any are missing — e.g. because a
		// previous NewDefault call persisted the offchain contract and then crashed
		// before writing the siblings then re-derive the full set and persist only the
		// missing contracts. DeriveContracts is deterministic so this is safe.
		existing, err := m.GetContracts(ctx, WithKeyID(key.Id))
		if err != nil {
			return err
		}
		existingByType := make(map[string]bool, len(existing))
		for _, c := range existing {
			existingByType[c.Type] = true
		}
		// Keys created by NewDelegate only have TypeDelegate contracts and should
		// never receive default contracts as a side effect. Skip derivation only
		// when the key already has contracts but none are default-type. A key with
		// no contracts at all is a partially-crashed NewDefault call and must still
		// go through derivation.
		hasAnyDefault := existingByType[TypeDefault] || existingByType[TypeDefaultBoarding] ||
			existingByType[TypeDefaultOnchain]
		if len(existing) > 0 && !hasAnyDefault {
			continue
		}
		if existingByType[TypeDefault] && existingByType[TypeDefaultBoarding] &&
			existingByType[TypeDefaultOnchain] {
			continue
		}
		contracts, err := h.DeriveContracts(ctx, key, m.cfg)
		if err != nil {
			return fmt.Errorf("bootstrap: derive contracts for key %s: %w", key.Id, err)
		}
		for _, c := range contracts {
			if existingByType[c.Type] {
				continue // already persisted; don't overwrite label/state/metadata
			}
			if err := m.persistAndCache(ctx, *c); err != nil {
				return fmt.Errorf("bootstrap: persist contract for key %s: %w", key.Id, err)
			}
		}
	}
	return nil
}

func (m *managerImpl) NewDefault(ctx context.Context) (*Contract, error) {
	m.defaultCreateMu.Lock()
	defer m.defaultCreateMu.Unlock()

	existing, err := m.GetContracts(ctx,
		WithType(TypeDefault),
		WithState(StateActive),
		WithIsOnchain(false),
	)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		// Reuse the most recent active contract. All three address facets
		// (offchain, boarding, onchain) come from the same key, so the caller
		// receives the same addresses on every request. See the interface comment
		// on NewDefault for why this is intentional.
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
	contracts, err := (&DefaultHandler{}).DeriveContracts(ctx, *key, m.cfg)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var offchain *Contract
	for _, c := range contracts {
		c.CreatedAt = now
		if err := m.persistAndCache(ctx, *c); err != nil {
			return nil, err
		}
		m.emit(Event{Type: "contract_created", Contract: *c})
		if c.Type == TypeDefault {
			offchain = c
		}
	}
	if offchain == nil {
		return nil, fmt.Errorf("DeriveContracts did not return an offchain contract")
	}
	return offchain, nil
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

func (m *managerImpl) GetContracts(ctx context.Context, opts ...FilterOption) ([]Contract, error) {
	f := &Filter{}
	for _, opt := range opts {
		opt(f)
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
		if f.IsOnchain != nil && c.IsOnchain != *f.IsOnchain {
			continue
		}
		if f.KeyID != nil && c.Params[ParamKeyID] != *f.KeyID {
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

	m.cbMu.Lock()
	m.cbs = make(map[int]func(Event))
	m.cbMu.Unlock()

	return nil
}

func (m *managerImpl) NewDelegate(
	ctx context.Context,
	delegateKey *btcec.PublicKey,
) (*Contract, error) {
	if delegateKey == nil {
		return nil, fmt.Errorf("delegate key must not be nil")
	}

	m.delegateCreateMu.Lock()
	defer m.delegateCreateMu.Unlock()

	delegateKeyHex := hex.EncodeToString(schnorr.SerializePubKey(delegateKey))
	existing, err := m.GetContracts(ctx, WithType(TypeDelegate), WithState(StateActive))
	if err != nil {
		return nil, err
	}
	for i := range existing {
		if existing[i].Params[ParamDelegateKey] == delegateKeyHex {
			return &existing[i], nil
		}
	}

	key, err := m.ks.NewKey(ctx)
	if err != nil {
		return nil, err
	}

	if key == nil {
		return nil, fmt.Errorf("keystore returned nil key")
	}

	c, err := (&DelegateHandler{}).DeriveContract(ctx, *key, m.cfg, delegateKey)
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

func (m *managerImpl) SelectPath(
	ctx context.Context, c *Contract, pctx PathContext,
) (*PathSelection, error) {
	switch c.Type {
	case TypeDefault, TypeDefaultBoarding, TypeDefaultOnchain:
		return (&DefaultHandler{}).SelectPath(ctx, c, pctx)
	case TypeDelegate:
		return (&DelegateHandler{}).SelectPath(ctx, c, pctx)
	default:
		return nil, fmt.Errorf("SelectPath: unsupported contract type %q", c.Type)
	}
}

func (m *managerImpl) GetSpendablePaths(
	ctx context.Context, c *Contract, pctx PathContext,
) ([]PathSelection, error) {
	switch c.Type {
	case TypeDefault, TypeDefaultBoarding, TypeDefaultOnchain:
		return (&DefaultHandler{}).GetSpendablePaths(ctx, c, pctx)
	case TypeDelegate:
		return (&DelegateHandler{}).GetSpendablePaths(ctx, c, pctx)
	default:
		return nil, fmt.Errorf("GetSpendablePaths: unsupported contract type %q", c.Type)
	}
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
