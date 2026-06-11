package contract

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/go-sdk/contract/handlers"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

const logPrefix = "contract manager:"

// signerHex returns the canonical x-only (32-byte) hex of a signer pubkey.
// Used as the map key for per-signer scan state so the same key always
// resolves to the same bucket regardless of how it arrived on the wire
// (33-byte compressed or 32-byte x-only).
func signerHex(key *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

// acceptedSigners returns the full set of signer pubkeys discovery must try,
// derived from a single GetInfo response: the current signer first, followed
// by every deprecated signer. Every key is normalized to x-only and the set
// is deduplicated (a deprecated entry equal to the current key, or a repeated
// deprecated key, collapses to one). Malformed entries are skipped with a
// warning — discovery (and therefore Unlock) must never fail because the
// server advertised a bad deprecated key.
func acceptedSigners(info *client.Info) []*btcec.PublicKey {
	seen := make(map[string]struct{})
	result := make([]*btcec.PublicKey, 0, 1+len(info.DeprecatedSignerPubKeys))

	addKey := func(hexStr string) {
		buf, err := hex.DecodeString(hexStr)
		if err != nil {
			log.Warnf("%s skipping malformed signer key %q: %v", logPrefix, hexStr, err)
			return
		}
		key, err := btcec.ParsePubKey(buf)
		if err != nil {
			log.Warnf("%s skipping invalid signer key %q: %v", logPrefix, hexStr, err)
			return
		}
		xOnly := signerHex(key)
		if _, dup := seen[xOnly]; dup {
			return
		}
		seen[xOnly] = struct{}{}
		result = append(result, key)
	}

	addKey(info.SignerPubKey)
	for _, d := range info.DeprecatedSignerPubKeys {
		addKey(d.PubKey)
	}
	return result
}

type contractManager struct {
	store       types.ContractStore
	keyProvider keyProvider
	indexer     offchainDataProvider
	explorer    onchainDataProvider
	network     arklib.Network
	registry    Registry
	mu          sync.RWMutex
	// client is the shared GetInfo-caching transport wrapper. The manager
	// reads the accepted signer set (current + deprecated) directly from it
	// during discovery, sharing the same cache the handlers use so we don't
	// fan out redundant GetInfo calls.
	client client.Client
	// infoCache is the cache backing `client`. The manager invalidates it at
	// the start of every scan so the signer set is always fresh on restore
	// and after a live rotation.
	infoCache *infoCache
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
		client:      cachedClient,
		infoCache:   cache,
	}, nil
}

// InvalidateInfoCache clears the shared GetInfo cache so the next scan (or
// any handler call) fetches a fresh server info. Exposed on the Manager
// interface so the wallet can force a re-read when it detects a live signer
// rotation.
func (m *contractManager) InvalidateInfoCache() {
	m.infoCache.Invalidate()
}

func (m *contractManager) Registry() Registry { return m.registry }

func (m *contractManager) ScanContracts(ctx context.Context, gapLimit uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Force a fresh GetInfo so the signer set is never stale on restore (a
	// rotation that happened while the wallet was locked must be reflected) and
	// after a live rotation. Every subsequent GetInfo in this scan (here and in
	// the handlers) is served from the freshly-populated cache.
	m.infoCache.Invalidate()

	info, err := m.client.GetInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get server info: %w", err)
	}
	signers := acceptedSigners(info)

	if m.keyProvider.GetType() == identity.SingleKeyIdentity {
		// A single-key identity has only one derivable contract per type and
		// signer, so the gap-limit loop would just churn on the same scripts.
		// Derive each type's contract for every accepted signer and batch the
		// offchain probe into a single indexer call; boarding still goes
		// per-address through the explorer.
		return m.scanSingleKeyContracts(ctx, signers)
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
		if err := m.scanContracts(
			ctx, contractType, gapLimit, handler, findUsed, signers,
		); err != nil {
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

	if m.keyProvider.GetType() == identity.SingleKeyIdentity {
		// A single-key identity reuses the same key for every contract of a given type, so the
		// derived script is identical across calls. Treat a repeat as idempotent reuse and return
		// the stored contract.
		contracts, err := m.store.GetContractsByType(ctx, contractType)
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
		return m.store.GetContractsByType(ctx, f.contractType)
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

// signerScanState tracks one signer's independent gap-limit walk. The current
// signer and each deprecated signer get their own state so a gap in one space
// never stops the scan in another (EC-1). lastUsedIdx anchors persistence;
// contractByIndex holds the derived contract for every scanned index so we can
// persist the contiguous range [startIdx, lastUsedIdx] without re-deriving.
type signerScanState struct {
	startIdx          uint32
	consecutiveUnused uint32
	lastUsedIdx       int64 // -1 sentinel until a hit
	done              bool
	contractByIndex   map[uint32]types.Contract
}

func (m *contractManager) scanContracts(
	ctx context.Context, contractType types.ContractType,
	gapLimit uint32, handler handlers.Handler, findUsed findUsedFn,
	signers []*btcec.PublicKey,
) error {
	const noUsage int64 = -1

	// Where the CURRENT signer (signers[0]) starts. We keep the existing
	// "resume strictly after the last stored index" optimization for it, since
	// everything up to the latest allocated current-signer contract is already
	// tracked. Deprecated signers always start from index 0: a pre-rotation
	// vtxo can sit at any low index even when current-signer contracts exist at
	// high indices (EC-2, spec 3.3.5).
	var currentStartIdx uint32
	contract, err := m.store.GetLatestContract(ctx, contractType)
	if err != nil {
		return fmt.Errorf(
			"failed to get latest key id for contract type %s: %w", contractType, err,
		)
	}
	if contract != nil {
		keyRef, err := handler.GetKeyRef(*contract)
		if err != nil {
			return fmt.Errorf("failed to get key ref for contract %s: %w", contract.Script, err)
		}
		currentIdx, err := m.keyProvider.GetKeyIndex(ctx, keyRef.Id)
		if err != nil {
			return fmt.Errorf("failed to parse key id for contract %s: %w", contract.Script, err)
		}
		currentStartIdx = currentIdx + 1
	}

	states := make(map[string]*signerScanState, len(signers))
	for i, s := range signers {
		startIdx := uint32(0)
		if i == 0 {
			startIdx = currentStartIdx
		}
		states[signerHex(s)] = &signerScanState{
			startIdx:        startIdx,
			lastUsedIdx:     noUsage,
			contractByIndex: make(map[uint32]types.Contract),
		}
	}

	anyActive := func() bool {
		for _, st := range states {
			if !st.done {
				return true
			}
		}
		return false
	}

	// Walk the shared owner-key HD chain from index 0 upward. The owner key is
	// per-index and signer-independent, so we derive it once per index and fan
	// it out across every still-active signer via CandidateContracts. We probe
	// gapLimit indices at a time: all candidate scripts across signers AND
	// indices in the batch are deduplicated and sent in a SINGLE findUsed call
	// (EC-3, EC-11) so we never multiply indexer round-trips by the signer
	// count.
	currentKeyId := ""
	for anyActive() {
		type entry struct {
			signerKey string
			idx       uint32
			contract  types.Contract
		}
		batch := make([]entry, 0, int(gapLimit)*len(signers))
		probe := make([]types.Contract, 0, int(gapLimit)*len(signers))
		probeSeen := make(map[string]struct{}, int(gapLimit)*len(signers))

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
			currentKeyId = nextKeyId

			// Only the signers that still need this index.
			activeSigners := make([]*btcec.PublicKey, 0, len(signers))
			for _, s := range signers {
				st := states[signerHex(s)]
				if st.done || idx < st.startIdx {
					continue
				}
				activeSigners = append(activeSigners, s)
			}
			if len(activeSigners) == 0 {
				continue
			}

			candidates, err := handler.CandidateContracts(ctx, *keyRef, activeSigners)
			if err != nil {
				return fmt.Errorf(
					"failed to derive %s candidate contracts for key %s: %w",
					contractType, nextKeyId, err,
				)
			}
			for j, c := range candidates {
				sHex := signerHex(activeSigners[j])
				batch = append(batch, entry{signerKey: sHex, idx: idx, contract: c})
				states[sHex].contractByIndex[idx] = c
				if _, dup := probeSeen[c.Script]; !dup {
					probeSeen[c.Script] = struct{}{}
					probe = append(probe, c)
				}
			}
		}

		if len(probe) == 0 {
			// No active signer reached its start index in this batch (e.g. the
			// only signer is the current one resuming at a high startIdx while
			// this batch covered lower indices). Keep walking the chain; the
			// loop condition (anyActive) is what actually terminates the scan.
			continue
		}

		used, err := findUsed(ctx, probe)
		if err != nil {
			return err
		}

		// Credit each candidate back to its own signer's counters so gaps stay
		// per-signer (EC-1).
		for _, e := range batch {
			st := states[e.signerKey]
			if st.done {
				continue
			}
			if _, isUsed := used[e.contract.Script]; isUsed {
				if int64(e.idx) > st.lastUsedIdx {
					st.lastUsedIdx = int64(e.idx)
				}
				st.consecutiveUnused = 0
				continue
			}
			st.consecutiveUnused++
			if st.consecutiveUnused >= gapLimit {
				st.done = true
			}
		}
	}

	// Persist each signer's contiguous range [startIdx, lastUsedIdx]. Persisting
	// a script that already exists is a no-op thanks to INSERT OR IGNORE (EC-12),
	// so re-scans and overlapping (index, signer) rows are harmless.
	for _, s := range signers {
		st := states[signerHex(s)]
		if st.lastUsedIdx == noUsage {
			continue
		}
		for i := st.startIdx; i <= uint32(st.lastUsedIdx); i++ {
			c, ok := st.contractByIndex[i]
			if !ok {
				continue
			}
			if err := m.store.AddContract(ctx, c, i); err != nil {
				return fmt.Errorf("failed to store %s contract: %w", contractType, err)
			}
			log.Debugf("%s added new %s contract %s", logPrefix, contractType, c.Script)
		}
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

// scanSingleKeyContracts derives, for each registered type, one contract per
// accepted signer that a single-key identity can produce, and probes external
// state to decide which to persist. A single-key wallet that held pre-rotation
// (deprecated-signer) vtxos must still discover them, so we derive candidates
// for the current signer AND every deprecated signer (EC-9). Offchain
// candidates are deduplicated and batched into a single indexer call; boarding
// candidates go through the per-address explorer probe.
//
// The previous "skip if any contract of this type is already stored" early-exit
// is intentionally gone: it would mask a deprecated-signer contract whenever a
// current-signer one already existed. INSERT OR IGNORE makes re-persisting an
// already-stored contract a no-op, so re-scans stay idempotent (EC-12).
func (m *contractManager) scanSingleKeyContracts(
	ctx context.Context, signers []*btcec.PublicKey,
) error {
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
		candidates, err := handler.CandidateContracts(ctx, *keyRef, signers)
		if err != nil {
			return fmt.Errorf(
				"failed to derive %s candidate contracts for key %s: %w",
				contractType, keyId, err,
			)
		}
		for _, c := range candidates {
			p := pending{typ: contractType, contract: c, keyIdx: idx}
			if contractType == types.ContractTypeBoarding {
				boarding = append(boarding, p)
			} else {
				offchain = append(offchain, p)
			}
		}
	}

	persist := func(p pending) error {
		if err := m.store.AddContract(ctx, p.contract, p.keyIdx); err != nil {
			return fmt.Errorf("failed to store %s contract: %w", p.typ, err)
		}
		log.Debugf("%s added new %s contract %s", logPrefix, p.typ, p.contract.Script)
		return nil
	}

	// One indexer round-trip for every offchain candidate (all types, all
	// signers) at once, deduplicated by script.
	var offchainUsed map[string]struct{}
	if len(offchain) > 0 {
		batch := make([]types.Contract, 0, len(offchain))
		seen := make(map[string]struct{}, len(offchain))
		for _, p := range offchain {
			if _, dup := seen[p.contract.Script]; dup {
				continue
			}
			seen[p.contract.Script] = struct{}{}
			batch = append(batch, p.contract)
		}
		used, err := m.findUsedContracts(ctx, batch)
		if err != nil {
			return err
		}
		offchainUsed = used
	}

	for _, p := range offchain {
		if _, isUsed := offchainUsed[p.contract.Script]; !isUsed {
			continue
		}
		if err := persist(p); err != nil {
			return err
		}
	}

	if len(boarding) > 0 {
		batch := make([]types.Contract, 0, len(boarding))
		seen := make(map[string]struct{}, len(boarding))
		for _, p := range boarding {
			if _, dup := seen[p.contract.Script]; dup {
				continue
			}
			seen[p.contract.Script] = struct{}{}
			batch = append(batch, p.contract)
		}
		used, err := m.findUsedBoardingContracts(ctx, batch)
		if err != nil {
			return err
		}
		for _, p := range boarding {
			if _, isUsed := used[p.contract.Script]; !isUsed {
				continue
			}
			if err := persist(p); err != nil {
				return err
			}
		}
	}

	return nil
}
