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
		// A single-key identity reuses the same key for every contract of a given
		// type, so the derived script is identical across calls under the SAME
		// signer. Treat a repeat as idempotent reuse and return the stored
		// contract — but only one that commits to the CURRENT server signer.
		//
		// After a rotation, ScanContracts persists both deprecated-signer and
		// current-signer contracts of the same type, and GetContractsByType has no
		// signer filter or ordering. Returning contracts[0] could hand back a
		// deprecated-signer contract, so a new incoming payment would commit to a
		// deprecated signer (violating arkd #822). Filter by the current signer
		// (read from fresh server info) and fall through to derive a fresh
		// current-signer contract if none of the stored ones match.
		info, err := m.client.GetInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get server info: %w", err)
		}
		currentBuf, err := hex.DecodeString(info.SignerPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode current signer key: %w", err)
		}
		currentKey, err := btcec.ParsePubKey(currentBuf)
		if err != nil {
			return nil, fmt.Errorf("failed to parse current signer key: %w", err)
		}
		currentHex := signerHex(currentKey)
		contracts, err := m.store.GetContractsByType(ctx, contractType)
		if err != nil {
			return nil, err
		}
		for _, c := range contracts {
			signerKey, err := handler.GetSignerKey(c)
			if err != nil {
				// A contract whose signer we cannot resolve cannot be confirmed as
				// current-signer; skip it rather than risk reusing a deprecated one.
				log.Warnf(
					"%s skipping stored contract %s with unresolvable signer: %v",
					logPrefix, c.Script, err,
				)
				continue
			}
			if signerHex(signerKey) == currentHex {
				contract := c
				return &contract, nil
			}
		}
		// No stored current-signer contract: fall through to derive a new one.
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

// signerScanState tracks one signer's persistence state during the shared
// gap-limit walk. Termination is governed by a SINGLE union gap counter shared
// across all signers (see scanContracts), not by per-signer counters: the
// owner-key HD allocation is one monotonic stream regardless of signer
// (NewContract advances via the signer-agnostic GetLatestContract), so a "used"
// index is any index where ANY accepted signer has a hit. A union counter that
// resets on any signer's hit is therefore the correct termination rule and is
// what lets the current signer's first post-rotation hit (which can sit far
// beyond gapLimit on a fresh restore) still be discovered, as long as some
// signer keeps the shared counter alive across the intervening indices.
//
// lastUsedIdx anchors persistence; contractByIndex holds the derived contract
// for every scanned index so we can persist the contiguous range
// [startIdx, lastUsedIdx] without re-deriving.
type signerScanState struct {
	startIdx        uint32
	lastUsedIdx     int64 // -1 sentinel until a hit
	contractByIndex map[uint32]types.Contract
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
	// high indices, so a deprecated-signer scan that resumed after the last
	// stored index would miss those low-index pre-rotation contracts.
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

	// A SINGLE union gap counter governs termination. The owner-key HD chain is
	// one monotonic allocation stream shared by every signer, so the scan must
	// not stop until gapLimit CONSECUTIVE indices pass with no hit from ANY
	// accepted signer. consecutiveUnusedShared resets to 0 on a hit by any
	// signer at an index and increments only when an index produced no hit at
	// all; the scan ends once it reaches gapLimit. This is what lets the current
	// signer's first post-rotation hit be discovered even when it sits far
	// beyond gapLimit from index 0 on a fresh restore: the deprecated signer's
	// hits at the low indices keep the shared counter alive across the gap.
	var consecutiveUnusedShared uint32
	scanDone := false

	// Walk the shared owner-key HD chain from index 0 upward. The owner key is
	// per-index and signer-independent, so we derive it once per index and fan
	// it out across every signer via CandidateContracts. We probe gapLimit
	// indices at a time: all candidate scripts across signers AND indices in the
	// batch are deduplicated and sent in a SINGLE findUsed call so we never
	// multiply indexer round-trips by the signer count.
	currentKeyId := ""
	for !scanDone {
		type entry struct {
			signerKey string
			idx       uint32
			contract  types.Contract
		}
		batch := make([]entry, 0, int(gapLimit)*len(signers))
		probe := make([]types.Contract, 0, int(gapLimit)*len(signers))
		probeSeen := make(map[string]struct{}, int(gapLimit)*len(signers))
		// Indices probed in this batch, in ascending order, so the union counter
		// can be advanced index-by-index after the batch result comes back.
		batchIdxs := make([]uint32, 0, int(gapLimit))

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

			// Every signer probes every index (until the shared counter fires),
			// except the current signer which keeps the "resume strictly after the
			// last stored index" optimization (idx < its startIdx is already
			// tracked). Deprecated signers always start at 0 (startIdx==0), so the
			// only skipped pairs are current-signer indices below currentStartIdx.
			activeSigners := make([]*btcec.PublicKey, 0, len(signers))
			for _, s := range signers {
				st := states[signerHex(s)]
				if idx < st.startIdx {
					continue
				}
				activeSigners = append(activeSigners, s)
			}
			if len(activeSigners) == 0 {
				// Nothing to probe at this index (only the current signer is left
				// and it is resuming above this index). Do NOT record it for the
				// union counter: it sits inside the already-tracked current-signer
				// range, not in a real gap.
				continue
			}
			// Only indices we actually probe participate in the union gap counter.
			batchIdxs = append(batchIdxs, idx)

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
			// No signer reached its start index in this batch (e.g. the only
			// signer is the current one resuming at a high startIdx while this
			// batch covered lower indices). Those indices did not participate in
			// the union counter (batchIdxs is empty), so keep walking the chain;
			// the shared gap counter on a later batch is what terminates the scan.
			continue
		}

		used, err := findUsed(ctx, probe)
		if err != nil {
			return err
		}

		// Record per-signer hits (for persistence) and per-index hit presence
		// (for the union counter). A hit by ANY signer at an index marks that
		// index "used".
		hitAtIdx := make(map[uint32]struct{}, len(batchIdxs))
		for _, e := range batch {
			if _, isUsed := used[e.contract.Script]; !isUsed {
				continue
			}
			st := states[e.signerKey]
			if int64(e.idx) > st.lastUsedIdx {
				st.lastUsedIdx = int64(e.idx)
			}
			hitAtIdx[e.idx] = struct{}{}
		}

		// Advance the single union gap counter index-by-index in ascending order.
		// It resets on any signer's hit and increments on a fully-unused index;
		// the scan terminates the moment it reaches gapLimit so we never walk the
		// chain forever.
		for _, idx := range batchIdxs {
			if _, hit := hitAtIdx[idx]; hit {
				consecutiveUnusedShared = 0
				continue
			}
			consecutiveUnusedShared++
			if consecutiveUnusedShared >= gapLimit {
				scanDone = true
				break
			}
		}
	}

	// Persist each signer's contiguous range [startIdx, lastUsedIdx]. Persisting
	// a script that already exists is a no-op thanks to INSERT OR IGNORE, so
	// re-scans and overlapping (index, signer) rows are harmless.
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
// for the current signer AND every deprecated signer. Offchain candidates are
// deduplicated and batched into a single indexer call; boarding candidates go
// through the per-address explorer probe.
//
// The previous "skip if any contract of this type is already stored" early-exit
// is intentionally gone: it would mask a deprecated-signer contract whenever a
// current-signer one already existed. INSERT OR IGNORE makes re-persisting an
// already-stored contract a no-op, so re-scans stay idempotent.
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
