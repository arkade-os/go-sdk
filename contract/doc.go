// Package contract manages the lifecycle of contracts derived from an
// identity for a Wallet: it owns the per-type handlers, persists the
// contracts via a pluggable store, and rescans for not-yet tracked contracts
// to store.
//
// # Components
//
// Manager is the only surface external callers touch. Concrete callers go
// through the [Manager] interface returned by [NewManager]; everything
// else in this package is wiring it depends on.
//
//   - Handlers live in contract/handlers/ and provide per-type strategies
//     for building a contract from an identity.KeyRef and for the standard
//     getters (GetKeyRefs / GetSignerKey / GetTapscripts / GetExitDelay).
//     The "default" (offchain) and "boarding" (onchain) handlers are the
//     same implementation parameterized at construction with an isOnchain
//     bool — see contract/handlers/default.NewHandler. There is no
//     per-call IsOnchain option: handler identity carries the kind, and
//     [Manager.GetHandler] dispatches on the contract's Type.
//
//   - Store is the persistence layer (types.ContractStore, backed by KV
//     or SQL). Contracts are keyed by Script, with secondary access by
//     type/state/scripts. types.ContractStore.GetLatestContract(type)
//     resolves the latest stored contract for a given type by key index,
//     which the manager uses to find the next free derivation index
//     without scanning the entire row set.
//
//   - infoCache (see info_cache.go) memoizes client.Client.GetInfo
//     responses. NewManager wraps args.Client once with a cachingClient
//     and hands the wrapped client to every registered handler, so all
//     handlers (and any future vhtlc/delegate kinds) share a single
//     GetInfo cache rather than fanning one out per handler.
//
//   - keyProvider (unexported, defined in types.go) is the subset of the
//     identity.Identity surface the manager needs to derive contracts:
//     GetKeyIndex, NextKeyId, GetKey. Keeping it unexported decouples the
//     manager from the identity implementation and lets us grow the
//     surface without leaking new methods to callers of NewManager.
//
// # Creating a contract
//
// [Manager.NewContract](ctx, contractType, opts...):
//  1. Look up the handler registered for contractType.
//  2. Ask the store for GetLatestContract(contractType) and resolve the
//     last-used keyId from it (or start at the first key id when the pool
//     is empty).
//  3. Advance with keyProvider.NextKeyId, then GetKey to derive the new
//     KeyRef.
//  4. Hand the KeyRef to handler.NewContract — the handler builds the
//     script, address, and contract-type-specific params.
//  5. Persist via store.AddContract with the resolved key index.
//
// # Recovery (ScanContracts)
//
// [Manager.ScanContracts](ctx, gapLimit) runs a gap-limit HD scan against
// every registered handler's external data source:
//
//   - ContractTypeDefault uses the indexer's batched GetVtxos endpoint
//     (one round-trip per batch).
//   - ContractTypeBoarding uses the explorer's per-address GetTxs
//     endpoint (throttled to dodge rate limits).
//
// The scan derives gapLimit contracts at a time, asks the data source
// which scripts have been used, and stops once it has seen gapLimit
// consecutive unused addresses. It then persists every derived contract
// from startIdx up to and including the highest used index — the
// intermediate unused addresses are persisted too so subsequent
// NewContract calls advance past them.
//
// Recoverability follows BIP-44 semantics: only externally observable
// (used) addresses are recoverable from a mnemonic. Addresses that the
// original identity derived but never received funds at are not visible
// to the indexer/explorer and are therefore unreachable on restore.
//
// # Concurrency
//
// The manager guards its handler map with an [sync.RWMutex]. Lookups
// (GetContracts, GetHandler, GetSupportedContractTypes) hold a read lock;
// mutations (NewContract, ScanContracts, Clean, Close) hold the write
// lock. The store and the info cache have their own internal locking.
//
// # Extending with new contract types
//
// New handler kinds (vhtlc, delegate, custom user-defined contracts, …)
// plug in by:
//  1. Implementing handlers.Handler (see contract/handlers/handler.go).
//  2. Registering the handler with the manager. Two equivalent paths:
//     - At construction, via Args.ExtraHandlers, keyed by a new
//     types.ContractType.
//     - At runtime, via [Manager.RegisterHandler].
//     Both reject empty types, nil handlers, and any type that is already
//     registered (including the built-in default and boarding types).
//  3. If the new type's "has this contract been used externally?" probe
//     differs from the indexer or explorer paths the dispatcher already
//     knows about, adding a branch in ScanContracts that selects the
//     correct findUsedFn. By default ScanContracts uses the indexer
//     (offchain) path for any non-boarding type.
//
// User-registered handlers are responsible for their own client caching.
// The manager wraps args.Client with a shared GetInfo cache and hands the
// wrapped client to the built-in handlers only — handlers constructed by
// callers were built before the manager existed and need not depend on
// client.Client at all.
package contract
