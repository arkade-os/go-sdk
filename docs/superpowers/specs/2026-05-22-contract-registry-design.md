# Contract Registry — Design

**Date:** 2026-05-22
**Branch:** `contract-registry`
**Supersedes:** PR #151 (`Allow registering custom contract handlers`) on `feat/custom-contracts`

## 1. Goal

Replace the ad-hoc `Args.ExtraHandlers` + `Manager.RegisterHandler` API introduced in PR #151 with a focused, single-purpose `Registry` component owned by the contract manager. Expose custom-handler registration to wallet users through one ergonomic option, applied at construction time only.

## 2. Non-goals

- Runtime registration after `Unlock`. The Registry is sealed once `NewManager` returns.
- Unregistering handlers. Same reason.
- User-constructible registries. The package does not export `NewRegistry`.
- Replacing the `Manager` interface wholesale. The change is surgical.

## 3. Constraints

- The contract `Manager` is built inside `wallet.Unlock` (`init.go:103`), which means it depends on the *unlocked* identity (`KeyProvider`) plus the wallet's internal `Indexer`, `Explorer`, `Store`, and `Network`. We cannot expect users to construct one themselves.
- Handlers themselves are dependency-light: they take `client.Client` and `arklib.Network` at construction; key material flows in at call time via the `keyProvider` interface. So a user *can* construct a handler before `Unlock`.

## 4. Architecture

Three layers, top-down:

1. **`arksdk.WithContractHandler(t, h)`** — `WalletOption`, the public consumption point.
2. **`contract.WithHandler(t, h)`** — `ManagerOption`, internal plumbing between wallet and manager.
3. **`contract.Registry`** — sealed component inside the manager that maps `types.ContractType` → `handlers.Handler`.

Data flow:

```
NewWallet(WithContractHandler(...))   →  walletOptions.customHandlers
                                              ↓ copied
                                       wallet.customHandlers
                                              ↓ translated in Unlock()
                          []contract.ManagerOption{ WithHandler(...) }
                                              ↓
                             contract.NewManager(Args, opts...)
                                              ↓
                                   builtins ∪ customs
                                              ↓
                                       newRegistry(...)  ← all rule checks
                                              ↓
                                  contractManager.registry  (sealed)
```

## 5. The `Registry` component

New file: `contract/registry.go`.

```go
package contract

// Registry maps contract types to their handler implementations.
// Constructed once by NewManager; immutable for its lifetime; concurrent-safe
// by virtue of immutability (no locking required for reads).
type Registry interface {
    // GetHandler returns the handler for the given contract type.
    // Errors with a descriptive message when no handler is registered.
    GetHandler(t types.ContractType) (handlers.Handler, error)
    // SupportedTypes returns all registered contract types in deterministic
    // (alphabetical) order. Built-ins are included.
    SupportedTypes() []types.ContractType
}

// registry is the concrete, unexported implementation. Callers seed it
// indirectly via contract.WithHandler options to NewManager.
type registry struct {
    handlers map[types.ContractType]handlers.Handler
}
```

**Construction (package-internal):**

```go
// newRegistry merges built-ins with caller-supplied custom handlers, applying
// all validation rules that need cross-handler visibility (built-in
// collision). Per-option validations (empty type, nil handler, typed-nil,
// duplicates inside the options slice) are caught earlier in WithHandler.
func newRegistry(
    builtins map[types.ContractType]handlers.Handler,
    customs  map[types.ContractType]handlers.Handler,
) (*registry, error) {
    merged := make(map[types.ContractType]handlers.Handler, len(builtins)+len(customs))
    for t, h := range builtins {
        merged[t] = h
    }
    for t, h := range customs {
        if _, isBuiltIn := builtins[t]; isBuiltIn {
            return nil, fmt.Errorf(
                "contract type %q is reserved by a built-in handler", t,
            )
        }
        merged[t] = h
    }
    return &registry{handlers: merged}, nil
}
```

**Reads:**

```go
func (r *registry) GetHandler(t types.ContractType) (handlers.Handler, error) {
    h, ok := r.handlers[t]
    if !ok {
        return nil, fmt.Errorf("no handler registered for contract type %q", t)
    }
    return h, nil
}

func (r *registry) SupportedTypes() []types.ContractType {
    out := slices.Collect(maps.Keys(r.handlers))
    slices.SortFunc(out, func(a, b types.ContractType) int {
        return strings.Compare(string(a), string(b))
    })
    return out
}
```

### Properties

- **No mutex.** Map is sealed after `newRegistry` returns.
- **Not user-constructible.** `newRegistry` is package-private.
- **Deterministic ordering** for `SupportedTypes` to keep tests stable.
- **No `Close()`.** Handlers are not resources the manager owns the lifetime of.

## 6. `ManagerOption` and `WithHandler`

New file: `contract/manager_opts.go`.

```go
package contract

type ManagerOption func(*managerOptions) error

type managerOptions struct {
    customHandlers map[types.ContractType]handlers.Handler
}

// WithHandler registers a custom handler for a non-built-in contract type.
// Errors if the type is empty, the handler is nil/typed-nil, or the same type
// was passed to a previous WithHandler in the same construction. Collision
// with built-in types is detected by newRegistry.
func WithHandler(t types.ContractType, h handlers.Handler) ManagerOption {
    return func(o *managerOptions) error {
        if t == "" {
            return fmt.Errorf("missing contract type")
        }
        if err := AssertNonNilHandler(h, t); err != nil {
            return err
        }
        if _, dup := o.customHandlers[t]; dup {
            return fmt.Errorf("duplicate handler for contract type %q", t)
        }
        if o.customHandlers == nil {
            o.customHandlers = make(map[types.ContractType]handlers.Handler)
        }
        o.customHandlers[t] = h
        return nil
    }
}

// AssertNonNilHandler rejects both an interface that is nil and an interface
// holding a typed-nil concrete value (e.g. var h *MyHandler; WithHandler(t,h)).
// Exported so the wallet layer can share the same check inside
// arksdk.WithContractHandler.
func AssertNonNilHandler(h handlers.Handler, t types.ContractType) error {
    if h == nil {
        return fmt.Errorf("nil handler for contract type %q", t)
    }
    if v := reflect.ValueOf(h); v.IsValid() {
        switch v.Kind() {
        case reflect.Ptr, reflect.Slice, reflect.Map,
            reflect.Func, reflect.Chan, reflect.Interface:
            if v.IsNil() {
                return fmt.Errorf("nil concrete handler for contract type %q", t)
            }
        }
    }
    return nil
}
```

### Validation split summary

| Check | Where | Rationale |
|---|---|---|
| Empty type | `WithHandler` | Local; fail early |
| Nil interface | `WithHandler` | Local; fail early |
| Typed-nil concrete | `WithHandler` | Local; fail early |
| Duplicate in options | `WithHandler` | Detectable as soon as 2nd call runs |
| Collision with built-in | `newRegistry` | Needs the built-ins map |

## 7. `Manager` surface delta

```go
type Manager interface {
    // NEW
    Registry() Registry

    // REMOVED: GetSupportedContractTypes(ctx) → callers go through
    //          mgr.Registry().SupportedTypes()

    // CHANGED: GetHandler delegates to Registry.GetHandler
    GetHandler(ctx context.Context, c types.Contract) (handlers.Handler, error)

    // UNCHANGED
    NewContract(ctx, t, opts...) (*types.Contract, error)
    GetContracts(ctx, opts...) ([]types.Contract, error)
    ScanContracts(ctx, gapLimit) error
    Clean(ctx) error
    Close()
}
```

**Concrete struct:**

```go
type contractManager struct {
    store       types.ContractStore
    keyProvider keyProvider
    indexer     offchainDataProvider
    explorer    onchainDataProvider
    network     arklib.Network
    registry    *registry
    // REMOVED: handlers map  (now lives inside registry)
    // REMOVED: mu sync.RWMutex (handlers map is sealed; nothing else in
    //          contractManager mutates state that needs guarding)
}
```

**`NewManager` flow:**

```go
func NewManager(args Args, opts ...ManagerOption) (Manager, error) {
    if err := args.validate(); err != nil {
        return nil, err
    }
    var mo managerOptions
    for _, opt := range opts {
        if err := opt(&mo); err != nil {
            return nil, fmt.Errorf("invalid manager option: %w", err)
        }
    }

    cachedClient := newCachingClient(args.Client, newInfoCache(infoCacheTTL))
    builtins := map[types.ContractType]handlers.Handler{
        types.ContractTypeDefault:  defaultHandler.NewHandler(cachedClient, args.Network, false),
        types.ContractTypeBoarding: defaultHandler.NewHandler(cachedClient, args.Network, true),
    }
    reg, err := newRegistry(builtins, mo.customHandlers)
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
    }, nil
}

func (m *contractManager) Registry() Registry { return m.registry }

func (m *contractManager) GetHandler(_ context.Context, c types.Contract) (handlers.Handler, error) {
    return m.registry.GetHandler(c.Type)
}
```

**`Args` is unchanged.** No `ExtraHandlers` field. No `CustomHandlers` field. Custom handlers flow exclusively through `ManagerOption`.

**`ScanContracts` dispatch.** Where `ScanContracts` iterates handlers, it now iterates `m.registry.handlers` (or, equivalently, `m.registry.SupportedTypes()` and resolves each via `GetHandler`). The pre-existing branch that picks `findUsedFn` based on whether the type is `ContractTypeBoarding` (onchain explorer) versus everything else (offchain indexer) stays as-is — custom types default to the offchain indexer path.

## 8. Wallet-level option

New addition to `wallet_opts.go`:

```go
// WithContractHandler registers a custom contract handler that the wallet's
// contract manager will dispatch to for the given contract type. The type
// must be non-empty, the handler non-nil, and must not collide with another
// previously registered custom handler or with a built-in type (default,
// boarding). Multiple calls are allowed for different types.
func WithContractHandler(
    t types.ContractType, h handlers.Handler,
) WalletOption {
    return func(o *walletOptions) error {
        if t == "" {
            return fmt.Errorf("missing contract type")
        }
        if err := contract.AssertNonNilHandler(h, t); err != nil {
            return err
        }
        if _, dup := o.customHandlers[t]; dup {
            return fmt.Errorf("duplicate handler for contract type %q", t)
        }
        if o.customHandlers == nil {
            o.customHandlers = make(map[types.ContractType]handlers.Handler)
        }
        o.customHandlers[t] = h
        return nil
    }
}
```

The nil/typed-nil assertion is shared between layers by exporting `contract.AssertNonNilHandler`. Validation at `NewWallet` time gives the user immediate feedback on bad input instead of deferring the error until `Unlock`. Built-in collision detection stays inside `newRegistry` (the only layer that knows the built-ins).

**`walletOptions` struct gains:**

```go
type walletOptions struct {
    // ... existing fields ...
    customHandlers map[types.ContractType]handlers.Handler
}
```

**`wallet` struct gains the same field**, copied from `walletOptions` in `NewWallet`.

**`Unlock` translates and applies:**

```go
// init.go, around line 103
mgrOpts := make([]contract.ManagerOption, 0, len(w.customHandlers))
for t, h := range w.customHandlers {
    mgrOpts = append(mgrOpts, contract.WithHandler(t, h))
}
mgr, err := contract.NewManager(contract.Args{
    Store:       w.store.ContractStore(),
    KeyProvider: w.Identity(),
    Client:      w.Client(),
    Indexer:     w.Indexer(),
    Explorer:    w.Explorer(),
    Network:     w.network,
}, mgrOpts...)
```

### Caller experience

```go
w, err := arksdk.NewWallet(
    arksdk.WithContractHandler("vhtlc", myVHTLCHandler),
    arksdk.WithContractHandler("delegate", myDelegateHandler),
    // ... other wallet options
)
```

After `Unlock`, the wallet's manager will dispatch to those handlers when the user calls `NewContract("vhtlc", ...)` etc., and `ScanContracts` will include those types in its sweep.

## 9. Tests

| Layer | File | Coverage |
|---|---|---|
| `registry` | `contract/registry_test.go` (new) | `newRegistry` rejects built-in collisions; `GetHandler` hit/miss; `SupportedTypes` returns sorted slice including built-ins; immutability (returned slice is a copy) |
| `WithHandler` | `contract/manager_opts_test.go` (new) | Empty type, nil, typed-nil, duplicate-in-opts each produce the expected error message; valid call populates `managerOptions` |
| `NewManager` | extend `contract/manager_test.go` | Multiple `WithHandler` options are merged into the registry; built-in collision via `WithHandler` errors; `Registry()` returns a non-nil component |
| `Manager.GetHandler` | extend existing tests | Now delegates: unknown type returns the registry's error; known type returns the handler |
| Removed: `Manager.RegisterHandler` tests | delete | Method is gone |
| Wallet | `wallet_opts_test.go` | `WithContractHandler` rejects empty/nil/dup; valid calls populate `walletOptions.customHandlers` |
| Wallet integration | extend `*_test.go` near `Unlock` | A `WithContractHandler` passed to `NewWallet` ends up registered in `mgr.Registry()` after `Unlock` |

## 10. Migration from PR #151

PR #151 is on `feat/custom-contracts` and **not merged**. The deltas to drop:

| PR #151 element | Action |
|---|---|
| `Args.ExtraHandlers` field | **Delete** |
| `Manager.RegisterHandler` method | **Delete** |
| `validateHandlerRegistration` free function in `manager.go` | **Replace** with `newRegistry` (cross-handler checks) + `WithHandler` (per-option checks) |
| `builtInContractTypes` package-level map | **Delete** — derived from the `builtins` map passed to `newRegistry` |
| Manager's `sync.RWMutex` | **Delete** — sealed registry doesn't need it |
| `contract/manager_test.go` registry/RegisterHandler tests | **Rewrite** against the new `Registry` surface |
| `contract/fake_handler_test.go` | **Keep** — still needed for tests |

## 11. Risks

- **Removing `Manager.GetSupportedContractTypes`** is a breaking change to the existing master-merged Manager interface. Anyone consuming the SDK at HEAD needs to update to `mgr.Registry().SupportedTypes()`. Acceptable: the method shipped with #145 less than two weeks ago and isn't on a wide-adoption critical path.
- **Removing the manager's mutex** is safe only as long as no future change reintroduces post-construction mutation of the handlers map. The Registry interface's lack of a `Register` method enforces this; any reintroduction would have to extend the interface, making the regression visible at review time.
- **Typed-nil check via reflect.** Mildly unusual; documented inline.

## 12. Implementation order

Suggested for the writing-plans skill to expand into tasks:

1. Add `contract/registry.go` with `Registry` interface, `registry` struct, `newRegistry`, `GetHandler`, `SupportedTypes`.
2. Add `contract/manager_opts.go` with `ManagerOption`, `managerOptions`, `WithHandler`, `assertNonNilHandler`.
3. Modify `contract/manager.go`: `NewManager` becomes variadic; struct shrinks; `Registry()` and updated `GetHandler` methods.
4. Modify `contract/types.go`: `Manager` interface — add `Registry()`, drop `GetSupportedContractTypes`.
5. Update call sites that used `GetSupportedContractTypes`.
6. Add `WithContractHandler` to `wallet_opts.go`; extend `walletOptions` and `wallet` structs.
7. Update `init.go` to translate wallet-level handlers into `contract.WithHandler` options inside `Unlock`.
8. Write tests at each layer per the table in §9.
9. Update `contract/doc.go` to reflect the registry-centric model.
10. Run `make build`, `make vet`, the unit tests, and the e2e suite.
