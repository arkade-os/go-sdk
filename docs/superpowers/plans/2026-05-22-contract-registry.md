# Contract Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace PR #151's bolt-on `Args.ExtraHandlers` + `Manager.RegisterHandler` with a sealed `Registry` component owned by the contract manager, plus a single wallet-level option (`WithContractHandler`) for construction-time custom handler registration.

**Architecture:** A new `contract.Registry` interface, sealed by an unexported `registry` struct, holds the type→handler map. `NewManager` becomes variadic (`...contract.ManagerOption`); the only option is `contract.WithHandler(t, h)`. At the wallet layer, `arksdk.WithContractHandler(t, h)` collects handlers in `walletOptions` → copied to `wallet.customHandlers` → translated to `contract.WithHandler` calls inside `Unlock`. The Manager's `sync.RWMutex` is removed (registry is immutable post-construction). `Manager.GetSupportedContractTypes` is removed entirely in favor of `mgr.Registry().SupportedTypes()`.

**Tech Stack:** Go 1.26 · stdlib (`reflect`, `slices`, `maps`, `strings`) · `github.com/stretchr/testify/require` for tests · existing `contract/handlers` interface · `golang-migrate` (no migrations needed for this change).

**Spec:** `docs/superpowers/specs/2026-05-22-contract-registry-design.md`

---

## File map

| File | Action | Responsibility |
|---|---|---|
| `contract/registry.go` | **Create** | `Registry` interface, `registry` struct, `newRegistry`, `GetHandler`, `SupportedTypes`, `AssertNonNilHandler` |
| `contract/registry_test.go` | **Create** | Tests for `newRegistry` / `Registry` reads / `AssertNonNilHandler` |
| `contract/manager_opts.go` | **Create** | `ManagerOption`, `managerOptions`, `WithHandler` |
| `contract/manager_opts_test.go` | **Create** | Tests for `WithHandler` validation rules |
| `contract/manager.go` | **Modify** | `NewManager` becomes variadic; struct drops `handlers` map + `mu`; `Registry()` added; `GetHandler` / `ScanContracts` delegate to registry; remove `GetSupportedContractTypes` impl |
| `contract/types.go` | **Modify** | `Manager` interface — add `Registry()`, drop `GetSupportedContractTypes` |
| `contract/doc.go` | **Modify** | Rewrite the "Extending with new contract types" section, drop the registry TODO note, document `WithHandler` |
| `contract/manager_test.go` | **Modify** | Drop `TestManagerGetSupportedContractTypes`; add `TestNewManagerWithCustomHandler` covering merging + collision |
| `contract/fake_handler_test.go` | **Create** | Test fixture: minimal handler satisfying `handlers.Handler` (lifted from `feat/custom-contracts`) |
| `wallet_opts.go` | **Modify** | Add `WithContractHandler`; extend `walletOptions` with `customHandlers` |
| `wallet_opts_test.go` | **Modify** | Add tests for `WithContractHandler` validation |
| `wallet.go` | **Modify** | Add `customHandlers` field to `wallet` struct; copy from `o.customHandlers` in `NewWallet` and `LoadWallet` |
| `init.go` | **Modify** | Inside `Unlock`, build `[]contract.ManagerOption` from `w.customHandlers` and pass to `contract.NewManager` |

---

## Task 1: Test fixture — `fakeHandler`

We need a minimal `handlers.Handler` implementation so the registry tests don't depend on the real default-handler wiring (transport, network, etc.). Lifted from `feat/custom-contracts` to keep parity.

**Files:**
- Create: `contract/fake_handler_test.go`

- [ ] **Step 1: Write the fake handler fixture file**

```go
// contract/fake_handler_test.go
package contract_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

// fakeHandler is a minimal handlers.Handler used by the registry tests so
// they don't depend on the default/boarding handlers' wiring (transport
// client, network, etc.). It produces a deterministic contract from a
// keyRef so scan-loop tests can predict scripts.
type fakeHandler struct {
	typ       types.ContractType
	exitDelay arklib.RelativeLocktime
}

func newFakeHandler(typ types.ContractType) *fakeHandler {
	return &fakeHandler{
		typ: typ,
		exitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 144,
		},
	}
}

func (h *fakeHandler) NewContract(
	_ context.Context, keyRef identity.KeyRef,
) (*types.Contract, error) {
	script := fakeScript(h.typ, keyRef.Id)
	return &types.Contract{
		Type:    h.typ,
		State:   types.ContractStateActive,
		Script:  script,
		Address: "fake:" + script,
		Params: map[string]string{
			ownerKeyIdParam: keyRef.Id,
		},
	}, nil
}

func (h *fakeHandler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	return map[string]string{ownerKeyIdParam: c.Params[ownerKeyIdParam]}, nil
}

func (h *fakeHandler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	id, ok := c.Params[ownerKeyIdParam]
	if !ok {
		return nil, fmt.Errorf("missing %s in params", ownerKeyIdParam)
	}
	return &identity.KeyRef{Id: id}, nil
}

func (h *fakeHandler) GetSignerKey(_ types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}

func (h *fakeHandler) GetExitDelay(_ types.Contract) (*arklib.RelativeLocktime, error) {
	d := h.exitDelay
	return &d, nil
}

func (h *fakeHandler) GetTapscripts(_ types.Contract) ([]string, error) {
	return nil, nil
}

// fakeScript mirrors fakeHandler.NewContract so tests can predict the
// script a given (type, keyId) pair will produce.
func fakeScript(typ types.ContractType, keyId string) string {
	h := sha256.Sum256([]byte(string(typ) + ":" + keyId))
	return hex.EncodeToString(h[:])
}

// compile-time check that fakeHandler satisfies the Handler interface.
var _ handlers.Handler = (*fakeHandler)(nil)
```

- [ ] **Step 2: Verify the fixture compiles**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go build ./contract/...`
Expected: `(no output)` — package builds. The fixture file is `_test.go` so it only compiles under `go test`.

- [ ] **Step 3: Verify fixture compiles under `go test`**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go vet ./contract/...`
Expected: `(no output)` — vet passes including test files.

- [ ] **Step 4: Commit**

```bash
git add contract/fake_handler_test.go
git commit -m "contract: add fakeHandler test fixture"
```

---

## Task 2: `AssertNonNilHandler` helper (with tests)

Shared between `contract.WithHandler` (manager option) and `arksdk.WithContractHandler` (wallet option). Lives in `contract/registry.go` (forward declaration — the rest of the file lands in Task 3).

**Files:**
- Create: `contract/registry.go` (skeleton — just `AssertNonNilHandler` for now)
- Create: `contract/registry_test.go` (tests for `AssertNonNilHandler`)

- [ ] **Step 1: Write the failing tests**

```go
// contract/registry_test.go
package contract_test

import (
	"testing"

	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestAssertNonNilHandler(t *testing.T) {
	t.Run("valid handler passes", func(t *testing.T) {
		err := contract.AssertNonNilHandler(newFakeHandler("vhtlc"), "vhtlc")
		require.NoError(t, err)
	})

	t.Run("nil interface fails", func(t *testing.T) {
		err := contract.AssertNonNilHandler(nil, "vhtlc")
		require.ErrorContains(t, err, `nil handler for contract type "vhtlc"`)
	})

	t.Run("typed-nil concrete value fails", func(t *testing.T) {
		var h *fakeHandler
		var iface handlers.Handler = h
		err := contract.AssertNonNilHandler(iface, "vhtlc")
		require.ErrorContains(t, err, `nil concrete handler for contract type "vhtlc"`)
	})

	t.Run("error message includes the contract type", func(t *testing.T) {
		err := contract.AssertNonNilHandler(nil, types.ContractType("delegate"))
		require.ErrorContains(t, err, `"delegate"`)
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -run TestAssertNonNilHandler -v`
Expected: build error `undefined: contract.AssertNonNilHandler`

- [ ] **Step 3: Create the skeleton `registry.go` with `AssertNonNilHandler`**

```go
// contract/registry.go
package contract

import (
	"fmt"
	"reflect"

	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
)

// AssertNonNilHandler rejects both an interface that is nil and an
// interface holding a typed-nil concrete value (e.g.
// var h *MyHandler; AssertNonNilHandler(h, ...)).
// Exported so layers above contract (e.g. arksdk.WithContractHandler) can
// share the same check.
func AssertNonNilHandler(h handlers.Handler, t types.ContractType) error {
	if h == nil {
		return fmt.Errorf("nil handler for contract type %q", t)
	}
	v := reflect.ValueOf(h)
	if !v.IsValid() {
		return fmt.Errorf("nil handler for contract type %q", t)
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Map,
		reflect.Func, reflect.Chan, reflect.Interface:
		if v.IsNil() {
			return fmt.Errorf("nil concrete handler for contract type %q", t)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -run TestAssertNonNilHandler -v`
Expected: 4/4 subtests PASS.

- [ ] **Step 5: Commit**

```bash
git add contract/registry.go contract/registry_test.go
git commit -m "contract: add AssertNonNilHandler helper"
```

---

## Task 3: `Registry` interface + `newRegistry`

Add the sealed component plus tests. `newRegistry` does cross-handler validation (built-in collision). Per-handler validation (empty type, nil, typed-nil, duplicate-in-opts) belongs to `WithHandler` later — but `newRegistry` does NOT trust its inputs blindly, so it still rejects nil/typed-nil/empty-key on the merged map as a defense-in-depth check.

**Files:**
- Modify: `contract/registry.go`
- Modify: `contract/registry_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `contract/registry_test.go`:

```go
func TestRegistry_SupportedTypes(t *testing.T) {
	builtins := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault:  newFakeHandler(types.ContractTypeDefault),
		types.ContractTypeBoarding: newFakeHandler(types.ContractTypeBoarding),
	}
	customs := map[types.ContractType]handlers.Handler{
		types.ContractType("vhtlc"):    newFakeHandler("vhtlc"),
		types.ContractType("delegate"): newFakeHandler("delegate"),
	}
	reg, err := contract.NewRegistryForTest(builtins, customs)
	require.NoError(t, err)

	got := reg.SupportedTypes()
	want := []types.ContractType{
		types.ContractTypeBoarding,
		types.ContractType("delegate"),
		types.ContractTypeDefault,
		types.ContractType("vhtlc"),
	}
	require.Equal(t, want, got, "must be sorted alphabetically and include all types")
}

func TestRegistry_GetHandler(t *testing.T) {
	t.Run("hit returns the handler", func(t *testing.T) {
		h := newFakeHandler("vhtlc")
		builtins := map[types.ContractType]handlers.Handler{}
		customs := map[types.ContractType]handlers.Handler{
			types.ContractType("vhtlc"): h,
		}
		reg, err := contract.NewRegistryForTest(builtins, customs)
		require.NoError(t, err)

		got, err := reg.GetHandler(types.ContractType("vhtlc"))
		require.NoError(t, err)
		require.Same(t, h, got)
	})

	t.Run("miss returns descriptive error", func(t *testing.T) {
		reg, err := contract.NewRegistryForTest(
			map[types.ContractType]handlers.Handler{},
			map[types.ContractType]handlers.Handler{},
		)
		require.NoError(t, err)

		_, err = reg.GetHandler(types.ContractType("vhtlc"))
		require.ErrorContains(t, err, `no handler registered for contract type "vhtlc"`)
	})
}

func TestNewRegistry_RejectsBuiltinCollision(t *testing.T) {
	builtins := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault: newFakeHandler(types.ContractTypeDefault),
	}
	customs := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault: newFakeHandler(types.ContractTypeDefault),
	}
	_, err := contract.NewRegistryForTest(builtins, customs)
	require.ErrorContains(t, err, "reserved by a built-in handler")
}

func TestNewRegistry_RejectsEmptyKey(t *testing.T) {
	_, err := contract.NewRegistryForTest(
		map[types.ContractType]handlers.Handler{},
		map[types.ContractType]handlers.Handler{
			types.ContractType(""): newFakeHandler("x"),
		},
	)
	require.ErrorContains(t, err, "missing contract type")
}

func TestNewRegistry_RejectsNilHandler(t *testing.T) {
	_, err := contract.NewRegistryForTest(
		map[types.ContractType]handlers.Handler{},
		map[types.ContractType]handlers.Handler{
			types.ContractType("vhtlc"): nil,
		},
	)
	require.ErrorContains(t, err, "nil handler")
}
```

(`NewRegistryForTest` is a package-private test seam — alias for `newRegistry` exported only for `_test.go`. See next step.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -run "TestRegistry|TestNewRegistry" -v`
Expected: build error `undefined: contract.NewRegistryForTest`.

- [ ] **Step 3: Implement `Registry` interface, `registry` struct, `newRegistry`, plus the test seam**

Append to `contract/registry.go`:

```go
import (
	"slices"
	"strings"
)
// (merge with existing imports; the full import block becomes:)
//
//   import (
//       "fmt"
//       "reflect"
//       "slices"
//       "strings"
//
//       "github.com/arkade-os/go-sdk/contract/handlers"
//       "github.com/arkade-os/go-sdk/types"
//   )

// Registry maps contract types to their handler implementations.
// Constructed once by NewManager; immutable for its lifetime; concurrent-safe
// by virtue of immutability (no locking required for reads).
type Registry interface {
	// GetHandler returns the handler for the given contract type, or a
	// descriptive error if none is registered.
	GetHandler(t types.ContractType) (handlers.Handler, error)
	// SupportedTypes returns all registered contract types in
	// deterministic (alphabetical) order. Built-ins are included.
	SupportedTypes() []types.ContractType
}

// registry is the concrete, unexported implementation. Callers seed it
// indirectly via contract.WithHandler options to NewManager.
type registry struct {
	handlers map[types.ContractType]handlers.Handler
}

// newRegistry merges built-ins with caller-supplied custom handlers,
// applying all rules that need cross-handler visibility (built-in
// collision). Per-option validations (empty type, nil handler, typed-nil,
// duplicates inside the same WithHandler list) are caught earlier in
// WithHandler; this function still defends against them in case it's
// called from a path that didn't go through WithHandler.
func newRegistry(
	builtins map[types.ContractType]handlers.Handler,
	customs map[types.ContractType]handlers.Handler,
) (*registry, error) {
	merged := make(map[types.ContractType]handlers.Handler, len(builtins)+len(customs))
	for t, h := range builtins {
		merged[t] = h
	}
	for t, h := range customs {
		if t == "" {
			return nil, fmt.Errorf("missing contract type")
		}
		if err := AssertNonNilHandler(h, t); err != nil {
			return nil, err
		}
		if _, isBuiltIn := builtins[t]; isBuiltIn {
			return nil, fmt.Errorf(
				"contract type %q is reserved by a built-in handler", t,
			)
		}
		merged[t] = h
	}
	return &registry{handlers: merged}, nil
}

func (r *registry) GetHandler(t types.ContractType) (handlers.Handler, error) {
	h, ok := r.handlers[t]
	if !ok {
		return nil, fmt.Errorf("no handler registered for contract type %q", t)
	}
	return h, nil
}

func (r *registry) SupportedTypes() []types.ContractType {
	out := make([]types.ContractType, 0, len(r.handlers))
	for t := range r.handlers {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b types.ContractType) int {
		return strings.Compare(string(a), string(b))
	})
	return out
}
```

- [ ] **Step 4: Add the test seam in a new helper file**

```go
// contract/export_test.go
package contract

import (
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
)

// NewRegistryForTest is a test-only alias for newRegistry, exposing the
// package-private constructor to _test.go files in contract_test. Lives
// in export_test.go so it's only compiled under `go test`.
func NewRegistryForTest(
	builtins map[types.ContractType]handlers.Handler,
	customs map[types.ContractType]handlers.Handler,
) (Registry, error) {
	return newRegistry(builtins, customs)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -run "TestRegistry|TestNewRegistry" -v`
Expected: all 6 subtests PASS.

- [ ] **Step 6: Commit**

```bash
git add contract/registry.go contract/registry_test.go contract/export_test.go
git commit -m "contract: add Registry component"
```

---

## Task 4: `ManagerOption` + `WithHandler`

The user-facing option that collects custom handlers eagerly. Per-call validation (empty type, nil, typed-nil, duplicate-in-this-call) lives here. Built-in collision is caught later by `newRegistry`.

**Files:**
- Create: `contract/manager_opts.go`
- Create: `contract/manager_opts_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// contract/manager_opts_test.go
package contract_test

import (
	"testing"

	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestWithHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		opts, err := contract.ApplyManagerOptionsForTest(
			contract.WithHandler("vhtlc", newFakeHandler("vhtlc")),
		)
		require.NoError(t, err)
		require.Len(t, opts.CustomHandlers, 1)
		require.NotNil(t, opts.CustomHandlers["vhtlc"])
	})

	t.Run("multiple distinct types", func(t *testing.T) {
		opts, err := contract.ApplyManagerOptionsForTest(
			contract.WithHandler("vhtlc", newFakeHandler("vhtlc")),
			contract.WithHandler("delegate", newFakeHandler("delegate")),
		)
		require.NoError(t, err)
		require.Len(t, opts.CustomHandlers, 2)
	})

	t.Run("empty type errors", func(t *testing.T) {
		_, err := contract.ApplyManagerOptionsForTest(
			contract.WithHandler("", newFakeHandler("x")),
		)
		require.ErrorContains(t, err, "missing contract type")
	})

	t.Run("nil handler errors", func(t *testing.T) {
		_, err := contract.ApplyManagerOptionsForTest(
			contract.WithHandler("vhtlc", nil),
		)
		require.ErrorContains(t, err, `nil handler for contract type "vhtlc"`)
	})

	t.Run("typed-nil handler errors", func(t *testing.T) {
		var h *fakeHandler
		_, err := contract.ApplyManagerOptionsForTest(
			contract.WithHandler("vhtlc", h),
		)
		require.ErrorContains(t, err, `nil concrete handler for contract type "vhtlc"`)
	})

	t.Run("duplicate in same options errors", func(t *testing.T) {
		_, err := contract.ApplyManagerOptionsForTest(
			contract.WithHandler("vhtlc", newFakeHandler("vhtlc")),
			contract.WithHandler("vhtlc", newFakeHandler("vhtlc")),
		)
		require.ErrorContains(t, err, `duplicate handler for contract type "vhtlc"`)
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -run TestWithHandler -v`
Expected: build error `undefined: contract.WithHandler` and `contract.ApplyManagerOptionsForTest`.

- [ ] **Step 3: Implement `ManagerOption` and `WithHandler`**

```go
// contract/manager_opts.go
package contract

import (
	"fmt"

	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
)

// ManagerOption configures NewManager. The only currently defined option
// is WithHandler.
type ManagerOption func(*managerOptions) error

type managerOptions struct {
	customHandlers map[types.ContractType]handlers.Handler
}

// WithHandler registers a custom handler for a non-built-in contract type.
// Errors if the type is empty, the handler is nil/typed-nil, or the same
// type was passed to a previous WithHandler in the same NewManager call.
// Collision with built-in types is detected later, inside newRegistry.
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

func applyManagerOptions(opts ...ManagerOption) (*managerOptions, error) {
	mo := &managerOptions{}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("manager option cannot be nil")
		}
		if err := opt(mo); err != nil {
			return nil, fmt.Errorf("invalid manager option: %w", err)
		}
	}
	return mo, nil
}
```

- [ ] **Step 4: Add the test seam**

Append to `contract/export_test.go`:

```go
// ManagerOptionsView is a flattened, test-visible mirror of managerOptions.
// Returned by ApplyManagerOptionsForTest so _test.go files can assert on
// option collection results without poking at unexported fields.
type ManagerOptionsView struct {
	CustomHandlers map[types.ContractType]handlers.Handler
}

func ApplyManagerOptionsForTest(opts ...ManagerOption) (ManagerOptionsView, error) {
	mo, err := applyManagerOptions(opts...)
	if err != nil {
		return ManagerOptionsView{}, err
	}
	return ManagerOptionsView{CustomHandlers: mo.customHandlers}, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -run TestWithHandler -v`
Expected: all 6 subtests PASS.

- [ ] **Step 6: Commit**

```bash
git add contract/manager_opts.go contract/manager_opts_test.go contract/export_test.go
git commit -m "contract: add ManagerOption and WithHandler"
```

---

## Task 5: Rewire `NewManager` and shrink `contractManager`

`NewManager` becomes variadic; the internal struct drops `handlers map` + `mu`; gains `registry *registry`. `Registry()` getter is added. `GetHandler` delegates. `GetSupportedContractTypes` (impl) is **removed** — interface change comes in Task 6.

**Files:**
- Modify: `contract/manager.go`
- Modify: `contract/types.go` (only the `Args` doc cleanup; full Manager interface change in Task 6)

- [ ] **Step 1: Rewrite `contract/manager.go` — struct and `NewManager`**

Replace the existing `contractManager` struct, `NewManager`, `GetSupportedContractTypes`, `GetHandler`, `Clean`, `Close`, `ScanContracts`, `NewContract`, and `GetContracts` with the versions below. The `scanContracts`, `newContract`, `findUsedContracts`, `findUsedBoardingContracts`, and `findUsedFn` definitions stay **unchanged**.

```go
// contract/manager.go (relevant sections only)
package contract

import (
	"context"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
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
	registry    *registry
}

func NewManager(args Args, opts ...ManagerOption) (Manager, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}
	mo, err := applyManagerOptions(opts...)
	if err != nil {
		return nil, err
	}

	// Wrap the transport client once with a shared GetInfo cache so all
	// built-in handlers reuse the same cached server info. Custom handlers
	// supplied via WithHandler are constructed outside the manager and own
	// their own client wiring.
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

func (m *contractManager) ScanContracts(ctx context.Context, gapLimit uint32) error {
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
	if err := m.store.Clean(ctx); err != nil {
		return err
	}

	log.Debugf("%s cleaned contract store", logPrefix)
	return nil
}

func (m *contractManager) Close() {
	log.Debugf("%s closed contract manager", logPrefix)
}
```

> Notes for the implementer:
> 1. **Delete** the `GetSupportedContractTypes` method and the `sync` + `slices` + `maps` imports if they're no longer used.
> 2. The variadic `time` import is retained because `findUsedBoardingContracts` uses `time.Sleep`.
> 3. `scanContracts`, `newContract`, `findUsedContracts`, `findUsedBoardingContracts`, and `findUsedFn` (the unexported helpers below `Close`) are **unchanged** from master. Don't accidentally remove them.

- [ ] **Step 2: Run the existing `contract` unit tests — expect compile errors first**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go build ./contract/...`
Expected: PASS — `contract` package builds.

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -count=1 -run "TestRegistry|TestNewRegistry|TestAssertNonNilHandler|TestWithHandler" -v`
Expected: all PASS.

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -count=1 -run TestManagerNewContract -v`
Expected: all PASS (`TestManagerNewContract` is unchanged; it goes through `mgr.NewContract` → registry).

- [ ] **Step 3: Run `TestManagerGetSupportedContractTypes` — expect failure**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -count=1 -run TestManagerGetSupportedContractTypes -v`
Expected: build error — `mgr.GetSupportedContractTypes` no longer exists. This will be removed in Task 6.

- [ ] **Step 4: Commit**

```bash
git add contract/manager.go
git commit -m "contract: rewire NewManager around Registry; drop handlers map and mutex"
```

> Note: the package will not fully `go test` at this point — `TestManagerGetSupportedContractTypes` still references the removed method. That test is deleted in Task 6.

---

## Task 6: Update `Manager` interface and clean up the old test

Drop `GetSupportedContractTypes` from the interface; add `Registry()`. Delete the test that exercised it; add a new test for `Registry()`.

**Files:**
- Modify: `contract/types.go`
- Modify: `contract/manager_test.go`

- [ ] **Step 1: Update `Manager` interface in `contract/types.go`**

In `contract/types.go`, replace lines 16–41 (the `Manager` interface) with:

```go
// Manager manages the lifecycle of contracts derived from wallet keys.
// Constructed by NewManager; the registered handler set is sealed at that
// point — see Registry() and contract.WithHandler.
type Manager interface {
	// Registry returns the sealed handler registry. Use it to discover
	// which contract types this manager supports.
	Registry() Registry
	// ScanContracts looks for untracked contracts to store of any type,
	// and for each of them stops when gapLimit consecutive unused
	// contracts have been found.
	ScanContracts(ctx context.Context, gapLimit uint32) error
	// NewContract creates and stores a new contract. The key is derived
	// from the key provider, all required parameters are fetched by the
	// proper handler based on the contract type.
	NewContract(
		ctx context.Context, contractType types.ContractType, opts ...ContractOption,
	) (*types.Contract, error)
	// GetContracts returns all contracts matching the given filter option.
	// All filters are mutually exclusive, i.e. only one filter can be set
	// at a time. Pass no options to return all contracts.
	GetContracts(ctx context.Context, opts ...FilterOption) ([]types.Contract, error)
	// GetHandler returns the handler responsible for the given contract's
	// type. Errors when the contract type is not registered. Delegates to
	// Registry().GetHandler(contract.Type).
	GetHandler(ctx context.Context, contract types.Contract) (handlers.Handler, error)
	// Clean removes all contracts from the store. Must be used only at
	// wallet reset.
	Clean(ctx context.Context) error
	// Close releases any resources held by the manager.
	Close()
}
```

- [ ] **Step 2: Delete `TestManagerGetSupportedContractTypes` from `contract/manager_test.go`**

In `contract/manager_test.go`, delete the entire function (lines 124–131 in the current file):

```go
func TestManagerGetSupportedContractTypes(t *testing.T) {
	mgr, _ := newTestManager(t)
	supported := mgr.GetSupportedContractTypes(t.Context())
	require.ElementsMatch(
		t,
		[]types.ContractType{types.ContractTypeDefault, types.ContractTypeBoarding},
		supported,
	)
}
```

If the `maps` or `slices` imports near the top of `manager_test.go` become unused after this delete (they're only used by that function — verify with `goimports` or the compiler), remove them too.

- [ ] **Step 3: Run the existing tests**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -count=1 -v`
Expected: all tests PASS. No more reference to `GetSupportedContractTypes`.

- [ ] **Step 4: Add new tests exercising `Registry()` from `Manager`**

Append to `contract/manager_test.go`:

```go
func TestManager_Registry(t *testing.T) {
	t.Run("built-ins only", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		got := mgr.Registry().SupportedTypes()
		require.Equal(
			t,
			[]types.ContractType{types.ContractTypeBoarding, types.ContractTypeDefault},
			got,
		)
	})

	t.Run("with custom handler merged", func(t *testing.T) {
		mgr := newTestManagerWithHandlers(
			t,
			contract.WithHandler("vhtlc", newFakeHandler("vhtlc")),
		)
		got := mgr.Registry().SupportedTypes()
		require.Equal(
			t,
			[]types.ContractType{
				types.ContractTypeBoarding,
				types.ContractTypeDefault,
				types.ContractType("vhtlc"),
			},
			got,
		)
	})

	t.Run("registry is the same instance returned by GetHandler delegation", func(t *testing.T) {
		mgr := newTestManagerWithHandlers(
			t,
			contract.WithHandler("vhtlc", newFakeHandler("vhtlc")),
		)
		direct, err := mgr.Registry().GetHandler(types.ContractType("vhtlc"))
		require.NoError(t, err)
		viaManager, err := mgr.GetHandler(
			t.Context(),
			types.Contract{Type: types.ContractType("vhtlc")},
		)
		require.NoError(t, err)
		require.Same(t, direct, viaManager)
	})
}

func TestNewManager_RejectsBuiltinCollision(t *testing.T) {
	_, err := contract.NewManager(
		newValidTestArgs(t),
		contract.WithHandler(
			types.ContractTypeDefault,
			newFakeHandler(types.ContractTypeDefault),
		),
	)
	require.ErrorContains(t, err, "reserved by a built-in handler")
}
```

`newTestManagerWithHandlers` and `newValidTestArgs` need helpers in `utils_test.go`.

- [ ] **Step 5: Extend `contract/utils_test.go` with the helpers**

Append to `contract/utils_test.go`:

```go
// newValidTestArgs returns a freshly wired Args with a mocked env. Use
// when a test wants to call contract.NewManager directly (for example to
// pass ManagerOptions and assert on the construction result).
func newValidTestArgs(t *testing.T) contract.Args {
	t.Helper()
	env := newMockedEnv(t)
	svc, err := store.NewStore(store.Config{
		StoreType: types.SQLStore,
		Args:      t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	return contract.Args{
		Store:       svc.ContractStore(),
		KeyProvider: env.identity,
		Client:      env.transport,
		Indexer:     env.indexer,
		Explorer:    env.explorer,
		Network:     testNetwork,
	}
}

// newTestManagerWithHandlers is like newTestManager but lets the caller
// pass extra ManagerOptions (typically contract.WithHandler calls). The
// store handle is not returned because none of the call sites need it.
func newTestManagerWithHandlers(
	t *testing.T, opts ...contract.ManagerOption,
) contract.Manager {
	t.Helper()
	mgr, err := contract.NewManager(newValidTestArgs(t), opts...)
	require.NoError(t, err)
	t.Cleanup(mgr.Close)
	return mgr
}
```

- [ ] **Step 6: Run all `contract` tests**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./contract/ -count=1 -v`
Expected: all tests PASS (including the four new `TestManager_Registry` / `TestNewManager_RejectsBuiltinCollision` subtests).

- [ ] **Step 7: Commit**

```bash
git add contract/types.go contract/manager_test.go contract/utils_test.go
git commit -m "contract: drop GetSupportedContractTypes from Manager; add Registry() tests"
```

---

## Task 7: Update `contract/doc.go`

The package doc still references PR #145's locking model and a "TODO: registry" note. Bring it in line with the new sealed-registry model.

**Files:**
- Modify: `contract/doc.go`

- [ ] **Step 1: Read the current doc.go to anchor the edit**

Run: `sed -n '70,90p' /Users/piero/projects/ark-labs/go-sdk/contract/doc.go`
(Inspect the locking + Extending sections.)

- [ ] **Step 2: Replace the locking paragraph and the Extending section**

Replace the paragraph that currently starts with `// The manager guards its handler map with an [sync.RWMutex].` and the Extending section beneath it. The replacement text:

```go
// The handler map is sealed at NewManager time: it cannot be mutated
// once the manager is constructed. There is therefore no mutex on the
// manager — registry reads are concurrent-safe by virtue of
// immutability. The store and the info cache have their own internal
// locking.
//
// # Extending with new contract types
//
// New handler kinds (vhtlc, delegate, custom user-defined contracts, …)
// plug in by:
//  1. Implementing handlers.Handler (see contract/handlers/handler.go).
//  2. Passing the handler to NewManager via [WithHandler], keyed by a
//     new types.ContractType. WithHandler rejects empty types, nil
//     handlers, typed-nil concrete values, and duplicates in the same
//     options list. NewManager additionally rejects any type that
//     collides with a built-in (default, boarding).
//  3. If the new type's "has this contract been used externally?" probe
//     differs from the indexer or explorer paths the dispatcher already
//     knows about, adding a branch in ScanContracts that selects the
//     correct findUsedFn. By default ScanContracts uses the indexer
//     (offchain) path for any non-boarding type.
//
// User-registered handlers are responsible for their own client caching.
// The manager wraps args.Client with a shared GetInfo cache and hands
// the wrapped client to the built-in handlers only — handlers
// constructed by callers were built before the manager existed and need
// not depend on client.Client at all.
//
// At the wallet layer, callers use [arksdk.WithContractHandler] to
// register handlers at NewWallet time; the wallet translates them to
// contract.WithHandler options inside Unlock.
```

Also fix the slightly stale paragraph above (line ~78 in the original) that mentions mutations holding the write lock:

Find:
```
//   - mutations (NewContract, ScanContracts, Clean, Close) hold the write
//     lock.
```

Replace with: (just delete those two lines — the new doc above explains the absence of a mutex).

- [ ] **Step 3: Build to verify the doc still compiles**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go build ./contract/...`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add contract/doc.go
git commit -m "contract: update package doc for sealed-registry model"
```

---

## Task 8: Wallet-level option `WithContractHandler`

Add the public option that wallet users will call. Stash collected handlers in `walletOptions`.

**Files:**
- Modify: `wallet_opts.go`
- Modify: `wallet_opts_test.go` (extend; create if it doesn't exist)

- [ ] **Step 1: Check whether `wallet_opts_test.go` exists**

Run: `ls /Users/piero/projects/ark-labs/go-sdk/wallet_opts_test.go 2>/dev/null || echo MISSING`
Expected output: either the file path (if exists) or `MISSING`.

If MISSING, create it as a fresh file with the test below. If it exists, append.

- [ ] **Step 2: Write the failing tests**

Add to `wallet_opts_test.go`:

```go
package arksdk_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	arksdk "github.com/arkade-os/go-sdk"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// fakeWalletHandler mirrors contract_test.fakeHandler at the arksdk_test
// package level so wallet-level option tests don't depend on the internal
// test fixture.
type fakeWalletHandler struct{ typ types.ContractType }

func (h *fakeWalletHandler) NewContract(
	_ context.Context, k identity.KeyRef,
) (*types.Contract, error) {
	s := sha256.Sum256([]byte(string(h.typ) + ":" + k.Id))
	return &types.Contract{
		Type: h.typ, Script: hex.EncodeToString(s[:]),
		State: types.ContractStateActive,
	}, nil
}
func (h *fakeWalletHandler) GetKeyRefs(types.Contract) (map[string]string, error) {
	return nil, nil
}
func (h *fakeWalletHandler) GetKeyRef(types.Contract) (*identity.KeyRef, error) {
	return nil, errors.New("not implemented")
}
func (h *fakeWalletHandler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (h *fakeWalletHandler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}
func (h *fakeWalletHandler) GetTapscripts(types.Contract) ([]string, error) {
	return nil, nil
}
var _ handlers.Handler = (*fakeWalletHandler)(nil)

func TestWithContractHandler(t *testing.T) {
	t.Run("valid passes", func(t *testing.T) {
		require.NoError(t, arksdk.ApplyWalletOptions(
			arksdk.WithContractHandler("vhtlc", &fakeWalletHandler{typ: "vhtlc"}),
		))
	})

	t.Run("multiple distinct types pass", func(t *testing.T) {
		require.NoError(t, arksdk.ApplyWalletOptions(
			arksdk.WithContractHandler("vhtlc", &fakeWalletHandler{typ: "vhtlc"}),
			arksdk.WithContractHandler("delegate", &fakeWalletHandler{typ: "delegate"}),
		))
	})

	t.Run("empty type errors", func(t *testing.T) {
		err := arksdk.ApplyWalletOptions(
			arksdk.WithContractHandler("", &fakeWalletHandler{typ: "x"}),
		)
		require.ErrorContains(t, err, "missing contract type")
	})

	t.Run("nil handler errors", func(t *testing.T) {
		err := arksdk.ApplyWalletOptions(
			arksdk.WithContractHandler("vhtlc", nil),
		)
		require.ErrorContains(t, err, `nil handler for contract type "vhtlc"`)
	})

	t.Run("typed-nil handler errors", func(t *testing.T) {
		var h *fakeWalletHandler
		err := arksdk.ApplyWalletOptions(
			arksdk.WithContractHandler("vhtlc", h),
		)
		require.ErrorContains(t, err, `nil concrete handler for contract type "vhtlc"`)
	})

	t.Run("duplicate type errors", func(t *testing.T) {
		err := arksdk.ApplyWalletOptions(
			arksdk.WithContractHandler("vhtlc", &fakeWalletHandler{typ: "vhtlc"}),
			arksdk.WithContractHandler("vhtlc", &fakeWalletHandler{typ: "vhtlc"}),
		)
		require.ErrorContains(t, err, `duplicate handler for contract type "vhtlc"`)
	})
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test . -run TestWithContractHandler -v`
Expected: build error `undefined: arksdk.WithContractHandler`.

- [ ] **Step 4: Implement `WithContractHandler`**

In `wallet_opts.go`:

1. Add imports (merge with existing):

```go
import (
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
)
```

2. Append at the bottom of the file:

```go
// WithContractHandler registers a custom contract handler that the
// wallet's contract manager will dispatch to for the given contract
// type. The type must be non-empty, the handler non-nil, and must not
// collide with another previously registered custom handler. Collisions
// with a built-in type (default, boarding) are detected at Unlock time
// via the underlying contract.WithHandler / contract.NewManager checks.
// Multiple calls are allowed for different types.
func WithContractHandler(t types.ContractType, h handlers.Handler) WalletOption {
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

3. Extend `walletOptions` struct (lines 123–131 of current file) to add the new field:

```go
type walletOptions struct {
	refreshDbInterval time.Duration
	verbose           bool
	hdGapLimit        uint32
	hdGapLimitSet     bool
	identity          identity.Identity
	scheduler         scheduler.SchedulerService
	disableAutoSettle bool
	customHandlers    map[types.ContractType]handlers.Handler
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test . -run TestWithContractHandler -v`
Expected: all 6 subtests PASS.

- [ ] **Step 6: Commit**

```bash
git add wallet_opts.go wallet_opts_test.go
git commit -m "arksdk: add WithContractHandler wallet option"
```

---

## Task 9: Propagate `customHandlers` through `wallet` struct and `Unlock`

Wire the option-collected map all the way to `contract.NewManager`.

**Files:**
- Modify: `wallet.go` (struct field + both constructors)
- Modify: `init.go` (translate to `[]contract.ManagerOption` and pass to `NewManager`)

- [ ] **Step 1: Add `customHandlers` field to the `wallet` struct**

In `wallet.go`, in the `type wallet struct {` block (lines 45–73 in current file), add at the end of the struct body (just before the closing `}`):

```go
	customHandlers map[types.ContractType]handlers.Handler
```

Imports: `handlers` is `github.com/arkade-os/go-sdk/contract/handlers`. Add to the import block if not already there.

- [ ] **Step 2: Populate the field in `NewWallet`**

In `wallet.go`, in the return statement at the end of `NewWallet` (currently lines 133–146), add a field:

```go
	return &wallet{
		client:            cli,
		verbose:           o.verbose,
		store:             db,
		clientStore:       clientDb,
		syncMu:            &sync.Mutex{},
		syncListeners:     newReadyListeners(),
		syncCh:            make(chan error),
		dbMu:              &sync.Mutex{},
		logMu:             &sync.Mutex{},
		refreshDbInterval: o.refreshDbInterval,
		hdGapLimit:        o.hdGapLimit,
		scheduler:         o.scheduler,
		customHandlers:    o.customHandlers,
	}, nil
```

- [ ] **Step 3: Populate the field in `LoadWallet`**

In `wallet.go`, in the return statement at the end of `LoadWallet` (currently lines 245–259), add the same field:

```go
	return &wallet{
		client:            cli,
		verbose:           o.verbose,
		store:             db,
		clientStore:       clientDb,
		syncMu:            &sync.Mutex{},
		syncListeners:     newReadyListeners(),
		syncCh:            make(chan error),
		dbMu:              &sync.Mutex{},
		logMu:             &sync.Mutex{},
		refreshDbInterval: o.refreshDbInterval,
		hdGapLimit:        o.hdGapLimit,
		scheduler:         o.scheduler,
		network:           cfgData.Network,
		customHandlers:    o.customHandlers,
	}, nil
```

- [ ] **Step 4: Translate to `[]contract.ManagerOption` inside `Unlock`**

In `init.go`, replace lines 103–110 (the `contract.NewManager(contract.Args{...})` call) with:

```go
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

- [ ] **Step 5: Build and run unit tests**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go build ./...`
Expected: PASS.

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go vet ./...`
Expected: PASS.

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./... -count=1 -short`
Expected: all PASS (skips e2e because of `-short`).

- [ ] **Step 6: Commit**

```bash
git add wallet.go init.go
git commit -m "arksdk: wire customHandlers through wallet construction and Unlock"
```

---

## Task 10: Wallet-level integration test

Verify that a handler passed to `NewWallet(WithContractHandler(...))` lands in `mgr.Registry()` after `Unlock`. This is an in-process test against a fresh wallet using the existing e2e helpers, but it does not require regtest — it can run in the unit suite using the in-memory test wiring already in `test/e2e/utils_test.go` if available, or a lighter-weight isolated test.

**Important:** Look at how existing tests construct a wallet without going through the full e2e harness — `init_test.go` if it exists, or use the test helpers from the `feat/custom-contracts` branch as a reference. If no lightweight harness is available in the unit suite, place this test in `test/e2e/` so it can use the regtest setup. The test name and structure should mirror existing e2e tests under the build tags they already use.

**Files:**
- Modify: `test/e2e/<existing_test_file>.go` (probably `restore_smoke_test.go` or a new `custom_handler_test.go`), OR a new lighter unit test if a non-regtest harness is available.

- [ ] **Step 1: Locate an existing e2e test that exercises `NewWallet` + `Unlock`**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && grep -rn "arksdk.NewWallet" test/e2e/ | head -5`
Expected: a list of files showing the call pattern.

Use one of those as the template. The skeleton below assumes the same patterns.

- [ ] **Step 2: Write the new e2e test**

Create `test/e2e/custom_handler_test.go`:

```go
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

type customTestHandler struct{ typ types.ContractType }

func (h *customTestHandler) NewContract(
	_ context.Context, k identity.KeyRef,
) (*types.Contract, error) {
	s := sha256.Sum256([]byte(string(h.typ) + ":" + k.Id))
	return &types.Contract{
		Type:   h.typ,
		Script: hex.EncodeToString(s[:]),
		State:  types.ContractStateActive,
		Params: map[string]string{"ownerKeyId": k.Id},
	}, nil
}
func (h *customTestHandler) GetKeyRefs(types.Contract) (map[string]string, error) {
	return nil, nil
}
func (h *customTestHandler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	id, ok := c.Params["ownerKeyId"]
	if !ok {
		return nil, errors.New("missing ownerKeyId")
	}
	return &identity.KeyRef{Id: id}, nil
}
func (h *customTestHandler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (h *customTestHandler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}
func (h *customTestHandler) GetTapscripts(types.Contract) ([]string, error) {
	return nil, nil
}
var _ handlers.Handler = (*customTestHandler)(nil)

func TestCustomContractHandlerRegistered(t *testing.T) {
	arkClient := setupClient(t, arksdk.WithContractHandler(
		types.ContractType("vhtlc"),
		&customTestHandler{typ: "vhtlc"},
	))

	require.NoError(t, arkClient.Unlock(t.Context(), testPassword))

	mgr := arkClient.ContractManager()
	require.NotNil(t, mgr)

	got := mgr.Registry().SupportedTypes()
	require.Contains(t, got, types.ContractType("vhtlc"))
	require.Contains(t, got, types.ContractTypeDefault)
	require.Contains(t, got, types.ContractTypeBoarding)

	h, err := mgr.Registry().GetHandler(types.ContractType("vhtlc"))
	require.NoError(t, err)
	require.NotNil(t, h)
}
```

> Notes:
> - `setupClient` and `testPassword` must already exist in `test/e2e/utils_test.go`. The implementer should confirm and adapt the call signature if the helpers take different arguments.
> - The test does NOT need regtest. If `setupClient` requires a running regtest node, place the test under whatever build tag the rest of e2e uses and gate it accordingly. If the test can run without external infra, it's preferred to move it to a lighter location (e.g. `wallet_init_test.go`) — the implementer should pick based on what's possible without breaking layering.

- [ ] **Step 3: Run the test against the existing e2e infra**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./test/e2e/ -count=1 -run TestCustomContractHandlerRegistered -v`
Expected: PASS.

If the test cannot run because e2e requires regtest, run it as part of the standard e2e gate during Task 11 instead.

- [ ] **Step 4: Commit**

```bash
git add test/e2e/custom_handler_test.go
git commit -m "test/e2e: WithContractHandler registers handler in manager registry"
```

---

## Task 11: Full validation gate

Run the same checks GitHub Actions runs.

- [ ] **Step 1: `go build ./...`**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 2: `go vet ./...`**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go vet ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Lint**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && make lint`
Expected: clean.

If `make lint` doesn't exist or fails for unrelated reasons, run: `cd /Users/piero/projects/ark-labs/go-sdk && golangci-lint run ./...`

- [ ] **Step 4: Unit tests**

Run: `cd /Users/piero/projects/ark-labs/go-sdk && go test ./... -count=1 -short`
Expected: all PASS.

- [ ] **Step 5: Invoke the gosdk-gha skill for full CI parity**

Use the `gosdk-gha` skill (listed in available skills) to run the full GitHub Actions simulation locally — lint, vet, build, unit tests, integration tests. **Mandatory.** The integration tests are the gate that catches issues `-short` cannot.

- [ ] **Step 6: Final commit (if any drift)**

If the validation gate surfaced anything (lint cleanups, missing imports, etc.), fix in-place and commit:

```bash
git add -A
git commit -m "contract: address validation findings from full CI gate"
```

If nothing surfaced, skip this step.

---

## Self-review

1. **Spec coverage:** Every section of `2026-05-22-contract-registry-design.md` is covered:
   - §5 Registry — Task 3
   - §6 ManagerOption/WithHandler/AssertNonNilHandler — Tasks 2, 4
   - §7 Manager surface delta — Tasks 5, 6
   - §8 Wallet-level option — Tasks 8, 9
   - §9 Tests by layer — interleaved with each task; e2e integration test in Task 10
   - §10 Migration from PR #151 — implicit (PR #151 isn't merged, so its diff doesn't need active removal; we're starting fresh on `contract-registry`)
   - §11 Risks — risk #1 (breaking change to master `GetSupportedContractTypes`) is realized in Task 6; risk #2 (mutex removal) is mitigated by the Registry interface having no `Register` method (Task 3); risk #3 (typed-nil reflect) is implemented in Task 2 with tests.

2. **Placeholder scan:** No "TBD"/"TODO"/"implement later"/"add error handling" remain. Each step shows the full code or full command.

3. **Type consistency:**
   - `Registry`, `Manager`, `ManagerOption`, `managerOptions`, `WithHandler`, `WithContractHandler`, `AssertNonNilHandler`, `newRegistry`, `customHandlers`, `NewRegistryForTest`, `ApplyManagerOptionsForTest`, `newTestManagerWithHandlers`, `newValidTestArgs` — names consistent across all tasks.
   - `ManagerOptionsView.CustomHandlers` is the only flattened public alias of the unexported `managerOptions.customHandlers`, used only in `_test.go`.
   - `wallet.customHandlers` is named identically to `walletOptions.customHandlers` for clarity.

4. **No fabricated APIs:** `setupClient`, `testPassword`, `t.Context()`, `require.ErrorContains`, `require.Same`, `require.Equal`, `require.NotNil` are all in the existing test base. The implementer should confirm `setupClient`'s exact signature at Task 10 step 2.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-22-contract-registry.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
