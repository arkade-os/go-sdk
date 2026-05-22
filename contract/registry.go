package contract

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
)

// Registry maps contract types to their handler implementations.
// Constructed once by NewManager; immutable for its lifetime.
type Registry interface {
	// GetHandler returns the handler for the given contract type, or a descriptive error if none
	// is registered.
	GetHandler(t types.ContractType) (handlers.Handler, error)
	// SupportedTypes returns all registered contract types in deterministic (alphabetical) order.
	// Built-ins are included.
	SupportedTypes() []types.ContractType
}

// registry is the concrete, unexported implementation.
// Callers seed it indirectly via contract.WithHandler options to NewManager.
type registry struct {
	handlers map[types.ContractType]handlers.Handler
}

// NewRegistry merges built-ins with caller-supplied custom handlers, applying all rules that need
// cross-handler visibility (built-in collision).
// Per-option validations (empty type, nil handler, typed-nil, duplicates inside the same
// WithHandler list) are caught earlier in WithHandler; this function still defends against them
// in case it's called from a path that didn't go through WithHandler.
func NewRegistry(builtIns, customs map[types.ContractType]handlers.Handler) (*registry, error) {
	merged := make(map[types.ContractType]handlers.Handler, len(builtIns)+len(customs))
	for t, h := range builtIns {
		merged[t] = h
	}
	for t, h := range customs {
		if t == "" {
			return nil, fmt.Errorf("missing contract type")
		}
		if err := validateHandler(h, t); err != nil {
			return nil, err
		}
		if _, isBuiltIn := builtIns[t]; isBuiltIn {
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

// validateHandler rejects both an interface that is nil and an interface holding a typed-nil
// concrete value (e.g. var h *MyHandler; validateHandler(h, ...)).
func validateHandler(h handlers.Handler, t types.ContractType) error {
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
