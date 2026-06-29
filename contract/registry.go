package contract

import (
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/internal/utils"
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

func NewRegistry(builtIns, customs map[types.ContractType]handlers.Handler) (Registry, error) {
	return newRegistry(builtIns, customs)
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

// newRegistry merges built-ins with caller-supplied custom handlers, applying all rules that need
// cross-handler visibility (built-in collision).
// Per-option validations (empty type, nil handler, typed-nil, duplicates inside the same
// WithHandler list) are caught earlier in WithHandler; this function still defends against them
// in case it's called from a path that didn't go through WithHandler.
func newRegistry(builtIns, customs map[types.ContractType]handlers.Handler) (*registry, error) {
	merged := make(map[types.ContractType]handlers.Handler, len(builtIns)+len(customs))
	for t, h := range builtIns {
		merged[t] = h
	}
	for t, h := range customs {
		if t == "" {
			return nil, fmt.Errorf("missing contract type")
		}
		if err := utils.ValidateHandler(h, t); err != nil {
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
