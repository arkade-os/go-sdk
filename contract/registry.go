package contract

import (
	"fmt"
	"sync"
)

// Registry holds the set of registered contract handlers.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]Handler)}
}

// DefaultRegistry is the package-level registry populated by handler init() calls.
var DefaultRegistry = NewRegistry()

// Register adds a handler. Returns an error if the type is already registered.
func (r *Registry) Register(h Handler) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.handlers[h.Type()]; ok {
		return fmt.Errorf("contract handler %q already registered", h.Type())
	}
	r.handlers[h.Type()] = h
	return nil
}

// Get returns the handler for a given type.
func (r *Registry) Get(typ string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[typ]
	return h, ok
}

// MustGet panics if no handler is registered for typ.
func (r *Registry) MustGet(typ string) Handler {
	h, ok := r.Get(typ)
	if !ok {
		panic(fmt.Sprintf("no contract handler registered for type %q", typ))
	}
	return h
}
