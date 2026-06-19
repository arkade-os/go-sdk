package contract

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
)

// ManagerOption configures NewManager. The only currently defined option
// is WithHandler.
type ManagerOption func(*managerOptions) error

// WithHandler registers a custom handler for a non-built-in contract type.
// Errors if the type is empty, the handler is nil/typed-nil, or the same
// type was passed to a previous WithHandler in the same NewManager call.
// Collision with built-in types is detected later, in contract manager.
func WithHandler(t types.ContractType, h handlers.Handler) ManagerOption {
	return func(o *managerOptions) error {
		if t == "" {
			return fmt.Errorf("missing contract type")
		}
		if err := utils.ValidateHandler(h, t); err != nil {
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

type managerOptions struct {
	customHandlers map[types.ContractType]handlers.Handler
}

func newDefaultManagerOption() *managerOptions {
	return &managerOptions{}
}

// FilterOption configures a filter for Manager query methods.
// Pass no options to return all contracts.
type FilterOption interface {
	applyFilter(*filterOptions) error
}

type filterOptFn func(*filterOptions) error

func (f filterOptFn) applyFilter(o *filterOptions) error { return f(o) }

func WithType(contractType types.ContractType) FilterOption {
	return filterOptFn(func(f *filterOptions) error {
		if f.contractType != "" {
			return fmt.Errorf("contract type filter already set to %s", f.contractType)
		}
		if f.state != "" || len(f.scripts) != 0 {
			return fmt.Errorf("a filter is already set")
		}
		f.contractType = contractType
		return nil
	})
}

func WithState(state types.ContractState) FilterOption {
	return filterOptFn(func(f *filterOptions) error {
		if f.state != "" {
			return fmt.Errorf("contract state filter already set to %s", f.state)
		}
		if f.contractType != "" || len(f.scripts) != 0 {
			return fmt.Errorf("a filter is already set")
		}
		f.state = state
		return nil
	})
}

func WithScripts(scripts []string) FilterOption {
	return filterOptFn(func(f *filterOptions) error {
		if len(scripts) <= 0 {
			return fmt.Errorf("missing scripts")
		}
		if len(f.scripts) > 0 {
			return fmt.Errorf("contract scripts filter already set to %s", f.scripts)
		}
		if f.state != "" || f.contractType != "" {
			return fmt.Errorf("a filter is already set")
		}
		f.scripts = make([]string, len(scripts))
		copy(f.scripts, scripts)
		return nil
	})
}

type filterOptions struct {
	contractType types.ContractType
	state        types.ContractState
	scripts      []string
}

func newDefaultFilter() *filterOptions {
	return &filterOptions{}
}

// ContractOption configures the creation of a new contract.
type ContractOption interface {
	applyContract(*contractOptions) error
}

type contractOptFn func(*contractOptions) error

func (f contractOptFn) applyContract(o *contractOptions) error { return f(o) }

func WithLabel(label string) ContractOption {
	return contractOptFn(func(o *contractOptions) error {
		if o.label != "" {
			return fmt.Errorf("label option is already set to %s", o.label)
		}
		o.label = label
		return nil
	})
}

// WithParams passes handler-specific parameters for contract creation.
// Each handler type documents its expected concrete type
// (e.g. *vhtlcHandler.ContractParams for VHTLC contracts).
func WithParams(params any) ContractOption {
	return contractOptFn(func(o *contractOptions) error {
		if o.params != nil {
			return fmt.Errorf("params option is already set")
		}
		if params == nil {
			return fmt.Errorf("params must not be nil")
		}
		o.params = params
		return nil
	})
}

// WithKeyRef creates the contract with a caller-selected wallet key instead of
// deriving the next key from the contract manager. This is useful when an
// external protocol needs the wallet pubkey before all contract params are
// known, then the final contract must be stored with that same key.
func WithKeyRef(keyRef identity.KeyRef) ContractOption {
	return contractOptFn(func(o *contractOptions) error {
		if o.keyRef != nil {
			return fmt.Errorf("key ref option is already set")
		}
		if keyRef.Id == "" {
			return fmt.Errorf("key ref ID is required")
		}
		if keyRef.PubKey == nil {
			return fmt.Errorf("key ref pubkey is required")
		}
		k := keyRef
		o.keyRef = &k
		return nil
	})
}

type contractOptions struct {
	label  string
	params any
	keyRef *identity.KeyRef
}

func newDefaultContractOption() *contractOptions {
	return &contractOptions{}
}
