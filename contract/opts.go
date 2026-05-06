package contract

import (
	"fmt"

	"github.com/arkade-os/go-sdk/types"
)

// FilterOption configures a filter for Manager query methods.
// Pass no options to return all contracts.
type FilterOption interface {
	applyFilter(*filter) error
}

type filterOptFn func(*filter) error

func (f filterOptFn) applyFilter(o *filter) error { return f(o) }

func WithType(contractType types.ContractType) FilterOption {
	return filterOptFn(func(f *filter) error {
		if f.contractType != "" {
			return fmt.Errorf("contract type filter already set to %s", f.contractType)
		}
		if f.isOnchain || f.state != "" || len(f.scripts) != 0 || len(f.keyIds) != 0 {
			return fmt.Errorf("a filter is already set")
		}
		f.contractType = contractType
		return nil
	})
}

func WithState(state types.ContractState) FilterOption {
	return filterOptFn(func(f *filter) error {
		if f.state != "" {
			return fmt.Errorf("contract state filter already set to %s", f.state)
		}
		if f.isOnchain || f.contractType != "" || len(f.scripts) != 0 || len(f.keyIds) != 0 {
			return fmt.Errorf("a filter is already set")
		}
		f.state = state
		return nil
	})
}

func WithScripts(scripts []string) FilterOption {
	return filterOptFn(func(f *filter) error {
		if len(f.scripts) != 0 {
			return fmt.Errorf("contract scripts filter already set to %s", f.scripts)
		}
		if f.isOnchain || f.state != "" || f.contractType != "" || len(f.keyIds) != 0 {
			return fmt.Errorf("a filter is already set")
		}
		f.scripts = make([]string, len(scripts))
		copy(f.scripts, scripts)
		return nil
	})
}

func WithKeyIds(keyIds []string) FilterOption {
	return filterOptFn(func(f *filter) error {
		if len(f.keyIds) > 0 {
			return fmt.Errorf("key id filter already set to %s", f.keyIds)
		}
		if f.isOnchain || f.state != "" || f.contractType != "" || len(f.scripts) != 0 {
			return fmt.Errorf("a filter is already set")
		}
		f.keyIds = make([]string, len(keyIds))
		copy(f.keyIds, keyIds)
		return nil
	})
}

type filter struct {
	contractType types.ContractType
	state        types.ContractState
	scripts      []string
	isOnchain    bool
	keyIds       []string
}

func newDefaultFilter() *filter {
	return &filter{}
}

// ContractOption configures the creation of a new contract.
type ContractOption interface {
	applyContract(*contractOption) error
}

type contractOptFn func(*contractOption) error

func (f contractOptFn) applyContract(o *contractOption) error { return f(o) }

func WithDryRun() ContractOption {
	return contractOptFn(func(o *contractOption) error {
		if o.dryRun {
			return fmt.Errorf("dry run option is already set")
		}
		o.dryRun = true
		return nil
	})
}

func WithLabel(label string) ContractOption {
	return contractOptFn(func(o *contractOption) error {
		if o.label != "" {
			return fmt.Errorf("label option is already set to %s", o.label)
		}
		o.label = label
		return nil
	})
}

type contractOption struct {
	dryRun    bool
	label     string
	isOnchain bool
}

func newDefaultContractOption() *contractOption {
	return &contractOption{}
}

// IsOnchainOption is the intersection of every option family that accepts an
// "isOnchain" flag. A single WithIsOnchain satisfies both FilterOption and
// ContractOption — so the helper is defined once instead of duplicated per
// family.
type IsOnchainOption interface {
	FilterOption
	ContractOption
}

type isOnchainOpt struct{}

func (isOnchainOpt) applyFilter(f *filter) error {
	if f.isOnchain {
		return fmt.Errorf("isOnchain filter is already set")
	}
	if f.state != "" || f.contractType != "" || len(f.scripts) != 0 || len(f.keyIds) != 0 {
		return fmt.Errorf("a filter is already set")
	}
	f.isOnchain = true
	return nil
}

func (isOnchainOpt) applyContract(o *contractOption) error {
	if o.isOnchain {
		return fmt.Errorf("isOnchain option is already set")
	}
	o.isOnchain = true
	return nil
}

// WithIsOnchain marks the operation as onchain. It can be used both as a
// FilterOption (in GetContracts) and as a ContractOption (in NewContract /
// GetKeyIDUsedForLatestContract).
func WithIsOnchain() IsOnchainOption {
	return isOnchainOpt{}
}
