package arksdk

import (
	"fmt"
	"reflect"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/scheduler"
	"github.com/arkade-os/go-sdk/types"
)

const (
	minInterval     = 30 * time.Second
	defaultGapLimit = 20
)

type WalletOption func(*walletOptions) error

// ApplyWalletOptions applies opts to a new default clientOptions and returns
// the first error encountered, if any.
// Exposed for use in external (arksdk_test) test packages.
func ApplyWalletOptions(opts ...WalletOption) error {
	_, err := applyWalletOptions(opts...)
	return err
}

// WithRefreshDbInterval sets the interval at which the local database is
// periodically refreshed from the server. Must be at least 30s. Can only be set once.
// If no WalletOption is passed, refreshDbInterval defaults to zero, which
// disables periodic refresh entirely.
func WithRefreshDbInterval(d time.Duration) WalletOption {
	return func(o *walletOptions) error {
		if o.refreshDbInterval != 0 {
			return fmt.Errorf("refresh db interval already set")
		}
		if d < minInterval {
			return fmt.Errorf("refresh db interval must be at least %s", minInterval)
		}
		o.refreshDbInterval = d
		return nil
	}
}

// WithVerbose enables verbose logging.
func WithVerbose() WalletOption {
	return func(o *walletOptions) error {
		o.verbose = true
		return nil
	}
}

// WithGapLimit sets the HD wallet discovery gap limit used during startup
// recovery. Must be greater than zero.
func WithGapLimit(limit uint32) WalletOption {
	return func(o *walletOptions) error {
		if o.hdGapLimitSet {
			return fmt.Errorf("gap limit already set")
		}
		if limit == 0 {
			return fmt.Errorf("gap limit must be greater than zero")
		}
		o.hdGapLimit = limit
		o.hdGapLimitSet = true
		return nil
	}
}

// WithIdentity injects a custom Identity implementation for key management.
// Can only be set once and must not be nil.
func WithIdentity(identitySvc identity.Identity) WalletOption {
	return func(o *walletOptions) error {
		if o.identity != nil {
			return fmt.Errorf("identity already set")
		}
		if identitySvc == nil {
			return fmt.Errorf("identity cannot be nil")
		}
		o.identity = identitySvc
		return nil
	}
}

// WithScheduler injects a custom SchedulerService implementation for task scheduling.
func WithScheduler(svc scheduler.SchedulerService) WalletOption {
	return func(o *walletOptions) error {
		if svc == nil {
			return fmt.Errorf("scheduler cannot be nil")
		}
		if o.scheduler != nil {
			return fmt.Errorf("scheduler already set")
		}
		if o.disableAutoSettle {
			return fmt.Errorf("cannot set scheduler when auto-settle is disabled")
		}
		o.scheduler = svc
		return nil
	}
}

// WithoutAutoSettle disables the auto-settle feature.
func WithoutAutoSettle() WalletOption {
	return func(o *walletOptions) error {
		if o.scheduler != nil {
			return fmt.Errorf("cannot disable auto-settle when scheduler is set")
		}
		o.disableAutoSettle = true
		return nil
	}
}

func applyWalletOptions(opts ...WalletOption) (*walletOptions, error) {
	o := newDefaultWalletOptions()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("wallet option cannot be nil")
		}
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

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

// newDefaultWalletOptions returns a zero-value walletOptions.
// A zero refreshDbInterval disables periodic DB refresh (periodicRefreshDb exits early).
func newDefaultWalletOptions() *walletOptions {
	return &walletOptions{hdGapLimit: defaultGapLimit}
}

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
