package arksdk

import (
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/scheduler"
	"github.com/arkade-os/go-sdk/types"
)

const (
	minInterval               = 30 * time.Second
	defaultGapLimit           = 20
	defaultMaxMigrationInputs = 50
)

type WalletOption func(*walletOptions) error

// ApplyWalletOptions validates wallet options for external tests.
func ApplyWalletOptions(opts ...WalletOption) error {
	_, err := applyWalletOptions(opts...)
	return err
}

// WithRefreshDbInterval enables periodic DB refresh. Must be at least 30s.
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

// WithGapLimit sets the HD startup recovery gap limit.
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

// WithMaxMigrationInputs caps deprecated-signer VTXOs per migration tx.
func WithMaxMigrationInputs(limit uint32) WalletOption {
	return func(o *walletOptions) error {
		if o.maxMigrationInputsSet {
			return fmt.Errorf("max migration inputs already set")
		}
		if limit == 0 {
			return fmt.Errorf("max migration inputs must be greater than zero")
		}
		o.maxMigrationInputs = int(limit)
		o.maxMigrationInputsSet = true
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

// WithContractHandler registers a custom handler for one contract type.
func WithContractHandler(t types.ContractType, h handlers.Handler) WalletOption {
	return func(o *walletOptions) error {
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
	refreshDbInterval     time.Duration
	verbose               bool
	hdGapLimit            uint32
	hdGapLimitSet         bool
	maxMigrationInputs    int
	maxMigrationInputsSet bool
	identity              identity.Identity
	scheduler             scheduler.SchedulerService
	disableAutoSettle     bool
	customHandlers        map[types.ContractType]handlers.Handler
}

// newDefaultWalletOptions returns defaults; zero refreshDbInterval disables polling.
func newDefaultWalletOptions() *walletOptions {
	return &walletOptions{
		hdGapLimit:         defaultGapLimit,
		maxMigrationInputs: defaultMaxMigrationInputs,
	}
}
