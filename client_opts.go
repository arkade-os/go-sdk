package arksdk

import (
	"fmt"
	"time"
)

const (
	minInterval = 30 * time.Second
)

type ClientOption func(*clientOptions) error

// ApplyClientOptions applies opts to a new default clientOptions and returns
// the first error encountered, if any.
// Exposed for use in external (arksdk_test) test packages.
func ApplyClientOptions(opts ...ClientOption) error {
	_, err := applyClientOptions(opts...)
	return err
}

// WithRefreshDbInterval sets the interval at which the local database is
// periodically refreshed from the server. Must be at least 30s. Can only be set once.
// If no ClientOption is passed, refreshDbInterval defaults to zero, which
// disables periodic refresh entirely.
func WithRefreshDbInterval(d time.Duration) ClientOption {
	return func(o *clientOptions) error {
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

func WithVerbose() ClientOption {
	return func(o *clientOptions) error {
		o.verbose = true
		return nil
	}
}

// WithAutoSettle enables automatic settlement scheduling. When enabled, the SDK
// will call Settle() automatically 2 × SessionDuration before the earliest
// spendable VTXO expiry. Off by default; explicit opt-in required.
//
// The feature is a no-op when delegate addresses are in use (a warning is
// logged when the loop starts).
func WithAutoSettle() ClientOption {
	return func(o *clientOptions) error {
		o.autoSettle = true
		return nil
	}
}

func applyClientOptions(opts ...ClientOption) (*clientOptions, error) {
	o := newDefaultClientOptions()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("client option cannot be nil")
		}
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

type clientOptions struct {
	refreshDbInterval time.Duration
	verbose           bool
	// autoSettle enables the auto-settlement scheduler. Off by default.
	autoSettle bool
	// delegateMode is a placeholder guard for the future delegate-address feature.
	// Always false today; when true, the auto-settle loop becomes a no-op.
	// No exported WithDelegateMode option exists yet — the field is structural so
	// the guard wiring is in place when delegate support lands.
	delegateMode bool
}

// newDefaultClientOptions returns a zero-value clientOptions.
// A zero refreshDbInterval disables periodic DB refresh (periodicRefreshDb exits early).
func newDefaultClientOptions() *clientOptions {
	return &clientOptions{}
}
