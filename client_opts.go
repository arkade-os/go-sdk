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
}

// newDefaultClientOptions returns a zero-value clientOptions.
// A zero refreshDbInterval disables periodic DB refresh (periodicRefreshDb exits early).
func newDefaultClientOptions() *clientOptions {
	return &clientOptions{}
}
