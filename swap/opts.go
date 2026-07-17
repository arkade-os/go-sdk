package swap

import (
	"fmt"
	"time"
)

// Option can be used to pass optional params to the SwapManager.
type Option func(*opts) error

// ApplyOptions applies options to a new default opts and returns the first error encountered,
// if any. Exposed for use in external (swap_test) test packages.
func ApplyOptions(options ...Option) error {
	_, err := applyOptions(options...)
	return err
}

const (
	defaultTimeout      = 15 * time.Second
	defaultPollInterval = 5 * time.Second
)

// WithOutpoint makes the VHTLC APIs spend the given vtxo instead of the oldest one funding the
// contract.
func WithTimeout(timeout time.Duration) Option {
	return func(o *opts) error {
		if timeout <= 0 {
			return fmt.Errorf("timeout must not be empty")
		}
		if o.timeoutSet {
			return fmt.Errorf("timeout already set")
		}
		o.timeoutSet = true
		o.timeout = timeout
		return nil
	}
}

// WithPollInterval can be used to customize the SwapManager polling interval
// to fetch the chain tip.
func WithPollInterval(interval time.Duration) Option {
	return func(o *opts) error {
		if interval <= 0 {
			return fmt.Errorf("polling interval must not be empty")
		}
		if o.pollIntervalSet {
			return fmt.Errorf("polling interval already set")
		}
		o.pollIntervalSet = true
		o.pollInterval = interval
		return nil
	}
}

// WithVerbose enables verbose logging.
func WithVerbose() Option {
	return func(o *opts) error {
		if o.verbose {
			return fmt.Errorf("verbose already set")
		}
		o.verbose = true
		return nil
	}
}

type opts struct {
	timeout         time.Duration
	timeoutSet      bool
	pollInterval    time.Duration
	pollIntervalSet bool
	verbose         bool
}

func defaulOpts() *opts {
	return &opts{timeout: defaultTimeout, pollInterval: defaultPollInterval}
}

func applyOptions(options ...Option) (*opts, error) {
	o := defaulOpts()
	for _, opt := range options {
		if opt == nil {
			return nil, fmt.Errorf("swap option cannot be nil")
		}
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}
