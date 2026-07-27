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
	// LN payments settle in seconds once Boltz attempts them, a couple of minutes is a
	// generous deadline for the whole submarine flow.
	defaultLnSwapTimeout = 2 * time.Minute
	// Chain swaps involve onchain lockups: a BTC -> Arkade one waits for the caller to fund
	// the lockup address and for the funding to confirm, which can take a while.
	defaultChainSwapTimeout = 30 * time.Minute
	defaultPollInterval     = 5 * time.Second
)

// WithLnSwapTimeout allows to customize the deadline for the execution of LN (submarine)
// swaps. It's also the deadline Boltz is given to settle the invoice.
func WithLnSwapTimeout(timeout time.Duration) Option {
	return func(o *opts) error {
		if timeout <= 0 {
			return fmt.Errorf("ln swap timeout must not be empty")
		}
		if o.lnSwapTimeoutSet {
			return fmt.Errorf("ln swap timeout already set")
		}
		o.lnSwapTimeoutSet = true
		o.lnSwapTimeout = timeout
		return nil
	}
}

// WithChainSwapTimeout allows to customize the deadline for the execution of chain swaps,
// including the time given to the caller to fund the BTC lockup of a BTC -> Arkade one.
func WithChainSwapTimeout(timeout time.Duration) Option {
	return func(o *opts) error {
		if timeout <= 0 {
			return fmt.Errorf("chain swap timeout must not be empty")
		}
		if o.chainSwapTimeoutSet {
			return fmt.Errorf("chain swap timeout already set")
		}
		o.chainSwapTimeoutSet = true
		o.chainSwapTimeout = timeout
		return nil
	}
}

// WithPollInterval can be used to customize the SwapManager polling interval
// to periodically fetch the chain tip.
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
	lnSwapTimeout       time.Duration
	lnSwapTimeoutSet    bool
	chainSwapTimeout    time.Duration
	chainSwapTimeoutSet bool
	pollInterval        time.Duration
	pollIntervalSet     bool
	verbose             bool
}

func defaultOpts() *opts {
	return &opts{
		lnSwapTimeout:    defaultLnSwapTimeout,
		chainSwapTimeout: defaultChainSwapTimeout,
		pollInterval:     defaultPollInterval,
	}
}

func applyOptions(options ...Option) (*opts, error) {
	o := defaultOpts()
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
