package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

type InitOption func(options *initOptions) error

// ApplyInitOptions applies the given InitOption functions to a new default
// initOptions struct and returns the first error encountered, if any.
// Exposed for use in external (arksdk_test) test packages.
func ApplyInitOptions(opts ...InitOption) error {
	_, err := applyInitOptions(opts...)
	return err
}

func WithWallet(wallet wallet.WalletService) InitOption {
	return func(o *initOptions) error {
		if o.wallet != nil {
			return fmt.Errorf("wallet already set")
		}
		if wallet == nil {
			return fmt.Errorf("wallet cannot be nil")
		}
		o.wallet = wallet
		return nil
	}
}

func WithExplorerURL(explorerUrl string) InitOption {
	return func(o *initOptions) error {
		if o.explorerUrl != "" {
			return fmt.Errorf("explorer url already set")
		}
		if explorerUrl == "" {
			return fmt.Errorf("explorer url cannot be empty")
		}
		o.explorerUrl = explorerUrl
		return nil
	}
}

func applyInitOptions(opts ...InitOption) (*initOptions, error) {
	o := newDefaultInitOptions()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("init option cannot be nil")
		}
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

type initOptions struct {
	wallet      wallet.WalletService
	explorerUrl string
}

func newDefaultInitOptions() *initOptions {
	return &initOptions{}
}
