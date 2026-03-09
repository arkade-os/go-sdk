package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

type InitOption func(options *initOptions) error

// ApplyInitOptions applies the given InitOption functions to a new default
// initOptions struct and returns the first error encountered, if any.
// Exposed for use in external (arksdk_test) test packages.
func ApplyInitOptions(opts ...InitOption) error {
	o := newDefaultInitOptions()
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return err
		}
	}
	return nil
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

func WithExplorer(explorer explorer.Explorer) InitOption {
	return func(o *initOptions) error {
		if o.explorer != nil {
			return fmt.Errorf("explorer already set")
		}
		if explorer == nil {
			return fmt.Errorf("explorer cannot be nil")
		}
		o.explorer = explorer
		return nil
	}
}

type initOptions struct {
	wallet   wallet.WalletService
	explorer explorer.Explorer
}

func newDefaultInitOptions() *initOptions {
	return &initOptions{}
}
