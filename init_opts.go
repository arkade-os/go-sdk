package arksdk

import (
	"fmt"
	"time"

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

func WithWalletType(walletType string) InitOption {
	return func(o *initOptions) error {
		if o.wallet != nil {
			return fmt.Errorf("wallet already set")
		}
		if o.walletType != "" {
			return fmt.Errorf("wallet type already set")
		}
		if walletType == "" {
			return fmt.Errorf("wallet type cannot be empty")
		}
		o.walletType = walletType
		return nil
	}
}

func WithWallet(wallet wallet.WalletService) InitOption {
	return func(o *initOptions) error {
		if o.walletType != "" {
			return fmt.Errorf("wallet type already set")
		}
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

func WithExplorerUrl(explorerUrl string) InitOption {
	return func(o *initOptions) error {
		if o.explorer != nil {
			return fmt.Errorf("explorer already set")
		}
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

func WithExplorer(explorer explorer.Explorer) InitOption {
	return func(o *initOptions) error {
		if o.explorerUrl != "" {
			return fmt.Errorf("explorer url already set")
		}
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

func WithExplorerPollInterval(interval time.Duration) InitOption {
	return func(o *initOptions) error {
		if o.explorer != nil {
			return fmt.Errorf("explorer already set")
		}
		if o.explorerPollInterval != 0 {
			return fmt.Errorf("explorer poll interval already set")
		}
		if interval <= 0 {
			return fmt.Errorf("explorer poll interval must be greater than 0")
		}
		o.explorerPollInterval = interval
		return nil
	}
}

type initOptions struct {
	walletType           string
	wallet               wallet.WalletService
	explorerUrl          string
	explorerPollInterval time.Duration
	explorer             explorer.Explorer
}

func newDefaultInitOptions() *initOptions {
	return &initOptions{}
}
