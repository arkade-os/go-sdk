package arksdk

import (
	"fmt"
	"strings"
)

type InitOption func(options *initOptions) error

// ApplyInitOptions applies the given InitOption functions to a new default
// initOptions struct and returns the first error encountered, if any.
// Exposed for use in external (arksdk_test) test packages.
func ApplyInitOptions(opts ...InitOption) error {
	_, err := applyInitOptions(opts...)
	return err
}

// WithExplorerURL overrides the default mempool.space URL used for on-chain queries.
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

// WithElectrumExplorer configures the SDK to use an ElectrumX server for
// on-chain queries instead of the default mempool.space REST/WebSocket API.
// serverURL must begin with "tcp://" or "ssl://".
func WithElectrumExplorer(serverURL string) InitOption {
	return func(o *initOptions) error {
		if o.explorerUrl != "" {
			return fmt.Errorf("explorer url already set")
		}
		if serverURL == "" {
			return fmt.Errorf("electrum server url cannot be empty")
		}
		if !strings.HasPrefix(serverURL, "tcp://") && !strings.HasPrefix(serverURL, "ssl://") {
			return fmt.Errorf("electrum server url must start with tcp:// or ssl://")
		}
		o.explorerUrl = serverURL
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
	explorerUrl string
}

func newDefaultInitOptions() *initOptions {
	return &initOptions{}
}
