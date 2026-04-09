package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
)

type SendOffChainOption func(options *sendOffChainOptions) error

// ApplySendOffChainOptions applies the given SendOffChainOption functions to a
// new default sendOffChainOptions struct and returns the first error
// encountered, if any. Exposed for use in external (arksdk_test) test packages.
func ApplySendOffChainOptions(opts ...SendOffChainOption) error {
	_, err := applySendOffChainOptions(opts...)
	return err
}

// WithExtension appends additional extension.Packet values to the OP_RETURN
// extension blob written by SendOffChain.
//
// 0x00 is reserved for the asset packet (auto-generated) and is rejected by
// the underlying client when the options are forwarded.
func WithExtension(packets ...extension.Packet) SendOffChainOption {
	return func(o *sendOffChainOptions) error {
		o.extraExtensionPackets = append(o.extraExtensionPackets, packets...)
		return nil
	}
}

func applySendOffChainOptions(opts ...SendOffChainOption) (*sendOffChainOptions, error) {
	o := newDefaultSendOffChainOptions()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("send off-chain option cannot be nil")
		}
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

type sendOffChainOptions struct {
	extraExtensionPackets []extension.Packet
}

func newDefaultSendOffChainOptions() *sendOffChainOptions {
	return &sendOffChainOptions{}
}
