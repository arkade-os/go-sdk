package arksdk

import (
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	client "github.com/arkade-os/arkd/pkg/client-lib"
)

// SendOffChainOption configures a SendOffChain call.
type SendOffChainOption = client.SendOption

// WithExtraPacket appends extra extension.Packet values to the OP_RETURN
// extension blob written by SendOffChain. Re-exports client.WithExtraPacket
// so callers don't need to import client-lib directly.
func WithExtraPacket(packets ...extension.Packet) SendOffChainOption {
	return client.WithExtraPacket(packets...)
}
