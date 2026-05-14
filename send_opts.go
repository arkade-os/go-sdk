package arksdk

import (
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	client "github.com/arkade-os/arkd/pkg/client-lib"
)

// SendOffChainOption configures a SendOffChain call.
type SendOffChainOption = client.SendOption

// WithExtension appends extra extension.Packet values to the OP_RETURN
// extension blob written by SendOffChain. Re-exports client.WithExtraPacket
// so callers don't need to import client-lib directly.
func WithExtension(packets ...extension.Packet) SendOffChainOption {
	return client.WithExtraPacket(packets...)
}

// WithOutputTaprootTree sets the BIP-371 TaprootTapTree on every output
// whose pkScript matches a key in the map. Re-exports
// client.WithOutputTaprootTree.
func WithOutputTaprootTree(byPkScript map[string][]byte) SendOffChainOption {
	return client.WithOutputTaprootTree(byPkScript)
}
