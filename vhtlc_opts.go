package arksdk

import (
	"fmt"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

// VHTLCOption can be used to pass optional params to the VHTLC APIs.
type VHTLCOption func(*vhtlcOpts) error

// WithOutpoint makes the VHTLC APIs spend the given vtxo instead of the oldest one funding the
// contract.
func WithOutpoint(outpoint clienttypes.Outpoint) VHTLCOption {
	return func(o *vhtlcOpts) error {
		emptyOutpoint := clienttypes.Outpoint{}
		if outpoint == emptyOutpoint {
			return fmt.Errorf("outpoint must not be empty")
		}
		if o.outpoint != nil {
			return fmt.Errorf("outpoint already set")
		}
		o.outpoint = &outpoint
		return nil
	}
}

type vhtlcOpts struct {
	outpoint *clienttypes.Outpoint
}

func defaultVhtlcOpts() *vhtlcOpts {
	return &vhtlcOpts{}
}
