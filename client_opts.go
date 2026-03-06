package arksdk

import (
	"github.com/arkade-os/go-sdk/types"
)

type ClientOption func(*arkClient)

func WithVerbose() ClientOption {
	return func(c *arkClient) {
		c.verbose = true
	}
}

func WithStore(store types.Store) ClientOption {
	return func(c *arkClient) {
		c.store = store
	}
}
