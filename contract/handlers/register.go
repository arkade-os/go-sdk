package handlers

import "github.com/arkade-os/go-sdk/contract"

func init() {
	if err := contract.DefaultRegistry.Register(&DefaultHandler{}); err != nil {
		panic(err)
	}
}
