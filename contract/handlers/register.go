package handlers

import "github.com/arkade-os/go-sdk/contract"

func init() {
	for _, h := range []contract.Handler{
		&DefaultHandler{},
		&DelegateHandler{},
		&VHTLCHandler{},
	} {
		if err := contract.DefaultRegistry.Register(h); err != nil {
			panic(err)
		}
	}
}
