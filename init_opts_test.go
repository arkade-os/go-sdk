package arksdk_test

import (
	"testing"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

func TestInitOptions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name string
			opts []arksdk.InitOption
		}{
			{
				name: "no options",
			},
			{
				name: "WithExplorerURL",
				opts: []arksdk.InitOption{arksdk.WithExplorerURL("https://example.com")},
			},
			{
				name: "WithElectrumExplorer tcp",
				opts: []arksdk.InitOption{arksdk.WithElectrumExplorer("tcp://127.0.0.1:50000")},
			},
			{
				name: "WithElectrumExplorer ssl",
				opts: []arksdk.InitOption{
					arksdk.WithElectrumExplorer("ssl://electrum.example.com:50002"),
				},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyInitOptions(f.opts...)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			opts            []arksdk.InitOption
			wantErrContains string
		}{
			{
				name:            "nil option",
				opts:            []arksdk.InitOption{nil},
				wantErrContains: "init option cannot be nil",
			},
			{
				name:            "WithExplorerURL empty string",
				opts:            []arksdk.InitOption{arksdk.WithExplorerURL("")},
				wantErrContains: "explorer url cannot be empty",
			},
			{
				name: "WithExplorer twice",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerURL("https://example.com"),
					arksdk.WithExplorerURL("https://example.com"),
				},
				wantErrContains: "explorer url already set",
			},
			{
				name:            "WithElectrumExplorer empty string",
				opts:            []arksdk.InitOption{arksdk.WithElectrumExplorer("")},
				wantErrContains: "electrum server url cannot be empty",
			},
			{
				name: "WithElectrumExplorer bad scheme",
				opts: []arksdk.InitOption{
					arksdk.WithElectrumExplorer("http://example.com"),
				},
				wantErrContains: "must start with tcp:// or ssl://",
			},
			{
				name: "WithElectrumExplorer conflicts with WithExplorerURL",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerURL("https://example.com"),
					arksdk.WithElectrumExplorer("tcp://127.0.0.1:50000"),
				},
				wantErrContains: "explorer url already set",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyInitOptions(f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}
