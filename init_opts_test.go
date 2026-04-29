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
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyInitOptions(f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}
