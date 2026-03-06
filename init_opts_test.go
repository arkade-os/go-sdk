package arksdk_test

import (
	"testing"
	"time"

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
				name: "WithWalletType",
				opts: []arksdk.InitOption{arksdk.WithWalletType("singlekey")},
			},
			{
				name: "WithWallet",
				opts: []arksdk.InitOption{arksdk.WithWallet(&mockWallet{})},
			},
			{
				name: "WithExplorerUrl",
				opts: []arksdk.InitOption{arksdk.WithExplorerUrl("http://explorer.example.com")},
			},
			{
				name: "WithExplorer",
				opts: []arksdk.InitOption{arksdk.WithExplorer(&mockExplorer{})},
			},
			{
				name: "WithExplorerPollInterval",
				opts: []arksdk.InitOption{arksdk.WithExplorerPollInterval(5 * time.Second)},
			},
			{
				name: "WithWalletType with explorer",
				opts: []arksdk.InitOption{
					arksdk.WithWalletType("singlekey"),
					arksdk.WithExplorer(&mockExplorer{}),
				},
			},
			{
				name: "WithWalletType with explorer url and poll interval",
				opts: []arksdk.InitOption{
					arksdk.WithWalletType("singlekey"),
					arksdk.WithExplorerUrl("http://explorer.example.com"),
					arksdk.WithExplorerPollInterval(5 * time.Second),
				},
			},
			{
				name: "WithWallet with explorer",
				opts: []arksdk.InitOption{
					arksdk.WithWallet(&mockWallet{}),
					arksdk.WithExplorer(&mockExplorer{}),
				},
			},
			{
				name: "WithWallet with explorer url",
				opts: []arksdk.InitOption{
					arksdk.WithWallet(&mockWallet{}),
					arksdk.WithExplorerUrl("http://explorer.example.com"),
				},
			},
			{
				name: "WithWallet with explorer url and poll interval",
				opts: []arksdk.InitOption{
					arksdk.WithWallet(&mockWallet{}),
					arksdk.WithExplorerUrl("http://explorer.example.com"),
					arksdk.WithExplorerPollInterval(5 * time.Second),
				},
			},
			{
				name: "WithExplorerUrl with poll interval",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerUrl("http://explorer.example.com"),
					arksdk.WithExplorerPollInterval(5 * time.Second),
				},
			},
			{
				// poll interval is silently ignored when a direct Explorer is provided
				name: "poll interval ignored when explorer is set directly",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerPollInterval(5 * time.Second),
					arksdk.WithExplorer(&mockExplorer{}),
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
				name:            "WithWalletType empty string",
				opts:            []arksdk.InitOption{arksdk.WithWalletType("")},
				wantErrContains: "wallet type cannot be empty",
			},
			{
				name: "WithWalletType twice",
				opts: []arksdk.InitOption{
					arksdk.WithWalletType("singlekey"),
					arksdk.WithWalletType("singlekey"),
				},
				wantErrContains: "wallet type already set",
			},
			{
				name:            "WithWallet nil",
				opts:            []arksdk.InitOption{arksdk.WithWallet(nil)},
				wantErrContains: "wallet cannot be nil",
			},
			{
				name: "WithWallet twice",
				opts: []arksdk.InitOption{
					arksdk.WithWallet(&mockWallet{}),
					arksdk.WithWallet(&mockWallet{}),
				},
				wantErrContains: "wallet already set",
			},
			{
				name: "WithWalletType then WithWallet",
				opts: []arksdk.InitOption{
					arksdk.WithWalletType("singlekey"),
					arksdk.WithWallet(&mockWallet{}),
				},
				wantErrContains: "wallet type already set",
			},
			{
				name: "WithWallet then WithWalletType",
				opts: []arksdk.InitOption{
					arksdk.WithWallet(&mockWallet{}),
					arksdk.WithWalletType("singlekey"),
				},
				wantErrContains: "wallet already set",
			},
			{
				name:            "WithExplorerUrl empty string",
				opts:            []arksdk.InitOption{arksdk.WithExplorerUrl("")},
				wantErrContains: "explorer url cannot be empty",
			},
			{
				name: "WithExplorerUrl twice",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerUrl("http://a.example.com"),
					arksdk.WithExplorerUrl("http://b.example.com"),
				},
				wantErrContains: "explorer url already set",
			},
			{
				name:            "WithExplorer nil",
				opts:            []arksdk.InitOption{arksdk.WithExplorer(nil)},
				wantErrContains: "explorer cannot be nil",
			},
			{
				name: "WithExplorer twice",
				opts: []arksdk.InitOption{
					arksdk.WithExplorer(&mockExplorer{}),
					arksdk.WithExplorer(&mockExplorer{}),
				},
				wantErrContains: "explorer already set",
			},
			{
				name: "WithExplorerUrl then WithExplorer",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerUrl("http://explorer.example.com"),
					arksdk.WithExplorer(&mockExplorer{}),
				},
				wantErrContains: "explorer url already set",
			},
			{
				name: "WithExplorer then WithExplorerUrl",
				opts: []arksdk.InitOption{
					arksdk.WithExplorer(&mockExplorer{}),
					arksdk.WithExplorerUrl("http://explorer.example.com"),
				},
				wantErrContains: "explorer already set",
			},
			{
				name: "WithExplorer then WithExplorerPollInterval",
				opts: []arksdk.InitOption{
					arksdk.WithExplorer(&mockExplorer{}),
					arksdk.WithExplorerPollInterval(5 * time.Second),
				},
				wantErrContains: "explorer already set",
			},
			{
				name: "WithExplorerPollInterval twice",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerPollInterval(5 * time.Second),
					arksdk.WithExplorerPollInterval(10 * time.Second),
				},
				wantErrContains: "explorer poll interval already set",
			},
			{
				name:            "WithExplorerPollInterval zero",
				opts:            []arksdk.InitOption{arksdk.WithExplorerPollInterval(0)},
				wantErrContains: "must be greater than 0",
			},
			{
				name: "WithExplorerPollInterval negative",
				opts: []arksdk.InitOption{
					arksdk.WithExplorerPollInterval(-1 * time.Second),
				},
				wantErrContains: "must be greater than 0",
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
