package arksdk_test

import (
	"testing"
	"time"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

func TestClientOptions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name string
			opts []arksdk.ClientOption
		}{
			{
				name: "no options",
			},
			{
				name: "WithRefreshDbInterval min",
				opts: []arksdk.ClientOption{arksdk.WithRefreshDbInterval(30 * time.Second)},
			},
			{
				name: "WithRefreshDbInterval typical",
				opts: []arksdk.ClientOption{arksdk.WithRefreshDbInterval(60 * time.Second)},
			},
			{
				name: "WithVerbose",
				opts: []arksdk.ClientOption{arksdk.WithVerbose()},
			},
			{
				name: "WithGapLimit",
				opts: []arksdk.ClientOption{arksdk.WithGapLimit(10)},
			},
			{
				name: "WithWallet",
				opts: []arksdk.ClientOption{arksdk.WithWallet(&mockWallet{})},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyClientOptions(f.opts...)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			opts            []arksdk.ClientOption
			wantErrContains string
		}{
			{
				name:            "nil option",
				opts:            []arksdk.ClientOption{nil},
				wantErrContains: "client option cannot be nil",
			},
			{
				name:            "WithRefreshDbInterval too small",
				opts:            []arksdk.ClientOption{arksdk.WithRefreshDbInterval(0)},
				wantErrContains: "refresh db interval must be at least 30s",
			},
			{
				name: "WithRefreshDbInterval twice",
				opts: []arksdk.ClientOption{
					arksdk.WithRefreshDbInterval(40 * time.Second),
					arksdk.WithRefreshDbInterval(40 * time.Second),
				},
				wantErrContains: "refresh db interval already set",
			},
			{
				name:            "WithGapLimit zero",
				opts:            []arksdk.ClientOption{arksdk.WithGapLimit(0)},
				wantErrContains: "gap limit must be greater than zero",
			},
			{
				name: "WithGapLimit twice",
				opts: []arksdk.ClientOption{
					arksdk.WithGapLimit(10),
					arksdk.WithGapLimit(12),
				},
				wantErrContains: "gap limit already set",
			},
			{
				name:            "WithWallet nil",
				opts:            []arksdk.ClientOption{arksdk.WithWallet(nil)},
				wantErrContains: "wallet cannot be nil",
			},
			{
				name: "WithWallet twice",
				opts: []arksdk.ClientOption{
					arksdk.WithWallet(&mockWallet{}),
					arksdk.WithWallet(&mockWallet{}),
				},
				wantErrContains: "wallet already set",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyClientOptions(f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}
