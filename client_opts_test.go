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
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyClientOptions(f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}
