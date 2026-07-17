package swap_test

import (
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/swap"
	"github.com/stretchr/testify/require"
)

func TestSwapManagerOptions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name string
			opts []swap.Option
		}{
			{
				name: "no options",
			},
			{
				name: "WithTimeout",
				opts: []swap.Option{swap.WithTimeout(30 * time.Second)},
			},
			{
				name: "WithPollInterval",
				opts: []swap.Option{swap.WithPollInterval(time.Second)},
			},
			{
				name: "WithVerbose",
				opts: []swap.Option{swap.WithVerbose()},
			},
			{
				name: "WithTimeout and WithPollInterval",
				opts: []swap.Option{
					swap.WithTimeout(30 * time.Second),
					swap.WithPollInterval(time.Second),
				},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := swap.ApplyOptions(f.opts...)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			opts            []swap.Option
			wantErrContains string
		}{
			{
				name:            "nil option",
				opts:            []swap.Option{nil},
				wantErrContains: "swap option cannot be nil",
			},
			{
				name:            "WithTimeout zero",
				opts:            []swap.Option{swap.WithTimeout(0)},
				wantErrContains: "timeout must not be empty",
			},
			{
				name:            "WithTimeout negative",
				opts:            []swap.Option{swap.WithTimeout(-time.Second)},
				wantErrContains: "timeout must not be empty",
			},
			{
				name: "WithTimeout twice",
				opts: []swap.Option{
					swap.WithTimeout(30 * time.Second),
					swap.WithTimeout(30 * time.Second),
				},
				wantErrContains: "timeout already set",
			},
			{
				name:            "WithPollInterval zero",
				opts:            []swap.Option{swap.WithPollInterval(0)},
				wantErrContains: "polling interval must not be empty",
			},
			{
				name:            "WithPollInterval negative",
				opts:            []swap.Option{swap.WithPollInterval(-time.Second)},
				wantErrContains: "polling interval must not be empty",
			},
			{
				name: "WithPollInterval twice",
				opts: []swap.Option{
					swap.WithPollInterval(time.Second),
					swap.WithPollInterval(time.Second),
				},
				wantErrContains: "polling interval already set",
			},
			{
				name: "WithVerbose twice",
				opts: []swap.Option{
					swap.WithVerbose(),
					swap.WithVerbose(),
				},
				wantErrContains: "verbose already set",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := swap.ApplyOptions(f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}
