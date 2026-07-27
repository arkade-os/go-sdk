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
				name: "WithLnSwapTimeout",
				opts: []swap.Option{swap.WithLnSwapTimeout(30 * time.Second)},
			},
			{
				name: "WithChainSwapTimeout",
				opts: []swap.Option{swap.WithChainSwapTimeout(time.Hour)},
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
				name: "all options",
				opts: []swap.Option{
					swap.WithLnSwapTimeout(30 * time.Second),
					swap.WithChainSwapTimeout(time.Hour),
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
				name:            "WithLnSwapTimeout zero",
				opts:            []swap.Option{swap.WithLnSwapTimeout(0)},
				wantErrContains: "ln swap timeout must not be empty",
			},
			{
				name:            "WithLnSwapTimeout negative",
				opts:            []swap.Option{swap.WithLnSwapTimeout(-time.Second)},
				wantErrContains: "ln swap timeout must not be empty",
			},
			{
				name: "WithLnSwapTimeout twice",
				opts: []swap.Option{
					swap.WithLnSwapTimeout(30 * time.Second),
					swap.WithLnSwapTimeout(30 * time.Second),
				},
				wantErrContains: "ln swap timeout already set",
			},
			{
				name:            "WithChainSwapTimeout zero",
				opts:            []swap.Option{swap.WithChainSwapTimeout(0)},
				wantErrContains: "chain swap timeout must not be empty",
			},
			{
				name:            "WithChainSwapTimeout negative",
				opts:            []swap.Option{swap.WithChainSwapTimeout(-time.Second)},
				wantErrContains: "chain swap timeout must not be empty",
			},
			{
				name: "WithChainSwapTimeout twice",
				opts: []swap.Option{
					swap.WithChainSwapTimeout(time.Hour),
					swap.WithChainSwapTimeout(time.Hour),
				},
				wantErrContains: "chain swap timeout already set",
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
