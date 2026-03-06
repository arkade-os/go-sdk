package arksdk_test

import (
	"testing"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

func TestNewArkClient(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name    string
			datadir string
			verbose bool
		}{
			{
				name:    "empty datadir uses in-memory stores",
				datadir: "",
			},
			{
				name:    "non-empty datadir uses file and SQL stores",
				datadir: t.TempDir(),
			},
			{
				name:    "verbose flag is accepted",
				datadir: "",
				verbose: true,
			},
			{
				// whitespace is trimmed, so this behaves identically to empty datadir
				name:    "whitespace-only datadir uses in-memory stores",
				datadir: "   ",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				client, err := arksdk.NewArkClient(f.datadir, f.verbose)
				require.NoError(t, err)
				require.NotNil(t, client)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			datadir         string
			wantErrContains string
		}{
			{
				// /dev/null is a character device, not a directory, so
				// creating a subdirectory inside it fails.
				name:            "non-creatable datadir",
				datadir:         "/dev/null/subdir",
				wantErrContains: "failed to open store",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				client, err := arksdk.NewArkClient(f.datadir, false)
				require.Error(t, err)
				require.ErrorContains(t, err, f.wantErrContains)
				require.Nil(t, client)
			})
		}
	})
}

func TestLoadNewArkClient(t *testing.T) {
	// Valid cases require a client that has already been initialized via Init(),
	// which needs a live Ark server. Those are covered by e2e tests.

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			datadir         string
			wantErrContains string
		}{
			{
				name:            "empty datadir with no existing config",
				datadir:         "",
				wantErrContains: "not initialized",
			},
			{
				// whitespace is trimmed to "", so this behaves identically to empty datadir
				name:            "whitespace-only datadir with no existing config",
				datadir:         "   ",
				wantErrContains: "not initialized",
			},
			{
				name:            "fresh datadir with no existing config",
				datadir:         t.TempDir(),
				wantErrContains: "not initialized",
			},
			{
				name:            "non-creatable datadir",
				datadir:         "/dev/null/subdir",
				wantErrContains: "failed to open store",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				client, err := arksdk.LoadNewArkClient(f.datadir, false)
				require.Error(t, err)
				if f.wantErrContains != "" {
					require.ErrorContains(t, err, f.wantErrContains)
				}
				require.Nil(t, client)
			})
		}
	})
}
