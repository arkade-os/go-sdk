package arksdk_test

import (
	"testing"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

func TestBatchSessionOptions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name string
			opts []arksdk.BatchSessionOption
		}{
			{
				name: "no options",
			},
			{
				name: "WithRetries min",
				opts: []arksdk.BatchSessionOption{arksdk.WithRetries(1)},
			},
			{
				name: "WithRetries max",
				opts: []arksdk.BatchSessionOption{arksdk.WithRetries(5)},
			},
			{
				name: "WithRetries mid",
				opts: []arksdk.BatchSessionOption{arksdk.WithRetries(3)},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyBatchSessionOptions(f.opts...)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			opts            []arksdk.BatchSessionOption
			wantErrContains string
		}{
			{
				name:            "nil option",
				opts:            []arksdk.BatchSessionOption{nil},
				wantErrContains: "batch session option cannot be nil",
			},
			{
				name:            "WithRetries zero",
				opts:            []arksdk.BatchSessionOption{arksdk.WithRetries(0)},
				wantErrContains: "retry num must be in range",
			},
			{
				name:            "WithRetries negative",
				opts:            []arksdk.BatchSessionOption{arksdk.WithRetries(-1)},
				wantErrContains: "retry num must be in range",
			},
			{
				name:            "WithRetries above max",
				opts:            []arksdk.BatchSessionOption{arksdk.WithRetries(6)},
				wantErrContains: "retry num must be in range",
			},
			{
				name: "WithRetries twice",
				opts: []arksdk.BatchSessionOption{
					arksdk.WithRetries(1),
					arksdk.WithRetries(2),
				},
				wantErrContains: "retry num already set",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyBatchSessionOptions(f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}
