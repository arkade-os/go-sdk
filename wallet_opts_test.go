package arksdk_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var nilHandler *mockHandler

func TestWalletOptions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name string
			opts []arksdk.WalletOption
		}{
			{
				name: "no options",
			},
			{
				name: "WithRefreshDbInterval min",
				opts: []arksdk.WalletOption{arksdk.WithRefreshDbInterval(30 * time.Second)},
			},
			{
				name: "WithRefreshDbInterval typical",
				opts: []arksdk.WalletOption{arksdk.WithRefreshDbInterval(60 * time.Second)},
			},
			{
				name: "WithVerbose",
				opts: []arksdk.WalletOption{arksdk.WithVerbose()},
			},
			{
				name: "WithGapLimit",
				opts: []arksdk.WalletOption{arksdk.WithGapLimit(10)},
			},
			{
				name: "WithIdentity",
				opts: []arksdk.WalletOption{arksdk.WithIdentity(&mockIdentity{})},
			},
			{
				name: "WithScheduler",
				opts: []arksdk.WalletOption{arksdk.WithScheduler(&testScheduler{})},
			},
			{
				name: "WitContractHandler (one)",
				opts: []arksdk.WalletOption{
					arksdk.WithContractHandler("vhtlc", &mockHandler{typ: "vhtlc"}),
				},
			},
			{
				name: "WitContractHandler (many)",
				opts: []arksdk.WalletOption{
					arksdk.WithContractHandler("vhtlc", &mockHandler{typ: "vhtlc"}),
					arksdk.WithContractHandler("delegate", &mockHandler{typ: "delegate"}),
				},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyWalletOptions(f.opts...)
				require.NoError(t, err)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			opts            []arksdk.WalletOption
			wantErrContains string
		}{
			{
				name:            "nil option",
				opts:            []arksdk.WalletOption{nil},
				wantErrContains: "wallet option cannot be nil",
			},
			{
				name:            "WithRefreshDbInterval too small",
				opts:            []arksdk.WalletOption{arksdk.WithRefreshDbInterval(0)},
				wantErrContains: "refresh db interval must be at least 30s",
			},
			{
				name: "WithRefreshDbInterval twice",
				opts: []arksdk.WalletOption{
					arksdk.WithRefreshDbInterval(40 * time.Second),
					arksdk.WithRefreshDbInterval(40 * time.Second),
				},
				wantErrContains: "refresh db interval already set",
			},
			{
				name:            "WithGapLimit zero",
				opts:            []arksdk.WalletOption{arksdk.WithGapLimit(0)},
				wantErrContains: "gap limit must be greater than zero",
			},
			{
				name: "WithGapLimit twice",
				opts: []arksdk.WalletOption{
					arksdk.WithGapLimit(10),
					arksdk.WithGapLimit(12),
				},
				wantErrContains: "gap limit already set",
			},
			{
				name:            "WitIdentity nil",
				opts:            []arksdk.WalletOption{arksdk.WithIdentity(nil)},
				wantErrContains: "identity cannot be nil",
			},
			{
				name: "WithIdentity twice",
				opts: []arksdk.WalletOption{
					arksdk.WithIdentity(&mockIdentity{}),
					arksdk.WithIdentity(&mockIdentity{}),
				},
				wantErrContains: "identity already set",
			},
			{
				name: "WithScheduler nil",
				opts: []arksdk.WalletOption{
					arksdk.WithScheduler(nil),
				},
				wantErrContains: "scheduler cannot be nil",
			},
			{
				name: "WithScheduler twice",
				opts: []arksdk.WalletOption{
					arksdk.WithScheduler(&testScheduler{}),
					arksdk.WithScheduler(&testScheduler{}),
				},
				wantErrContains: "scheduler already set",
			},
			{
				name: "WithScheduler then WithoutAutoSettle",
				opts: []arksdk.WalletOption{
					arksdk.WithScheduler(&testScheduler{}),
					arksdk.WithoutAutoSettle(),
				},
				wantErrContains: "cannot disable auto-settle when scheduler is set",
			},
			{
				name: "WithoutAutoSettle then WithScheduler",
				opts: []arksdk.WalletOption{
					arksdk.WithoutAutoSettle(),
					arksdk.WithScheduler(&testScheduler{}),
				},
				wantErrContains: "cannot set scheduler when auto-settle is disabled",
			},
			{
				name: "WithContractHandler empty type",
				opts: []arksdk.WalletOption{
					arksdk.WithContractHandler("", &mockHandler{typ: "x"}),
				},
				wantErrContains: "missing contract type",
			},
			{
				name: "WithContractHandler nil handler",
				opts: []arksdk.WalletOption{
					arksdk.WithContractHandler("test", nil),
				},
				wantErrContains: "nil handler",
			},
			{
				name: "WithContractHandler typed-nil handler",
				opts: []arksdk.WalletOption{
					arksdk.WithContractHandler("vhtlc", nilHandler),
				},
				wantErrContains: "nil concrete handler",
			},
			{
				name: "WithContractHandler duplicate handler",
				opts: []arksdk.WalletOption{
					arksdk.WithContractHandler("vhtlc", &mockHandler{typ: "vhtlc"}),
					arksdk.WithContractHandler("vhtlc", &mockHandler{typ: "vhtlc"}),
				},
				wantErrContains: "duplicate handler",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := arksdk.ApplyWalletOptions(f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

// mockHandler is a minimal handlers.Handler used only by the
// WithContractHandler tests. It implements the full interface with
// zero-value stubs since these tests never invoke the methods.
type mockHandler struct{ typ types.ContractType }

func (h *mockHandler) NewContract(
	_ context.Context, k identity.KeyRef,
) (*types.Contract, error) {
	s := sha256.Sum256([]byte(string(h.typ) + ":" + k.Id))
	return &types.Contract{
		Type:   h.typ,
		Script: hex.EncodeToString(s[:]),
		State:  types.ContractStateActive,
	}, nil
}
func (h *mockHandler) GetKeyRefs(types.Contract) (map[string]string, error) {
	return nil, nil
}
func (h *mockHandler) GetKeyRef(types.Contract) (*identity.KeyRef, error) {
	return nil, errors.New("not implemented")
}
func (h *mockHandler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (h *mockHandler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}
func (h *mockHandler) GetTapscripts(types.Contract) ([]string, error) {
	return nil, nil
}
