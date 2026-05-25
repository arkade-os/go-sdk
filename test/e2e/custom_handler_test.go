package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestCustomContractHandlerRegistered(t *testing.T) {
	// Build the wallet manually rather than via setupClient so we can
	// inspect the registry immediately after Unlock, without waiting for
	// the background ScanContracts to complete. The custom handler here
	// produces non-standard scripts that arkd's indexer would reject —
	// that's fine because the registry assertion runs before sync drains
	// any error onto syncCh.
	arkClient, err := sdk.NewWallet(t.TempDir(), sdk.WithContractHandler(
		types.ContractType("custom"), &customTestHandler{typ: "custom"},
	))
	require.NoError(t, err)
	t.Cleanup(arkClient.Stop)

	require.NoError(t, arkClient.Init(t.Context(), serverUrl, "", password))
	require.NoError(t, arkClient.Unlock(t.Context(), password))

	mgr := arkClient.ContractManager()
	require.NotNil(t, mgr)

	got := mgr.Registry().SupportedTypes()
	require.Contains(t, got, types.ContractType("custom"))
	require.Contains(t, got, types.ContractTypeDefault)
	require.Contains(t, got, types.ContractTypeBoarding)

	h, err := mgr.Registry().GetHandler(types.ContractType("custom"))
	require.NoError(t, err)
	require.NotNil(t, h)

	// Drain IsSynced so the bg goroutines spawned by Unlock reach a stable
	// state before t.Cleanup invokes Stop. We don't assert on the result —
	// the custom handler produces non-standard scripts that the live arkd
	// indexer rejects during ScanContracts, so a sync error is expected.
	// Bound the wait so a stuck sync fails the test instead of hanging CI.
	syncCtx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	select {
	case <-arkClient.IsSynced(syncCtx):
	case <-syncCtx.Done():
		require.FailNowf(t, "sync drain timeout", "IsSynced did not return: %v", syncCtx.Err())
	}
}

// customTestHandler is a minimal handlers.Handler that produces a
// deterministic contract from the key ref. Sufficient for verifying
// registration without exercising the contract lifecycle.
type customTestHandler struct{ typ types.ContractType }

func (h *customTestHandler) NewContract(
	_ context.Context, k identity.KeyRef,
) (*types.Contract, error) {
	s := sha256.Sum256([]byte(string(h.typ) + ":" + k.Id))
	return &types.Contract{
		Type:   h.typ,
		Script: hex.EncodeToString(s[:]),
		State:  types.ContractStateActive,
		Params: map[string]string{"ownerKeyId": k.Id},
	}, nil
}
func (h *customTestHandler) GetKeyRefs(types.Contract) (map[string]string, error) {
	return nil, nil
}
func (h *customTestHandler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	id, ok := c.Params["ownerKeyId"]
	if !ok {
		return nil, errors.New("missing ownerKeyId")
	}
	return &identity.KeyRef{Id: id}, nil
}
func (h *customTestHandler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (h *customTestHandler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}
func (h *customTestHandler) GetTapscripts(types.Contract) ([]string, error) {
	return nil, nil
}
