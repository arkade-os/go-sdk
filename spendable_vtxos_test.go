package arksdk

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	sdktypes "github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// --- mock fixtures used only in this file ---

type fixVtxoStore struct {
	spendable []clientTypes.Vtxo
}

func (v *fixVtxoStore) GetSpendableVtxos(_ context.Context) ([]clientTypes.Vtxo, error) {
	return v.spendable, nil
}
func (v *fixVtxoStore) AddVtxos(_ context.Context, _ []clientTypes.Vtxo) (int, error) {
	return 0, nil
}

func (v *fixVtxoStore) SpendVtxos(
	_ context.Context,
	_ map[clientTypes.Outpoint]string,
	_ string,
) (int, error) {
	return 0, nil
}

func (v *fixVtxoStore) SettleVtxos(
	_ context.Context,
	_ map[clientTypes.Outpoint]string,
	_ string,
) (int, error) {
	return 0, nil
}
func (v *fixVtxoStore) SweepVtxos(_ context.Context, _ []clientTypes.Vtxo) (int, error) {
	return 0, nil
}
func (v *fixVtxoStore) UnrollVtxos(_ context.Context, _ []clientTypes.Vtxo) (int, error) {
	return 0, nil
}

func (v *fixVtxoStore) GetAllVtxos(
	_ context.Context,
) ([]clientTypes.Vtxo, []clientTypes.Vtxo, error) {
	return nil, nil, nil
}

func (v *fixVtxoStore) GetVtxos(
	_ context.Context,
	_ []clientTypes.Outpoint,
) ([]clientTypes.Vtxo, error) {
	return nil, nil
}
func (v *fixVtxoStore) Clean(_ context.Context) error { return nil }
func (v *fixVtxoStore) GetEventChannel() <-chan sdktypes.VtxoEvent {
	return make(chan sdktypes.VtxoEvent)
}
func (v *fixVtxoStore) Close() {}

type fixStore struct {
	vtxo sdktypes.VtxoStore
}

func (s *fixStore) VtxoStore() sdktypes.VtxoStore               { return s.vtxo }
func (s *fixStore) UtxoStore() sdktypes.UtxoStore               { return nil }
func (s *fixStore) TransactionStore() sdktypes.TransactionStore { return nil }
func (s *fixStore) AssetStore() sdktypes.AssetStore             { return nil }
func (s *fixStore) ContractStore() sdktypes.ContractStore       { return nil }
func (s *fixStore) Clean(_ context.Context)                     {}
func (s *fixStore) Close()                                      {}

// fixHandler serves tapscripts from c.Params["tapscripts"] (JSON array).
// All other methods are no-ops since getSpendableVtxos only calls GetTapscripts.
type fixHandler struct{}

func (h *fixHandler) NewContract(_ context.Context, _ wallet.KeyRef) (*sdktypes.Contract, error) {
	return nil, nil
}
func (h *fixHandler) GetKeyRefs(_ sdktypes.Contract) (map[string]string, error) { return nil, nil }
func (h *fixHandler) GetKeyRef(_ sdktypes.Contract) (*wallet.KeyRef, error)     { return nil, nil }
func (h *fixHandler) GetSignerKey(_ sdktypes.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (h *fixHandler) GetExitDelay(_ sdktypes.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}
func (h *fixHandler) GetTapscripts(c sdktypes.Contract) ([]string, error) {
	s, ok := c.Params["tapscripts"]
	if !ok {
		return nil, nil
	}
	var ts []string
	// nolint:errcheck
	json.Unmarshal([]byte(s), &ts)
	return ts, nil
}

var _ handlers.Handler = (*fixHandler)(nil)

type fixContractManager struct {
	contracts []sdktypes.Contract
}

func (m *fixContractManager) GetSupportedContractTypes(_ context.Context) []sdktypes.ContractType {
	return nil
}
func (m *fixContractManager) ScanContracts(_ context.Context, _ uint32) error { return nil }
func (m *fixContractManager) NewContract(
	_ context.Context, _ sdktypes.ContractType, _ ...contract.ContractOption,
) (*sdktypes.Contract, error) {
	return nil, nil
}
func (m *fixContractManager) GetContracts(
	_ context.Context,
	_ ...contract.FilterOption,
) ([]sdktypes.Contract, error) {
	return m.contracts, nil
}
func (m *fixContractManager) GetHandler(
	_ context.Context, _ sdktypes.Contract,
) (handlers.Handler, error) {
	return &fixHandler{}, nil
}
func (m *fixContractManager) NewDelegate(
	_ context.Context, _ *btcec.PublicKey,
) (*sdktypes.Contract, error) {
	return nil, nil
}
func (m *fixContractManager) NewVHTLC(
	_ context.Context, _ map[string]string,
) (*sdktypes.Contract, error) {
	return nil, nil
}
func (m *fixContractManager) Clean(_ context.Context) error { return nil }
func (m *fixContractManager) Close()                        {}
func (m *fixContractManager) OnContractEvent(_ func(sdktypes.Contract)) func() {
	return func() {}
}

func newArkClientForTest(vtxos []clientTypes.Vtxo, contracts []sdktypes.Contract) *arkClient {
	return &arkClient{
		store:           &fixStore{vtxo: &fixVtxoStore{spendable: vtxos}},
		contractManager: &fixContractManager{contracts: contracts},
		dbMu:            &sync.Mutex{},
	}
}

func makeTestVtxo(script string) clientTypes.Vtxo {
	return clientTypes.Vtxo{
		Outpoint: clientTypes.Outpoint{Txid: "aaaa", VOut: 0},
		Amount:   5000,
		Script:   script,
	}
}

func makeTestContract(script string) sdktypes.Contract {
	return sdktypes.Contract{
		Script: script,
		Type:   sdktypes.ContractTypeDefault,
		State:  sdktypes.ContractStateActive,
		Params: map[string]string{
			"tapscripts": `["leaf0","leaf1"]`,
		},
		CreatedAt: time.Now(),
	}
}

// TestGetSpendableVtxos_AllHaveContracts is the normal case: every vtxo has a
// matching contract, so all vtxos appear in the result with tapscripts.
func TestGetSpendableVtxos_AllHaveContracts(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{
		makeTestVtxo("script-a"),
		makeTestVtxo("script-b"),
	}
	contracts := []sdktypes.Contract{
		makeTestContract("script-a"),
		makeTestContract("script-b"),
	}

	a := newArkClientForTest(vtxos, contracts)
	result, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, result, 2)
	scripts := []string{result[0].Script, result[1].Script}
	require.Contains(t, scripts, "script-a")
	require.Contains(t, scripts, "script-b")
}

// TestGetSpendableVtxos_NoContracts verifies that vtxos with no matching
// contract are silently skipped, producing an empty result.
func TestGetSpendableVtxos_NoContracts(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{
		makeTestVtxo("boarding-script-1"),
		makeTestVtxo("boarding-script-2"),
	}

	a := newArkClientForTest(vtxos, nil)
	result, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Empty(t, result, "vtxos without a contract should be skipped")
}

// TestGetSpendableVtxos_MixedContracts verifies that only vtxos with a
// matching contract appear in the output; unmatched vtxos are silently dropped.
func TestGetSpendableVtxos_MixedContracts(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{
		makeTestVtxo("has-contract"),
		makeTestVtxo("no-contract"),
	}
	contracts := []sdktypes.Contract{
		makeTestContract("has-contract"),
	}

	a := newArkClientForTest(vtxos, contracts)
	result, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, "has-contract", result[0].Script)
}

// TestGetSpendableVtxos_Empty verifies that an empty vtxo store produces empty
// results without error.
func TestGetSpendableVtxos_Empty(t *testing.T) {
	t.Parallel()

	a := newArkClientForTest(nil, nil)
	result, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Empty(t, result)
}

// TestGetSpendableVtxos_UnrolledVtxosSkipped verifies that unrolled vtxos are
// always excluded, even when a matching contract exists.
func TestGetSpendableVtxos_UnrolledVtxosSkipped(t *testing.T) {
	t.Parallel()

	v := makeTestVtxo("unrolled-script")
	v.Unrolled = true
	contracts := []sdktypes.Contract{makeTestContract("unrolled-script")}

	a := newArkClientForTest([]clientTypes.Vtxo{v}, contracts)
	result, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Empty(t, result)
}

// TestGetSpendableVtxos_TapscriptsFromContract verifies that the Tapscripts on
// each VtxoWithTapTree come from the matching contract's handler, not from the
// vtxo itself.
func TestGetSpendableVtxos_TapscriptsFromContract(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{makeTestVtxo("known-script")}
	c := makeTestContract("known-script")
	c.Params["tapscripts"] = `["aa","bb","cc"]`

	a := newArkClientForTest(vtxos, []sdktypes.Contract{c})
	result, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, []string{"aa", "bb", "cc"}, result[0].Tapscripts)
}
