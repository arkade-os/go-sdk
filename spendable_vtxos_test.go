package arksdk

import (
	"context"
	"sync"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	sdktypes "github.com/arkade-os/go-sdk/types"
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
func (s *fixStore) ContractStore() contract.ContractStore       { return nil }
func (s *fixStore) Clean(_ context.Context)                     {}
func (s *fixStore) Close()                                      {}

type fixContractManager struct {
	contracts []contract.Contract
}

func (m *fixContractManager) Load(_ context.Context) error { return nil }
func (m *fixContractManager) NewDefault(_ context.Context) (*contract.Contract, error) {
	return nil, nil
}

func (m *fixContractManager) GetContracts(
	_ context.Context,
	_ ...contract.FilterOption,
) ([]contract.Contract, error) {
	return m.contracts, nil
}

func (m *fixContractManager) GetContractsForVtxos(
	_ context.Context,
	scripts []string,
) ([]contract.Contract, error) {
	lookup := make(map[string]struct{}, len(scripts))
	for _, s := range scripts {
		lookup[s] = struct{}{}
	}
	var result []contract.Contract
	for _, c := range m.contracts {
		if _, ok := lookup[c.Script]; ok {
			result = append(result, c)
		}
	}
	return result, nil
}
func (m *fixContractManager) OnContractEvent(_ func(contract.Event)) func() { return func() {} }
func (m *fixContractManager) Close() error                                  { return nil }

func newArkClientForTest(vtxos []clientTypes.Vtxo, contracts []contract.Contract) *arkClient {
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

func makeTestContract(script, keyID string) contract.Contract {
	return contract.Contract{
		Script: script,
		Type:   contract.TypeDefault,
		State:  contract.StateActive,
		Params: map[string]string{
			"keyId":                  keyID,
			contract.ParamTapscripts: `["leaf0","leaf1"]`,
		},
		CreatedAt: time.Now(),
	}
}

// TestGetSpendableVtxos_AllHaveContracts is the normal case: every vtxo has a
// matching contract, so the key map is fully populated.
func TestGetSpendableVtxos_AllHaveContracts(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{
		makeTestVtxo("script-a"),
		makeTestVtxo("script-b"),
	}
	contracts := []contract.Contract{
		makeTestContract("script-a", "key-a"),
		makeTestContract("script-b", "key-b"),
	}

	a := newArkClientForTest(vtxos, contracts)
	result, keyMap, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, result, 2)
	require.Len(t, keyMap, 2)
	require.Equal(t, "key-a", keyMap["script-a"])
	require.Equal(t, "key-b", keyMap["script-b"])
}

// TestGetSpendableVtxos_NoContracts is the boarding-only scenario that
// motivated the bug fix: vtxos in the store have no matching contracts, so
// scriptToKeyID must be empty. Callers guard with len(scriptToKeyID) > 0
// before passing WithKeys to the client; an empty map must not be passed.
func TestGetSpendableVtxos_NoContracts(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{
		makeTestVtxo("boarding-script-1"),
		makeTestVtxo("boarding-script-2"),
	}

	a := newArkClientForTest(vtxos, nil)
	result, keyMap, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Empty(t, result, "vtxos without a contract should be skipped")
	require.Empty(t, keyMap, "scriptToKeyID must be empty when no contracts match")
}

// TestGetSpendableVtxos_MixedContracts verifies that only matched vtxos and
// their key IDs appear in the output; unmatched vtxos are silently dropped.
func TestGetSpendableVtxos_MixedContracts(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{
		makeTestVtxo("has-contract"),
		makeTestVtxo("no-contract"),
	}
	contracts := []contract.Contract{
		makeTestContract("has-contract", "key-x"),
	}

	a := newArkClientForTest(vtxos, contracts)
	result, keyMap, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, "has-contract", result[0].Script)
	require.Len(t, keyMap, 1)
	require.Equal(t, "key-x", keyMap["has-contract"])
	require.NotContains(t, keyMap, "no-contract")
}

// TestGetSpendableVtxos_Empty verifies that an empty vtxo store produces empty
// results without error.
func TestGetSpendableVtxos_Empty(t *testing.T) {
	t.Parallel()

	a := newArkClientForTest(nil, nil)
	result, keyMap, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Empty(t, result)
	require.Empty(t, keyMap)
}

// TestGetSpendableVtxos_UnrolledVtxosSkipped verifies that unrolled vtxos are
// always excluded, even when a matching contract exists.
func TestGetSpendableVtxos_UnrolledVtxosSkipped(t *testing.T) {
	t.Parallel()

	v := makeTestVtxo("unrolled-script")
	v.Unrolled = true
	contracts := []contract.Contract{makeTestContract("unrolled-script", "key-u")}

	a := newArkClientForTest([]clientTypes.Vtxo{v}, contracts)
	result, keyMap, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Empty(t, result)
	require.Empty(t, keyMap)
}

// TestGetSpendableVtxos_TapscriptsFromContract verifies that the Tapscripts on
// each VtxoWithTapTree come from the matching contract, not from the vtxo itself.
func TestGetSpendableVtxos_TapscriptsFromContract(t *testing.T) {
	t.Parallel()

	vtxos := []clientTypes.Vtxo{makeTestVtxo("known-script")}
	c := makeTestContract("known-script", "key-k")
	c.Params[contract.ParamTapscripts] = `["aa","bb","cc"]`

	a := newArkClientForTest(vtxos, []contract.Contract{c})
	result, _, err := a.getSpendableVtxos(context.Background(), false)

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, []string{"aa", "bb", "cc"}, result[0].Tapscripts)
}
