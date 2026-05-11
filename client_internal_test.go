package arksdk

import (
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestCommittedSentAmount(t *testing.T) {
	t.Parallel()

	vtxo := func(amount uint64) clientTypes.Vtxo { return clientTypes.Vtxo{Amount: amount} }
	boarding := func(amount uint64) clientTypes.Transaction { return clientTypes.Transaction{Amount: amount} }

	tests := []struct {
		name        string
		myVtxos     []clientTypes.Vtxo
		boardingTxs []clientTypes.Transaction
		vtxosToAdd  []clientTypes.Vtxo
		wantAmount  uint64
		wantSent    bool
	}{
		{
			name:       "pure send: inputs exceed change",
			myVtxos:    []clientTypes.Vtxo{vtxo(10_000), vtxo(5_000)},
			vtxosToAdd: []clientTypes.Vtxo{vtxo(3_000)},
			wantAmount: 12_000,
			wantSent:   true,
		},
		{
			name:        "boarding + vtxo spend in same round: boarding inflates vtxosToAdd beyond myVtxos",
			myVtxos:     []clientTypes.Vtxo{vtxo(1_000)},
			boardingTxs: []clientTypes.Transaction{boarding(20_000)},
			vtxosToAdd:  []clientTypes.Vtxo{vtxo(18_000)},
			wantAmount:  3_000,
			wantSent:    true,
		},
		{
			name:       "totalIn equals totalOut: no TxSent recorded",
			myVtxos:    []clientTypes.Vtxo{vtxo(5_000)},
			vtxosToAdd: []clientTypes.Vtxo{vtxo(5_000)},
			wantAmount: 0,
			wantSent:   false,
		},
		{
			name:       "totalIn less than totalOut: no underflow, no TxSent",
			myVtxos:    []clientTypes.Vtxo{vtxo(1_000)},
			vtxosToAdd: []clientTypes.Vtxo{vtxo(9_000)},
			wantAmount: 0,
			wantSent:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := committedSentAmount(tc.myVtxos, tc.boardingTxs, tc.vtxosToAdd)
			require.Equal(t, tc.wantSent, ok)
			require.Equal(t, tc.wantAmount, got)
		})
	}
}

func TestArkSentAmount(t *testing.T) {
	t.Parallel()

	vtxo := func(amount uint64) clientTypes.Vtxo { return clientTypes.Vtxo{Amount: amount} }

	tests := []struct {
		name       string
		myVtxos    []clientTypes.Vtxo
		vtxosToAdd []clientTypes.Vtxo
		wantAmount uint64
		wantSent   bool
	}{
		{
			name:       "pure send: inputs exceed change",
			myVtxos:    []clientTypes.Vtxo{vtxo(10_000), vtxo(5_000)},
			vtxosToAdd: []clientTypes.Vtxo{vtxo(3_000)},
			wantAmount: 12_000,
			wantSent:   true,
		},
		{
			name:       "receive in same ark tx inflates vtxosToAdd beyond myVtxos: no underflow, no TxSent",
			myVtxos:    []clientTypes.Vtxo{vtxo(1_000)},
			vtxosToAdd: []clientTypes.Vtxo{vtxo(9_000)},
			wantAmount: 0,
			wantSent:   false,
		},
		{
			name:       "totalIn equals totalOut: no TxSent recorded",
			myVtxos:    []clientTypes.Vtxo{vtxo(5_000)},
			vtxosToAdd: []clientTypes.Vtxo{vtxo(5_000)},
			wantAmount: 0,
			wantSent:   false,
		},
		{
			name:       "totalIn less than totalOut: no underflow, no TxSent",
			myVtxos:    []clientTypes.Vtxo{vtxo(2_000)},
			vtxosToAdd: []clientTypes.Vtxo{vtxo(8_000)},
			wantAmount: 0,
			wantSent:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := arkSentAmount(tc.myVtxos, tc.vtxosToAdd)
			require.Equal(t, tc.wantSent, ok)
			require.Equal(t, tc.wantAmount, got)
		})
	}
}

func TestGroupSpentVtxosByTx(t *testing.T) {
	t.Parallel()

	t.Run("groups offchain and settled vtxos and ignores unknown outpoints", func(t *testing.T) {
		t.Parallel()

		outpoint1 := clientTypes.Outpoint{Txid: "tx1", VOut: 0}
		outpoint2 := clientTypes.Outpoint{Txid: "tx2", VOut: 1}
		outpoint3 := clientTypes.Outpoint{Txid: "tx3", VOut: 2}
		missingOutpoint := clientTypes.Outpoint{Txid: "missing", VOut: 3}

		oldSpendable := map[clientTypes.Outpoint]clientTypes.Vtxo{
			outpoint1: {Outpoint: outpoint1},
			outpoint2: {Outpoint: outpoint2},
			outpoint3: {Outpoint: outpoint3},
		}

		spentVtxos := []clientTypes.Vtxo{
			{
				Outpoint: outpoint1,
				ArkTxid:  "arktx-checkpoint-1",
				SpentBy:  "checkpoint-txid-1",
			},
			{
				Outpoint: outpoint2,
				ArkTxid:  "arktx-checkpoint-1",
				SpentBy:  "checkpoint-txid-2",
			},
			{
				Outpoint:  outpoint3,
				SettledBy: "commitment-txid-1",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  missingOutpoint,
				ArkTxid:   "arktx-ignored",
				SettledBy: "commitment-txid-ignored",
				SpentBy:   "forfeit",
			},
		}

		vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendable)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"arktx-checkpoint-1": {
				outpoint1: "checkpoint-txid-1",
				outpoint2: "checkpoint-txid-2",
			},
		}, vtxosToSpend)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"commitment-txid-1": {
				outpoint3: "forfeit",
			},
		}, vtxosToSettle)
	})

	t.Run("creates multiple groups and prioritizes settled entries", func(t *testing.T) {
		t.Parallel()

		outpoint1 := clientTypes.Outpoint{Txid: "tx10", VOut: 0}
		outpoint2 := clientTypes.Outpoint{Txid: "tx11", VOut: 1}
		outpoint3 := clientTypes.Outpoint{Txid: "tx12", VOut: 2}
		outpoint4 := clientTypes.Outpoint{Txid: "tx13", VOut: 3}
		missingOutpoint := clientTypes.Outpoint{Txid: "tx14", VOut: 1}

		oldSpendable := map[clientTypes.Outpoint]clientTypes.Vtxo{
			outpoint1: {Outpoint: outpoint1},
			outpoint2: {Outpoint: outpoint2},
			outpoint3: {Outpoint: outpoint3},
			outpoint4: {Outpoint: outpoint4},
		}

		spentVtxos := []clientTypes.Vtxo{
			{
				Outpoint: outpoint1,
				ArkTxid:  "arktx-checkpoint-a",
				SpentBy:  "checkpoint-a-1",
			},
			{
				Outpoint: outpoint2,
				ArkTxid:  "arktx-checkpoint-b",
				SpentBy:  "checkpoint-b-1",
			},
			{
				Outpoint:  outpoint3,
				SettledBy: "commitment-a",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  outpoint4,
				ArkTxid:   "arktx-should-be-ignored",
				SettledBy: "commitment-b",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  missingOutpoint,
				ArkTxid:   "arktx",
				SettledBy: "commitment",
				SpentBy:   "forfeit",
			},
		}

		vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendable)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"arktx-checkpoint-a": {
				outpoint1: "checkpoint-a-1",
			},
			"arktx-checkpoint-b": {
				outpoint2: "checkpoint-b-1",
			},
		}, vtxosToSpend)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"commitment-a": {
				outpoint3: "forfeit",
			},
			"commitment-b": {
				outpoint4: "forfeit",
			},
		}, vtxosToSettle)
	})
}
