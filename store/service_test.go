package store_test

import (
	"fmt"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	testUtxos = []clientTypes.Utxo{
		{
			Outpoint: clientTypes.Outpoint{
				Txid: "0000000000000000000000000000000000000000000000000000000000000000",
				VOut: 0,
			},
			Script:     "0000000000000000000000000000000000000000000000000000000000000001",
			Amount:     1000,
			Tapscripts: []string{"abcd", "0001"},
			Tx:         "cccccc",
			Delay:      arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 10},
		},
		{
			Outpoint: clientTypes.Outpoint{
				Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				VOut: 0,
			},
			Script: "0000000000000000000000000000000000000000000000000000000000000001",
			Amount: 2000,
			Tapscripts: []string{
				"0000000000000000000000000000000000000000000000000000000000000000",
				"aaaa",
			},
			Tx:    "0200000010",
			Delay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		},
	}
	testUtxoKeys = []clientTypes.Outpoint{
		{
			Txid: "0000000000000000000000000000000000000000000000000000000000000000",
			VOut: 0,
		},
		{
			Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			VOut: 0,
		},
	}
	testConfirmedUtxoKeys = map[clientTypes.Outpoint]int64{
		testUtxoKeys[0]: time.Now().Unix(),
		testUtxoKeys[1]: time.Now().Add(10 * time.Second).Unix(),
	}
	testSpendUtxoKeys = map[clientTypes.Outpoint]string{
		testUtxoKeys[0]: "tx3",
	}
	testAssetGroups = []asset.AssetGroup{
		{
			// normal asset
			AssetId: &asset.AssetId{
				Txid: [32]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
					0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				Index: 0,
			},
			Outputs: []asset.AssetOutput{
				{
					Type:   asset.AssetOutputTypeLocal,
					Vout:   0,
					Amount: 500,
				},
				{
					Type:   asset.AssetOutputTypeLocal,
					Vout:   1,
					Amount: 500,
				},
			},
			Inputs: []asset.AssetInput{
				{
					Type:   asset.AssetInputTypeLocal,
					Vin:    0,
					Amount: 1000,
				},
			},
		},
		{
			// issuance with control asset by id
			AssetId: nil,
			Outputs: []asset.AssetOutput{
				{
					Type:   asset.AssetOutputTypeLocal,
					Vout:   0,
					Amount: 10000,
				},
			},
			ControlAsset: &asset.AssetRef{
				Type: asset.AssetRefByID,
				AssetId: asset.AssetId{
					Txid: [32]byte{
						0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
						0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					},
					Index: 0,
				},
			},
			Metadata: []asset.Metadata{
				{
					Key:   []byte("ticker"),
					Value: []byte("FRA"),
				},
				{
					Key:   []byte("name"),
					Value: []byte("French token"),
				},
			},
		},
		{
			// issuance with control asset by group index
			AssetId: nil,
			Outputs: []asset.AssetOutput{
				{
					Type:   asset.AssetOutputTypeLocal,
					Vout:   0,
					Amount: 10000,
				},
			},
			ControlAsset: &asset.AssetRef{
				Type:       asset.AssetRefByGroup,
				GroupIndex: 3,
			},
			Metadata: []asset.Metadata{
				{
					Key:   []byte("ticker"),
					Value: []byte("IT"),
				},
				{
					Key:   []byte("name"),
					Value: []byte("Italian token"),
				},
			},
		},
		{
			// control asset of IT asset
			AssetId: nil, // created in the issuance
			Outputs: []asset.AssetOutput{
				{
					Type:   asset.AssetOutputTypeLocal,
					Vout:   0,
					Amount: 100,
				},
			},
		},
	}

	testVtxoAsset1 = clientTypes.Asset{
		AssetId: asset.AssetId{
			Txid: [32]byte{
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0a,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			Index: 12,
		}.String(),
		Amount: 123456789,
	}

	testVtxoAsset2 = clientTypes.Asset{
		AssetId: asset.AssetId{
			Txid: [32]byte{
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0a,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			Index: 0,
		}.String(),
		Amount: 987654321,
	}

	testVtxos = []clientTypes.Vtxo{
		{
			Outpoint: clientTypes.Outpoint{
				Txid: "0000000000000000000000000000000000000000000000000000000000000000",
				VOut: 0,
			},
			Script: "0000000000000000000000000000000000000000000000000000000000000001",
			Amount: 1000,
			CommitmentTxids: []string{
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			ExpiresAt:    time.Unix(1748143068, 0),
			CreatedAt:    time.Unix(1746143068, 0),
			Preconfirmed: true,
		},
		{
			Outpoint: clientTypes.Outpoint{
				Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				VOut: 0,
			},
			Script: "0000000000000000000000000000000000000000000000000000000000000001",
			Amount: 2000,
			CommitmentTxids: []string{
				"0000000000000000000000000000000000000000000000000000000000000000",
			},
			ExpiresAt: time.Unix(1748143068, 0),
			CreatedAt: time.Unix(1746143068, 0),
		},
		{
			Outpoint: clientTypes.Outpoint{
				Txid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				VOut: 0,
			},
			Script: "0000000000000000000000000000000000000000000000000000000000000001",
			Amount: 3000,
			CommitmentTxids: []string{
				"0000000000000000000000000000000000000000000000000000000000000000",
			},
			ExpiresAt: time.Unix(1748143068, 0),
			CreatedAt: time.Unix(1746143068, 0),
			// vtxo with multiple assets
			Assets: []clientTypes.Asset{testVtxoAsset1, testVtxoAsset2},
		},
		{
			Outpoint: clientTypes.Outpoint{
				Txid: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				VOut: 0,
			},
			Script: "0000000000000000000000000000000000000000000000000000000000000001",
			Amount: 3000,
			CommitmentTxids: []string{
				"0000000000000000000000000000000000000000000000000000000000000000",
			},
			ExpiresAt: time.Unix(1748143068, 0),
			CreatedAt: time.Unix(1746143068, 0),
			// vtxo with single asset
			Assets: []clientTypes.Asset{testVtxoAsset1},
		},
	}
	testVtxoKeys = []clientTypes.Outpoint{
		{
			Txid: "0000000000000000000000000000000000000000000000000000000000000000",
			VOut: 0,
		},
		{
			Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			VOut: 0,
		},
		{
			Txid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			VOut: 0,
		},
		{
			Txid: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			VOut: 0,
		},
	}
	testSpendVtxoKeys = map[clientTypes.Outpoint]string{
		testVtxoKeys[0]: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	testSettleVtxoKeys = map[clientTypes.Outpoint]string{
		testVtxoKeys[1]: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	testTxs = []clientTypes.Transaction{
		{
			TransactionKey: clientTypes.TransactionKey{
				BoardingTxid: "0000000000000000000000000000000000000000000000000000000000000000",
			},
			Amount: 5000,
			Type:   clientTypes.TxReceived,
		},
		{
			TransactionKey: clientTypes.TransactionKey{
				ArkTxid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			Amount:      12000,
			Type:        clientTypes.TxReceived,
			AssetPacket: asset.Packet(testAssetGroups),
		},
	}

	testTxids = []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	testReplacedTxs = map[string]string{
		"0000000000000000000000000000000000000000000000000000000000000000": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	testReplacedTxids = []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
	}
	testConfirmedTxids = []string{
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	testSettledTxids = []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	settledBy = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	arkTxid   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	testAsset = clientTypes.AssetInfo{
		AssetId:        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		ControlAssetId: "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
		Metadata: []asset.Metadata{
			{
				Key:   []byte("ticker"),
				Value: []byte("FRA"),
			},
		},
	}
)

func TestNewStore(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			config          store.Config
			wantErrContains string
		}{
			{
				name:            "unknown store type",
				config:          store.Config{StoreType: "unknown"},
				wantErrContains: "unknown store type",
			},
			{
				name:   "SQL store with non-creatable path",
				config: store.Config{StoreType: types.SQLStore, Args: "/dev/null/subdir"},
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				svc, err := store.NewStore(f.config)
				require.Error(t, err)
				if f.wantErrContains != "" {
					require.ErrorContains(t, err, f.wantErrContains)
				}
				require.Nil(t, svc)
			})
		}
	})
}

func TestService(t *testing.T) {
	t.Run("app data store", func(t *testing.T) {
		dbDir := t.TempDir()
		tests := []struct {
			name   string
			config store.Config
		}{
			{
				name: "sql",
				config: store.Config{
					StoreType: types.SQLStore,
					Args:      dbDir,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc, err := store.NewStore(tt.config)
				require.NoError(t, err)
				testUtxoStore(t, svc.UtxoStore(), tt.config.StoreType)
				testVtxoStore(t, svc.VtxoStore(), tt.config.StoreType)
				testTxStore(t, svc.TransactionStore(), tt.config.StoreType)
				testAssetStore(t, svc.AssetStore())
				require.NotNil(t, svc.ContractStore())
				svc.Close()
			})
		}
	})
}

func testUtxoStore(t *testing.T, storeSvc types.UtxoStore, storeType string) {
	ctx := t.Context()

	go func() {
		eventCh := storeSvc.GetEventChannel()
		for event := range eventCh {
			switch event.Type {
			case types.UtxosAdded:
				log.Infof("%s store - utxos added: %d", storeType, len(event.Utxos))
			case types.UtxosConfirmed:
				log.Infof("%s store - utxos confirmed: %d", storeType, len(event.Utxos))
			case types.UtxosSpent:
				log.Infof("%s store - utxos spent: %d", storeType, len(event.Utxos))
			}
			for _, utxo := range event.Utxos {
				log.Infof("%v", utxo)
			}
		}
	}()

	t.Run("add utxos", func(t *testing.T) {
		spendable, spent, err := storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Empty(t, spendable)
		require.Empty(t, spent)

		count, err := storeSvc.AddUtxos(ctx, testUtxos)
		require.NoError(t, err)
		require.Equal(t, len(testUtxos), count)

		count, err = storeSvc.AddUtxos(ctx, testUtxos)
		require.NoError(t, err)
		require.Zero(t, count)

		spendable, spent, err = storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spendable, len(testUtxos))
		require.Empty(t, spent)

		utxos, err := storeSvc.GetUtxos(ctx, testUtxoKeys)
		require.NoError(t, err)
		require.Equal(t, testUtxos, utxos)

		utxos, err = storeSvc.GetUtxos(ctx, []clientTypes.Outpoint{
			{Txid: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", VOut: 0},
		})
		require.NoError(t, err)
		require.Empty(t, utxos)
	})

	t.Run("get utxos by txid", func(t *testing.T) {
		// Add two extra utxos sharing a txid to exercise multi-output lookup.
		sharedTxid := "1111111111111111111111111111111111111111111111111111111111111111"
		extra := []clientTypes.Utxo{
			{
				Outpoint:   clientTypes.Outpoint{Txid: sharedTxid, VOut: 0},
				Script:     "0000000000000000000000000000000000000000000000000000000000000002",
				Amount:     500,
				Tapscripts: []string{"aaaa"},
				Tx:         "deadbeef",
				Delay:      arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 1},
			},
			{
				Outpoint:   clientTypes.Outpoint{Txid: sharedTxid, VOut: 1},
				Script:     "0000000000000000000000000000000000000000000000000000000000000003",
				Amount:     600,
				Tapscripts: []string{"bbbb"},
				Tx:         "deadbeef",
				Delay:      arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 1},
			},
		}
		n, err := storeSvc.AddUtxos(ctx, extra)
		require.NoError(t, err)
		require.Equal(t, 2, n)

		fetched, err := storeSvc.GetUtxosByTxid(ctx, sharedTxid)
		require.NoError(t, err)
		require.Len(t, fetched, 2)
		gotVouts := map[uint32]bool{}
		for _, u := range fetched {
			require.Equal(t, sharedTxid, u.Txid)
			gotVouts[u.VOut] = true
		}
		require.True(t, gotVouts[0] && gotVouts[1])

		// Unknown txid returns empty without error.
		fetched, err = storeSvc.GetUtxosByTxid(
			ctx,
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		require.NoError(t, err)
		require.Empty(t, fetched)

		// Cleanup so the rest of the suite is unaffected.
		deleted, err := storeSvc.DeleteUtxos(ctx, []clientTypes.Outpoint{
			{Txid: sharedTxid, VOut: 0},
			{Txid: sharedTxid, VOut: 1},
		})
		require.NoError(t, err)
		require.Equal(t, 2, deleted)
	})

	t.Run("confirm utxos", func(t *testing.T) {
		spendable, spent, err := storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, len(spendable))
		require.Empty(t, spent)
		for _, v := range spendable {
			require.True(t, v.CreatedAt.IsZero())
		}

		count, err := storeSvc.ConfirmUtxos(ctx, testConfirmedUtxoKeys)
		require.NoError(t, err)
		require.Equal(t, len(testConfirmedUtxoKeys), count)

		count, err = storeSvc.ConfirmUtxos(ctx, testConfirmedUtxoKeys)
		require.NoError(t, err)
		require.Zero(t, count)

		spendable, spent, err = storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, len(spendable))
		require.Empty(t, spent)
		for _, v := range spendable {
			require.False(t, v.CreatedAt.IsZero())
			require.Equal(t, testConfirmedUtxoKeys[v.Outpoint], v.CreatedAt.Unix())
		}
	})

	t.Run("spend utxos", func(t *testing.T) {
		spendable, spent, err := storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, len(spendable))
		require.Empty(t, spent)
		for _, u := range spendable {
			require.False(t, u.Spent)
			require.Empty(t, u.SpentBy)
		}

		count, err := storeSvc.SpendUtxos(ctx, testSpendUtxoKeys)
		require.NoError(t, err)
		require.Equal(t, len(testSpendVtxoKeys), count)

		count, err = storeSvc.SpendUtxos(ctx, testSpendUtxoKeys)
		require.NoError(t, err)
		require.Zero(t, count)

		spendable, spent, err = storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, len(spent))
		require.Equal(t, 1, len(spendable))
		for _, u := range spent {
			require.True(t, u.Spent)
			require.Equal(t, testSpendUtxoKeys[u.Outpoint], u.SpentBy)
		}
	})

	t.Run("delete utxos", func(t *testing.T) {
		spendable, spent, err := storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, len(spendable))
		require.Equal(t, 1, len(spent))

		// Delete the remaining spendable utxo.
		count, err := storeSvc.DeleteUtxos(ctx, []clientTypes.Outpoint{spendable[0].Outpoint})
		require.NoError(t, err)
		require.Equal(t, 1, count)

		// Should be gone.
		spendable, spent, err = storeSvc.GetAllUtxos(ctx)
		require.NoError(t, err)
		require.Empty(t, spendable)
		require.Equal(t, 1, len(spent))

		// Deleting again should be a no-op.
		count, err = storeSvc.DeleteUtxos(ctx, []clientTypes.Outpoint{testUtxoKeys[1]})
		require.NoError(t, err)
		require.Zero(t, count)
	})
}

func testVtxoStore(t *testing.T, storeSvc types.VtxoStore, storeType string) {
	ctx := t.Context()

	go func() {
		eventCh := storeSvc.GetEventChannel()
		for event := range eventCh {
			switch event.Type {
			case types.VtxosAdded:
				log.Infof("%s store - vtxos added: %d", storeType, len(event.Vtxos))
			case types.VtxosSpent:
				log.Infof("%s store - vtxos spent: %d", storeType, len(event.Vtxos))
			case types.VtxosSwept:
				log.Infof("%s store - vtxos swept: %d", storeType, len(event.Vtxos))
			}
			for _, vtxo := range event.Vtxos {
				log.Infof("%v", vtxo)
			}
		}
	}()

	t.Run("add vtxos", func(t *testing.T) {
		all, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Empty(t, all)

		count, err := storeSvc.AddVtxos(ctx, testVtxos)
		require.NoError(t, err)
		require.Equal(t, len(testVtxos), count)

		count, err = storeSvc.AddVtxos(ctx, testVtxos)
		require.NoError(t, err)
		require.Zero(t, count)

		all, err = storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, all, len(testVtxos))
		requireVtxosListEqual(t, testVtxos, all)

		spendable, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Len(t, spendable, len(testVtxos))
		for _, v := range spendable {
			require.False(t, v.Spent)
			require.False(t, v.Unrolled)
		}
		requireVtxosListEqual(t, testVtxos, spendable)

		spent, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterSpent)
		require.NoError(t, err)
		require.Empty(t, spent)

		vtxos, err := storeSvc.GetVtxosByOutpoint(ctx, testVtxoKeys)
		require.NoError(t, err)
		requireVtxosListEqual(t, testVtxos, vtxos)

		vtxos, err = storeSvc.GetVtxosByOutpoint(ctx, []clientTypes.Outpoint{
			{Txid: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", VOut: 0},
		})
		require.NoError(t, err)
		require.Empty(t, vtxos)
	})

	t.Run("spend vtxos", func(t *testing.T) {
		count, err := storeSvc.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
		require.NoError(t, err)
		require.Equal(t, len(testSpendVtxoKeys), count)

		count, err = storeSvc.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
		require.NoError(t, err)
		require.Zero(t, count)

		all, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Equal(t, 4, len(all))

		spent, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterSpent)
		require.NoError(t, err)
		require.Equal(t, 1, len(spent))
		for _, v := range spent {
			require.True(t, v.Spent)
			require.Equal(t, testSpendVtxoKeys[v.Outpoint], v.SpentBy)
			require.Equal(t, arkTxid, v.ArkTxid)
		}

		spendable, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Len(t, spendable, 3)
		for _, v := range spendable {
			require.False(t, v.Spent)
		}
	})

	t.Run("settle vtxos", func(t *testing.T) {
		count, err := storeSvc.SettleVtxos(ctx, testSettleVtxoKeys, settledBy)
		require.NoError(t, err)
		require.Equal(t, len(testSettleVtxoKeys), count)

		count, err = storeSvc.SettleVtxos(ctx, testSettleVtxoKeys, settledBy)
		require.NoError(t, err)
		require.Zero(t, count)

		spent, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterSpent)
		require.NoError(t, err)
		require.Len(t, spent, 2)
		for _, v := range spent {
			require.True(t, v.Spent)
			testSettleBy, ok := testSettleVtxoKeys[v.Outpoint]
			if ok {
				require.Equal(t, testSettleBy, v.SpentBy)
				require.Equal(t, settledBy, v.SettledBy)
			}
		}

		spendable, err := storeSvc.GetVtxos(ctx, types.Page{}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Len(t, spendable, 2)
	})
}

func testTxStore(t *testing.T, storeSvc types.TransactionStore, storeType string) {
	ctx := t.Context()

	go func() {
		eventCh := storeSvc.GetEventChannel()
		for event := range eventCh {
			switch event.Type {
			case types.TxsAdded:
				log.Infof("%s store - txs added: %d", storeType, len(event.Txs))
			case types.TxsConfirmed:
				log.Infof("%s store - txs confirmed: %d", storeType, len(event.Txs))
			case types.TxsUpdated:
				log.Infof("%s store - txs updated: %d", storeType, len(event.Txs))
			case types.TxsSettled:
				log.Infof("%s store - txs settled: %d", storeType, len(event.Txs))
			case types.TxsReplaced:
				log.Infof("%s store - txs replaced: %d", storeType, len(event.Txs))
				log.Infof("replacements: %v", event.Replacements)
			}
			for _, tx := range event.Txs {
				log.Infof("%s", tx.TransactionKey)
			}
		}
	}()

	t.Run("add txs", func(t *testing.T) {
		allTxs, err := storeSvc.GetAllTransactions(ctx)
		require.NoError(t, err)
		require.Empty(t, allTxs)

		count, err := storeSvc.AddTransactions(ctx, testTxs)
		require.NoError(t, err)
		require.Len(t, testTxs, count)

		count, err = storeSvc.AddTransactions(ctx, testTxs)
		require.NoError(t, err)
		require.Zero(t, count)

		allTxs, err = storeSvc.GetAllTransactions(ctx)
		require.NoError(t, err)
		require.Equal(t, testTxs, allTxs)

		txs, err := storeSvc.GetTransactions(ctx, testTxids)
		require.NoError(t, err)
		require.Equal(t, allTxs, txs)

		txs, err = storeSvc.GetTransactions(ctx, []string{
			"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		})
		require.NoError(t, err)
		require.Empty(t, txs)
	})

	t.Run("replace txs", func(t *testing.T) {
		count, err := storeSvc.RbfTransactions(ctx, testReplacedTxs)
		require.NoError(t, err)
		require.Equal(t, len(testReplacedTxs), count)

		count, err = storeSvc.RbfTransactions(ctx, testReplacedTxs)
		require.NoError(t, err)
		require.Zero(t, count)

		txs, err := storeSvc.GetTransactions(ctx, testReplacedTxids)
		require.NoError(t, err)
		require.Empty(t, txs)

		newTxids := []string{testReplacedTxs[testReplacedTxids[0]]}
		txs, err = storeSvc.GetTransactions(ctx, newTxids)
		require.NoError(t, err)
		require.Equal(t, testReplacedTxs[testReplacedTxids[0]], txs[0].TransactionKey.String())
	})

	t.Run("confirm txs", func(t *testing.T) {
		count, err := storeSvc.ConfirmTransactions(ctx, testConfirmedTxids, time.Now())
		require.NoError(t, err)
		require.Equal(t, len(testConfirmedTxids), count)

		count, err = storeSvc.ConfirmTransactions(ctx, testConfirmedTxids, time.Now())
		require.NoError(t, err)
		require.Zero(t, count)

		txs, err := storeSvc.GetTransactions(ctx, testConfirmedTxids)
		require.NoError(t, err)
		require.Len(t, txs, 1)
		require.NotEmpty(t, txs[0].CreatedAt)
	})

	t.Run("settle txs", func(t *testing.T) {
		count, err := storeSvc.SettleTransactions(ctx, testSettledTxids, settledBy)
		require.NoError(t, err)
		require.Equal(t, len(testSettledTxids), count)

		count, err = storeSvc.SettleTransactions(ctx, testSettledTxids, settledBy)
		require.NoError(t, err)
		require.Zero(t, count)

		txs, err := storeSvc.GetTransactions(ctx, testSettledTxids)
		require.NoError(t, err)
		require.Len(t, txs, 1)
		require.NotEmpty(t, txs[0].SettledBy)
	})
}

func testAssetStore(t *testing.T, storeSvc types.AssetStore) {
	ctx := t.Context()

	err := storeSvc.UpsertAsset(ctx, testAsset)
	require.NoError(t, err)

	asset, err := storeSvc.GetAsset(ctx, testAsset.AssetId)
	require.NoError(t, err)
	require.Equal(t, testAsset, *asset)

	// upsert does not erase metadata or control asset id
	testAssetIdOnly := clientTypes.AssetInfo{
		AssetId: testAsset.AssetId,
	}
	err = storeSvc.UpsertAsset(ctx, testAssetIdOnly)
	require.NoError(t, err)

	asset, err = storeSvc.GetAsset(ctx, testAssetIdOnly.AssetId)
	require.NoError(t, err)
	require.Equal(t, testAsset, *asset)

	asset, err = storeSvc.GetAsset(
		ctx, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "asset not found")
	require.Nil(t, asset)
}

func TestVtxoPagination(t *testing.T) {
	svc, err := store.NewStore(store.Config{
		StoreType: types.SQLStore,
		Args:      t.TempDir(),
	})
	require.NoError(t, err)
	defer svc.Close()

	ctx := t.Context()
	vtxoStore := svc.VtxoStore()

	// Insert 22 spendable VTXOs with distinct created_at values.
	// created_at goes from 1000 (oldest, index 0) to 22000 (newest, index 21).
	// SQL orders by created_at DESC, so page 1 should contain the newest VTXOs.
	const totalVtxos = 22
	paginationVtxos := make([]clientTypes.Vtxo, totalVtxos)
	for i := range totalVtxos {
		paginationVtxos[i] = clientTypes.Vtxo{
			Outpoint: clientTypes.Outpoint{
				Txid: fmt.Sprintf("%064x", i+1),
				VOut: 0,
			},
			Script:          "aaaa",
			Amount:          uint64((i + 1) * 1000),
			CommitmentTxids: []string{"commitmentaaa"},
			ExpiresAt:       time.Unix(1800000000, 0),
			CreatedAt:       time.Unix(int64(1000*(i+1)), 0),
		}
	}
	count, err := vtxoStore.AddVtxos(ctx, paginationVtxos)
	require.NoError(t, err)
	require.Equal(t, totalVtxos, count)

	// Helper: collect created_at unix timestamps from a VTXO slice.
	createdAts := func(vtxos []clientTypes.Vtxo) []int64 {
		out := make([]int64, len(vtxos))
		for i, v := range vtxos {
			out[i] = v.CreatedAt.Unix()
		}
		return out
	}

	// Helper: collect outpoint txids from a VTXO slice.
	outpointTxids := func(vtxos []clientTypes.Vtxo) map[string]bool {
		out := make(map[string]bool, len(vtxos))
		for _, v := range vtxos {
			out[v.Txid] = true
		}
		return out
	}

	t.Run("Page{} returns ALL vtxos", func(t *testing.T) {
		all, err := vtxoStore.GetVtxos(ctx, types.Page{}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, all, totalVtxos)

		spendable, err := vtxoStore.GetVtxos(ctx, types.Page{}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Len(t, spendable, totalVtxos)
	})

	t.Run("Page{1,5} returns the 5 newest VTXOs", func(t *testing.T) {
		page1, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, page1, 5)

		// The 5 newest VTXOs have created_at = 22000, 21000, 20000, 19000, 18000.
		for _, v := range page1 {
			require.GreaterOrEqual(t, v.CreatedAt.Unix(), int64(18000),
				"page 1 VTXO created_at=%d should be >= 18000", v.CreatedAt.Unix())
		}
		txids := outpointTxids(page1)
		for i := 18; i <= 22; i++ {
			txid := fmt.Sprintf("%064x", i)
			require.True(
				t,
				txids[txid],
				"page 1 should contain VTXO with index %d (created_at=%d)",
				i,
				i*1000,
			)
		}
	})

	t.Run("Page{2,5} returns next 5, all older than page 1", func(t *testing.T) {
		page1, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)

		page2, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 2, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, page2, 5)

		// Every VTXO on page 2 must have created_at < every VTXO on page 1.
		page1Timestamps := createdAts(page1)
		page2Timestamps := createdAts(page2)
		var minPage1 = page1Timestamps[0]
		for _, ts := range page1Timestamps {
			if ts < minPage1 {
				minPage1 = ts
			}
		}
		for _, ts := range page2Timestamps {
			require.Less(t, ts, minPage1,
				"page 2 VTXO created_at=%d must be < min page 1 created_at=%d", ts, minPage1)
		}

		// Page 2 should contain VTXOs with created_at = 17000..13000.
		txids := outpointTxids(page2)
		for i := 13; i <= 17; i++ {
			txid := fmt.Sprintf("%064x", i)
			require.True(t, txids[txid], "page 2 should contain VTXO with index %d", i)
		}

		// No overlap between page 1 and page 2.
		page1Txids := outpointTxids(page1)
		for txid := range txids {
			require.False(t, page1Txids[txid], "page 1 and page 2 must not overlap (txid=%s)", txid)
		}
	})

	t.Run("Page{4,5} returns 5 VTXOs from the 4th page", func(t *testing.T) {
		// 22 VTXOs, page size 5, ordered by created_at DESC:
		// Page 1 (offset 0): 22000, 21000, 20000, 19000, 18000
		// Page 2 (offset 5): 17000, 16000, 15000, 14000, 13000
		// Page 3 (offset 10): 12000, 11000, 10000, 9000, 8000
		// Page 4 (offset 15): 7000, 6000, 5000, 4000, 3000
		// Page 5 (offset 20): 2000, 1000  <-- partial page
		page4, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 4, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, page4, 5)

		txids := outpointTxids(page4)
		for i := 3; i <= 7; i++ {
			txid := fmt.Sprintf("%064x", i)
			require.True(
				t,
				txids[txid],
				"page 4 should contain VTXO with index %d (created_at=%d)",
				i,
				i*1000,
			)
		}
	})

	t.Run("Page{5,5} returns last partial page with 2 VTXOs", func(t *testing.T) {
		page5, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 5, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, page5, 2)

		// These should be the 2 oldest VTXOs: created_at 2000, 1000.
		txids := outpointTxids(page5)
		for i := 1; i <= 2; i++ {
			txid := fmt.Sprintf("%064x", i)
			require.True(
				t,
				txids[txid],
				"last page should contain VTXO with index %d (created_at=%d)",
				i,
				i*1000,
			)
		}
	})

	t.Run("Page{6,5} beyond last page returns empty", func(t *testing.T) {
		beyond, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 6, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Empty(t, beyond)
	})

	t.Run("spendable filter pagination with ordering", func(t *testing.T) {
		page1, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 5}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Len(t, page1, 5)

		page2, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 2, PageSize: 5}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Len(t, page2, 5)

		// Every VTXO on page 2 must be older than every VTXO on page 1.
		page1Timestamps := createdAts(page1)
		page2Timestamps := createdAts(page2)
		var minPage1 = page1Timestamps[0]
		for _, ts := range page1Timestamps {
			if ts < minPage1 {
				minPage1 = ts
			}
		}
		for _, ts := range page2Timestamps {
			require.Less(
				t,
				ts,
				minPage1,
				"spendable filter: page 2 created_at=%d must be < min page 1 created_at=%d",
				ts,
				minPage1,
			)
		}

		// Beyond last page returns empty.
		beyondPage, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 999, PageSize: 5}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Empty(t, beyondPage)
	})

	t.Run("MaxPageSize clamping", func(t *testing.T) {
		all, err := vtxoStore.GetVtxos(ctx, types.Page{
			PageNum: 1, PageSize: types.MaxPageSize + 100,
		}, types.VtxoFilterAll)
		require.NoError(t, err)
		// Clamped to MaxPageSize=200, but only 22 exist.
		require.Len(t, all, totalVtxos)
	})

	t.Run("PageNum 0 treated as page 1", func(t *testing.T) {
		page0, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 0, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)
		page1, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)

		require.Len(t, page0, 5)
		require.Len(t, page1, 5)
		// Both should contain the exact same set of outpoints.
		page0Txids := outpointTxids(page0)
		page1Txids := outpointTxids(page1)
		require.Equal(t, page0Txids, page1Txids)
	})

	t.Run("multi-asset VTXO counts as 1", func(t *testing.T) {
		multiAssetVtxo := clientTypes.Vtxo{
			Outpoint: clientTypes.Outpoint{
				Txid: fmt.Sprintf("%064x", 100),
				VOut: 0,
			},
			Script:          "bbbb",
			Amount:          9000,
			CommitmentTxids: []string{"commitmentbbb"},
			ExpiresAt:       time.Unix(1800000000, 0),
			CreatedAt:       time.Unix(100000, 0),
			Assets:          []clientTypes.Asset{testVtxoAsset1, testVtxoAsset2},
		}
		n, err := vtxoStore.AddVtxos(ctx, []clientTypes.Vtxo{multiAssetVtxo})
		require.NoError(t, err)
		require.Equal(t, 1, n)

		// Total should be 23 VTXOs now (22 + 1 multi-asset).
		all, err := vtxoStore.GetVtxos(ctx, types.Page{}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, all, totalVtxos+1)

		// Multi-asset VTXO with created_at=100000 is the newest.
		page1, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 5}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, page1, 5)

		// The multi-asset VTXO should be on page 1 (it has the highest created_at).
		var foundMultiAsset bool
		for _, v := range page1 {
			if v.Txid == multiAssetVtxo.Txid {
				require.Len(t, v.Assets, 2)
				foundMultiAsset = true
			}
		}
		require.True(t, foundMultiAsset, "multi-asset VTXO should appear on page 1")
	})

	t.Run("spent filter pagination", func(t *testing.T) {
		// Spend the first vtxo (index 0, created_at=1000 — the oldest).
		spendMap := map[clientTypes.Outpoint]string{
			paginationVtxos[0].Outpoint: "spender_tx",
		}
		n, err := vtxoStore.SpendVtxos(ctx, spendMap, "arktx1")
		require.NoError(t, err)
		require.Equal(t, 1, n)

		// VtxoFilterAll should return everything (23 total).
		all, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 30}, types.VtxoFilterAll)
		require.NoError(t, err)
		require.Len(t, all, totalVtxos+1) // 22 original + 1 multi-asset

		// VtxoFilterSpent should return only the spent one.
		spent, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 30}, types.VtxoFilterSpent)
		require.NoError(t, err)
		require.Len(t, spent, 1)

		// VtxoFilterSpendable should return the unspent ones.
		spendable, err := vtxoStore.GetVtxos(ctx, types.Page{PageNum: 1, PageSize: 30}, types.VtxoFilterSpendable)
		require.NoError(t, err)
		require.Len(t, spendable, totalVtxos) // 21 original unspent + 1 multi-asset

		// Verify spent VTXO does NOT appear in spendable filter.
		for _, v := range spendable {
			require.NotEqual(t, paginationVtxos[0].Txid, v.Txid,
				"spent VTXO should not appear in spendable filter")
		}
	})
}

func requireVtxosListEqual(t *testing.T, expected, actual []clientTypes.Vtxo) {
	require.Len(t, expected, len(actual))

	for _, v := range expected {
		found := false
		for _, a := range actual {
			if v.Outpoint == a.Outpoint {
				require.Equal(t, v, a)
				found = true
				break
			}
		}
		require.True(t, found)
	}
}
