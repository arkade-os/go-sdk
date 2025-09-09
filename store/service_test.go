package store_test

import (
	"context"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	key, _         = btcec.NewPrivateKey()
	testConfigData = types.Config{
		ServerUrl:           "localhost:7070",
		SignerPubKey:        key.PubKey(),
		WalletType:          wallet.SingleKeyWallet,
		ClientType:          client.GrpcClient,
		Network:             arklib.BitcoinRegTest,
		VtxoTreeExpiry:      arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		RoundInterval:       10,
		UnilateralExitDelay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		Dust:                1000,
		BoardingExitDelay:   arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		ForfeitAddress:      "bcrt1qzvqj",
		// CheckpointTapscript: "abcdefghijklmnopqrtuvxyz",
	}

	testUtxos = []types.Utxo{
		{
			Outpoint: types.Outpoint{
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
			Outpoint: types.Outpoint{
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
	testUtxoKeys = []types.Outpoint{
		{
			Txid: "0000000000000000000000000000000000000000000000000000000000000000",
			VOut: 0,
		},
		{
			Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			VOut: 0,
		},
	}
	testConfirmedUtxoKeys = map[types.Outpoint]int64{
		testUtxoKeys[0]: time.Now().Unix(),
		testUtxoKeys[1]: time.Now().Add(10 * time.Second).Unix(),
	}
	testSpendUtxoKeys = map[types.Outpoint]string{
		testUtxoKeys[0]: "tx3",
	}
	testVtxos = []types.Vtxo{
		{
			Outpoint: types.Outpoint{
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
			Outpoint: types.Outpoint{
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
	}
	testVtxoKeys = []types.Outpoint{
		{
			Txid: "0000000000000000000000000000000000000000000000000000000000000000",
			VOut: 0,
		},
		{
			Txid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			VOut: 0,
		},
	}
	testSpendVtxoKeys = map[types.Outpoint]string{
		testVtxoKeys[0]: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	testSettleVtxoKeys = map[types.Outpoint]string{
		testVtxoKeys[1]: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	testTxs = []types.Transaction{
		{
			TransactionKey: types.TransactionKey{
				BoardingTxid: "0000000000000000000000000000000000000000000000000000000000000000",
			},
			Amount:  5000,
			Type:    types.TxReceived,
			Settled: false,
		},
		{
			TransactionKey: types.TransactionKey{
				ArkTxid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			Amount:  12000,
			Type:    types.TxReceived,
			Settled: false,
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
)

func TestService(t *testing.T) {
	t.Run("config store", func(t *testing.T) {
		dbDir := t.TempDir()
		tests := []struct {
			name   string
			config store.Config
		}{
			{
				name: "inmemory",
				config: store.Config{
					ConfigStoreType: types.InMemoryStore,
				},
			},
			{
				name: "file",
				config: store.Config{
					ConfigStoreType: types.FileStore,
					BaseDir:         dbDir,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc, err := store.NewStore(tt.config)
				require.NoError(t, err)
				testConfigStore(t, svc.ConfigStore())
			})
		}
	})

	t.Run("app data store", func(t *testing.T) {
		dbDir := t.TempDir()
		tests := []struct {
			name   string
			config store.Config
		}{
			{
				name: "kv",
				config: store.Config{
					ConfigStoreType:  types.InMemoryStore,
					AppDataStoreType: types.KVStore,
				},
			},
			{
				name: "sql",
				config: store.Config{
					ConfigStoreType:  types.InMemoryStore,
					AppDataStoreType: types.SQLStore,
					BaseDir:          dbDir,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc, err := store.NewStore(tt.config)
				require.NoError(t, err)
				testUtxoStore(t, svc.UtxoStore(), tt.config.AppDataStoreType)
				testVtxoStore(t, svc.VtxoStore(), tt.config.AppDataStoreType)
				testTxStore(t, svc.TransactionStore(), tt.config.AppDataStoreType)
				svc.Close()
			})
		}
	})
}

func testConfigStore(t *testing.T, storeSvc types.ConfigStore) {
	ctx := context.Background()

	// Check empty data when store is empty.
	data, err := storeSvc.GetData(ctx)
	require.NoError(t, err)
	require.Nil(t, data)

	// Check no side effects when cleaning an empty store.
	err = storeSvc.CleanData(ctx)
	require.NoError(t, err)

	// Check add and retrieve data.
	err = storeSvc.AddData(ctx, testConfigData)
	require.NoError(t, err)

	data, err = storeSvc.GetData(ctx)
	require.NoError(t, err)
	require.Equal(t, testConfigData, *data)

	// Check clean and retrieve data.
	err = storeSvc.CleanData(ctx)
	require.NoError(t, err)

	data, err = storeSvc.GetData(ctx)
	require.NoError(t, err)
	require.Nil(t, data)

	// Check overwriting the store.
	err = storeSvc.AddData(ctx, testConfigData)
	require.NoError(t, err)
	err = storeSvc.AddData(ctx, testConfigData)
	require.NoError(t, err)
}

func testUtxoStore(t *testing.T, storeSvc types.UtxoStore, storeType string) {
	ctx := context.Background()

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
}

func testVtxoStore(t *testing.T, storeSvc types.VtxoStore, storeType string) {
	ctx := context.Background()

	go func() {
		eventCh := storeSvc.GetEventChannel()
		for event := range eventCh {
			switch event.Type {
			case types.VtxosAdded:
				log.Infof("%s store - vtxos added: %d", storeType, len(event.Vtxos))
			case types.VtxosSpent:
				log.Infof("%s store - vtxos spent: %d", storeType, len(event.Vtxos))
			case types.VtxosUpdated:
				log.Infof("%s store - vtxos updated: %d", storeType, len(event.Vtxos))
			}
			for _, vtxo := range event.Vtxos {
				log.Infof("%v", vtxo)
			}
		}
	}()

	t.Run("add vtxos", func(t *testing.T) {
		spendable, spent, err := storeSvc.GetAllVtxos(ctx)
		require.NoError(t, err)
		require.Empty(t, spendable)
		require.Empty(t, spent)

		count, err := storeSvc.AddVtxos(ctx, testVtxos)
		require.NoError(t, err)
		require.Equal(t, len(testVtxos), count)

		count, err = storeSvc.AddVtxos(ctx, testVtxos)
		require.NoError(t, err)
		require.Zero(t, count)

		spendable, spent, err = storeSvc.GetAllVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, spendable, len(testVtxos))
		require.Empty(t, spent)

		vtxos, err := storeSvc.GetVtxos(ctx, testVtxoKeys)
		require.NoError(t, err)
		require.Equal(t, testVtxos, vtxos)
	})

	t.Run("spend vtxos", func(t *testing.T) {
		count, err := storeSvc.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
		require.NoError(t, err)
		require.Equal(t, len(testSpendVtxoKeys), count)

		count, err = storeSvc.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
		require.NoError(t, err)
		require.Zero(t, count)

		spendable, spent, err := storeSvc.GetAllVtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, len(spent))
		require.Equal(t, 1, len(spendable))
		for _, v := range spent {
			require.True(t, v.Spent)
			require.Equal(t, testSpendVtxoKeys[v.Outpoint], v.SpentBy)
			require.Equal(t, arkTxid, v.ArkTxid)
		}
	})

	t.Run("settle vtxos", func(t *testing.T) {
		count, err := storeSvc.SettleVtxos(ctx, testSettleVtxoKeys, settledBy)
		require.NoError(t, err)
		require.Equal(t, len(testSettleVtxoKeys), count)

		count, err = storeSvc.SettleVtxos(ctx, testSettleVtxoKeys, settledBy)
		require.NoError(t, err)
		require.Zero(t, count)

		spendable, spent, err := storeSvc.GetAllVtxos(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, len(spent))
		require.Empty(t, spendable)
		for _, v := range spent[1:] {
			require.True(t, v.Spent)
			require.Equal(t, testSettleVtxoKeys[v.Outpoint], v.SpentBy)
			require.Equal(t, settledBy, v.SettledBy)
		}
	})
}

func testTxStore(t *testing.T, storeSvc types.TransactionStore, storeType string) {
	ctx := context.Background()

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
		require.Equal(t, len(testTxs), count)

		count, err = storeSvc.AddTransactions(ctx, testTxs)
		require.NoError(t, err)
		require.Zero(t, count)

		allTxs, err = storeSvc.GetAllTransactions(ctx)
		require.NoError(t, err)
		require.Equal(t, testTxs, allTxs)

		txs, err := storeSvc.GetTransactions(ctx, testTxids)
		require.NoError(t, err)
		require.Equal(t, allTxs, txs)
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
		require.True(t, txs[0].Settled)
	})
}
