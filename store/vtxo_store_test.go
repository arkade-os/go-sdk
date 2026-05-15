package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fixtures (moved verbatim from service_test.go)
// ---------------------------------------------------------------------------

var (
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

	arkTxid = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func forEachVtxoBackend(t *testing.T, fn func(t *testing.T, s types.VtxoStore)) {
	t.Helper()

	backends := []struct {
		name   string
		config store.Config
	}{
		{name: "sql", config: store.Config{StoreType: types.SQLStore, Args: t.TempDir()}},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			svc, err := store.NewStore(b.config)
			require.NoError(t, err)
			t.Cleanup(svc.Close)

			vs := svc.VtxoStore()
			require.NotNil(t, vs)
			fn(t, vs)
		})
	}
}

func seedVtxos(t *testing.T, s types.VtxoStore, vtxos ...clientTypes.Vtxo) {
	t.Helper()
	if len(vtxos) == 0 {
		return
	}
	n, err := s.AddVtxos(t.Context(), vtxos)
	require.NoError(t, err)
	require.Equal(t, len(vtxos), n)
}

func requireVtxosListEqual(t *testing.T, expected, actual []clientTypes.Vtxo) {
	t.Helper()
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

// ---------------------------------------------------------------------------
// Tests — one per VtxoStore interface method
// ---------------------------------------------------------------------------

func TestVtxoStoreAddVtxos(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			t.Run("insert N vtxos", func(t *testing.T) {
				n, err := s.AddVtxos(ctx, testVtxos)
				require.NoError(t, err)
				require.Equal(t, len(testVtxos), n)
			})

			t.Run("idempotent reinsert returns 0", func(t *testing.T) {
				n, err := s.AddVtxos(ctx, testVtxos)
				require.NoError(t, err)
				require.Zero(t, n)
			})

			t.Run("multi-asset vtxo round-trips correctly", func(t *testing.T) {
				got, err := s.GetVtxosByOutpoints(ctx, testVtxoKeys)
				require.NoError(t, err)
				requireVtxosListEqual(t, testVtxos, got)
			})
		})
	})
}

func TestVtxoStoreSpendVtxos(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()
			seedVtxos(t, s, testVtxos...)

			t.Run("spends one outpoint", func(t *testing.T) {
				n, err := s.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
				require.NoError(t, err)
				require.Equal(t, len(testSpendVtxoKeys), n)
			})

			t.Run("second call for same outpoints returns 0", func(t *testing.T) {
				n, err := s.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
				require.NoError(t, err)
				require.Zero(t, n)
			})

			t.Run("spent vtxo has correct fields", func(t *testing.T) {
				vtxos, _, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusSpent,
					Limit:  1000,
				})
				require.NoError(t, err)
				require.Len(t, vtxos, 1)
				v := vtxos[0]
				require.True(t, v.Spent)
				require.Equal(t, testSpendVtxoKeys[v.Outpoint], v.SpentBy)
				require.Equal(t, arkTxid, v.ArkTxid)
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			t.Run("empty map returns 0, no error", func(t *testing.T) {
				n, err := s.SpendVtxos(ctx, map[clientTypes.Outpoint]string{}, "any")
				require.NoError(t, err)
				require.Zero(t, n)
			})

			t.Run("unknown outpoints returns 0, no error", func(t *testing.T) {
				unknown := map[clientTypes.Outpoint]string{
					{Txid: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", VOut: 0}: "tx1",
				}
				n, err := s.SpendVtxos(ctx, unknown, "any")
				require.NoError(t, err)
				require.Zero(t, n)
			})
		})
	})
}

func TestVtxoStoreSettleVtxos(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()
			seedVtxos(t, s, testVtxos...)

			t.Run("mark settle populates SpentBy and SettledBy", func(t *testing.T) {
				n, err := s.SettleVtxos(ctx, testSettleVtxoKeys, settledBy)
				require.NoError(t, err)
				require.Equal(t, len(testSettleVtxoKeys), n)

				vtxos, _, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusSpent,
					Limit:  1000,
				})
				require.NoError(t, err)
				for _, v := range vtxos {
					expectedSpentBy, ok := testSettleVtxoKeys[v.Outpoint]
					if ok {
						require.Equal(t, expectedSpentBy, v.SpentBy)
						require.Equal(t, settledBy, v.SettledBy)
					}
				}
			})

			t.Run("second call for same outpoints returns 0", func(t *testing.T) {
				n, err := s.SettleVtxos(ctx, testSettleVtxoKeys, settledBy)
				require.NoError(t, err)
				require.Zero(t, n)
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			t.Run("empty map returns 0, no error", func(t *testing.T) {
				n, err := s.SettleVtxos(ctx, map[clientTypes.Outpoint]string{}, "any")
				require.NoError(t, err)
				require.Zero(t, n)
			})

			t.Run("unknown outpoints returns 0, no error", func(t *testing.T) {
				unknown := map[clientTypes.Outpoint]string{
					{Txid: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", VOut: 0}: "tx1",
				}
				n, err := s.SettleVtxos(ctx, unknown, "any")
				require.NoError(t, err)
				require.Zero(t, n)
			})
		})
	})
}

func TestVtxoStoreSweepVtxos(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()
			seedVtxos(t, s, testVtxos...)

			toSweep := testVtxos[:2]

			t.Run("mark swept sets Swept=true", func(t *testing.T) {
				n, err := s.SweepVtxos(ctx, toSweep)
				require.NoError(t, err)
				require.Equal(t, len(toSweep), n)

				got, err := s.GetVtxosByOutpoints(ctx, []clientTypes.Outpoint{
					toSweep[0].Outpoint,
					toSweep[1].Outpoint,
				})
				require.NoError(t, err)
				for _, v := range got {
					require.True(t, v.Swept)
				}
			})

			t.Run("idempotent re-sweep returns 0", func(t *testing.T) {
				n, err := s.SweepVtxos(ctx, toSweep)
				require.NoError(t, err)
				require.Zero(t, n)
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			t.Run("empty input returns 0, no error", func(t *testing.T) {
				n, err := s.SweepVtxos(ctx, nil)
				require.NoError(t, err)
				require.Zero(t, n)
			})
		})
	})
}

func TestVtxoStoreUnrollVtxos(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()
			seedVtxos(t, s, testVtxos...)

			toUnroll := testVtxos[:2]

			t.Run("mark unrolled sets Unrolled=true", func(t *testing.T) {
				n, err := s.UnrollVtxos(ctx, toUnroll)
				require.NoError(t, err)
				require.Equal(t, len(toUnroll), n)

				got, err := s.GetVtxosByOutpoints(ctx, []clientTypes.Outpoint{
					toUnroll[0].Outpoint,
					toUnroll[1].Outpoint,
				})
				require.NoError(t, err)
				for _, v := range got {
					require.True(t, v.Unrolled)
				}
			})

			t.Run("idempotent re-unroll returns 0", func(t *testing.T) {
				n, err := s.UnrollVtxos(ctx, toUnroll)
				require.NoError(t, err)
				require.Zero(t, n)
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			t.Run("empty input returns 0, no error", func(t *testing.T) {
				n, err := s.UnrollVtxos(ctx, nil)
				require.NoError(t, err)
				require.Zero(t, n)
			})
		})
	})
}

func TestVtxoStoreGetSpendableOrRecoverableVtxos(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()
			seedVtxos(t, s, testVtxos...)

			t.Run("returns all non-spent non-unrolled vtxos initially", func(t *testing.T) {
				got, err := s.GetSpendableOrRecoverableVtxos(ctx)
				require.NoError(t, err)
				require.Len(t, got, len(testVtxos))
				for _, v := range got {
					require.False(t, v.Spent)
					require.False(t, v.Unrolled)
				}
			})

			t.Run("spent vtxos are excluded", func(t *testing.T) {
				_, err := s.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
				require.NoError(t, err)

				got, err := s.GetSpendableOrRecoverableVtxos(ctx)
				require.NoError(t, err)
				require.Len(t, got, len(testVtxos)-len(testSpendVtxoKeys))
				for _, v := range got {
					require.False(t, v.Spent)
				}
			})

			t.Run("unrolled vtxos are excluded", func(t *testing.T) {
				toUnroll := []clientTypes.Vtxo{testVtxos[1]}
				_, err := s.UnrollVtxos(ctx, toUnroll)
				require.NoError(t, err)

				got, err := s.GetSpendableOrRecoverableVtxos(ctx)
				require.NoError(t, err)
				// testVtxos[0] spent, testVtxos[1] unrolled → 2 remaining
				require.Len(t, got, len(testVtxos)-len(testSpendVtxoKeys)-1)
				for _, v := range got {
					require.False(t, v.Spent)
					require.False(t, v.Unrolled)
				}
			})
		})
	})
}

func TestVtxoStoreGetVtxosByOutpoints(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()
			seedVtxos(t, s, testVtxos...)

			t.Run("returns vtxos for matching outpoints", func(t *testing.T) {
				got, err := s.GetVtxosByOutpoints(ctx, testVtxoKeys)
				require.NoError(t, err)
				requireVtxosListEqual(t, testVtxos, got)
			})

			t.Run("preserves multi-asset hydration", func(t *testing.T) {
				got, err := s.GetVtxosByOutpoints(ctx, []clientTypes.Outpoint{testVtxoKeys[2]})
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, testVtxos[2].Assets, got[0].Assets)
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			t.Run("unknown outpoint returns empty slice, no error", func(t *testing.T) {
				got, err := s.GetVtxosByOutpoints(ctx, []clientTypes.Outpoint{
					{
						Txid: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
						VOut: 0,
					},
				})
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("empty input returns empty slice, no error", func(t *testing.T) {
				got, err := s.GetVtxosByOutpoints(ctx, nil)
				require.NoError(t, err)
				require.Empty(t, got)
			})
		})
	})
}

func TestVtxoStoreGetVtxos(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			// Seed a deterministic dataset: assign sequential created_at values so
			// descending sort is fully ordered (no ties).
			seed := make([]clientTypes.Vtxo, len(testVtxos))
			copy(seed, testVtxos)
			base := time.Now().Add(-time.Hour).Unix()
			for i := range seed {
				seed[i].CreatedAt = time.Unix(base+int64(i), 0)
			}
			seedVtxos(t, s, seed...)

			t.Run("first page returns newest first", func(t *testing.T) {
				vtxos, cursor, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusAll,
					Limit:  2,
				})
				require.NoError(t, err)
				require.Len(t, vtxos, 2)
				require.NotNil(t, cursor)
				// Descending by created_at — first element is the newest.
				require.False(t, vtxos[0].CreatedAt.Before(vtxos[1].CreatedAt))
			})

			t.Run("cursor resumes correctly", func(t *testing.T) {
				vtxos, cursor, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusAll,
					Limit:  2,
				})
				require.NoError(t, err)
				require.NotNil(t, cursor)

				vtxos2, cursor2, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusAll,
					Limit:  2,
					After:  cursor,
				})
				require.NoError(t, err)
				require.NotEmpty(t, vtxos2)
				require.Nil(t, cursor2)

				// No overlap between page 1 and page 2.
				seen := map[clientTypes.Outpoint]bool{}
				for _, v := range vtxos {
					seen[v.Outpoint] = true
				}
				for _, v := range vtxos2 {
					require.False(t, seen[v.Outpoint])
				}
			})

			t.Run("limit larger than dataset returns nil Next", func(t *testing.T) {
				vtxos, cursor, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusAll,
					Limit:  1000,
				})
				require.NoError(t, err)
				require.Len(t, vtxos, len(seed))
				require.Nil(t, cursor)
			})

			t.Run("limit may change between pages", func(t *testing.T) {
				vtxos, cursor, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusAll,
					Limit:  1,
				})
				require.NoError(t, err)
				require.Len(t, vtxos, 1)
				require.NotNil(t, cursor)

				vtxos2, cursor2, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusAll,
					Limit:  1000,
					After:  cursor,
				})
				require.NoError(t, err)
				require.Len(t, vtxos2, len(seed)-1)
				require.Nil(t, cursor2)
			})

			t.Run("status filter spendable", func(t *testing.T) {
				// Spend two of the seeded VTXOs.
				require.NoError(t, s.Clean(ctx))
				seedVtxos(t, s, seed...)
				spendMap := map[clientTypes.Outpoint]string{
					seed[0].Outpoint: "spentby0",
					seed[1].Outpoint: "spentby1",
				}
				_, err := s.SpendVtxos(ctx, spendMap, "arktx-test")
				require.NoError(t, err)

				vtxos, _, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusSpendable,
					Limit:  1000,
				})
				require.NoError(t, err)
				for _, v := range vtxos {
					require.False(t, v.Spent)
					require.False(t, v.Unrolled)
				}
				require.Len(t, vtxos, len(seed)-2)
			})

			t.Run("status filter spent", func(t *testing.T) {
				vtxos, _, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusSpent,
					Limit:  1000,
				})
				require.NoError(t, err)
				require.Len(t, vtxos, 2)
				for _, v := range vtxos {
					require.True(t, v.Spent || v.Unrolled)
				}
			})

			t.Run("empty result has nil Next and empty slice", func(t *testing.T) {
				require.NoError(t, s.Clean(ctx))
				vtxos, cursor, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status: types.VtxoStatusAll,
					Limit:  10,
				})
				require.NoError(t, err)
				require.Empty(t, vtxos)
				require.Nil(t, cursor)
			})

			t.Run("WithAssetID filter semantics", func(t *testing.T) {
				require.NoError(t, s.Clean(ctx))
				// seed[2] has both assets; seed[3] has only asset1.
				seedVtxos(t, s, seed[2], seed[3])

				// Querying with asset1 should return both vtxos.
				vtxos, _, err := s.GetVtxos(ctx, types.GetVtxoFilter{
					Status:  types.VtxoStatusAll,
					AssetID: testVtxoAsset1.AssetId,
					Limit:   1000,
				})
				require.NoError(t, err)
				require.Len(t, vtxos, 2)

				// The multi-asset vtxo (seed[2]) still carries both assets.
				for _, v := range vtxos {
					if v.Outpoint == seed[2].Outpoint {
						require.Equal(t, seed[2].Assets, v.Assets)
						return
					}
				}
				require.Fail(t, "multi-asset vtxo not found in WithAssetID result")
			})

			t.Run("tiebreaker on identical created_at", func(t *testing.T) {
				// Seed N VTXOs with identical created_at and distinct
				// (txid, vout). Page through in small pages and assert that
				// every outpoint appears exactly once and the total count
				// matches.
				require.NoError(t, s.Clean(ctx))

				const n = 10
				sharedCreatedAt := time.Unix(base, 0)
				tieVtxos := make([]clientTypes.Vtxo, n)
				for i := range tieVtxos {
					// Distinct txid per row; vout always 0. Lex-distinct txids
					// give the (txid, vout) tiebreaker something to work with.
					txid := fmt.Sprintf(
						"%064x", i+1, // 64 hex chars = 32-byte txid
					)
					tieVtxos[i] = clientTypes.Vtxo{
						Outpoint: clientTypes.Outpoint{Txid: txid, VOut: 0},
						Script:   testVtxos[0].Script,
						Amount:   uint64(1000 + i),
						CommitmentTxids: []string{
							"0000000000000000000000000000000000000000000000000000000000000000",
						},
						CreatedAt: sharedCreatedAt,
						ExpiresAt: testVtxos[0].ExpiresAt,
					}
				}
				seedVtxos(t, s, tieVtxos...)

				seen := make(map[clientTypes.Outpoint]int, n)
				var cursor *types.Cursor
				pages := 0
				for {
					pages++
					require.Less(t, pages, n+2, "pagination did not terminate")

					vtxos, next, err := s.GetVtxos(ctx, types.GetVtxoFilter{
						Status: types.VtxoStatusAll,
						Limit:  3, // small page so we exercise multiple cursor hops
						After:  cursor,
					})
					require.NoError(t, err)
					for _, v := range vtxos {
						seen[v.Outpoint]++
					}
					if next == nil {
						break
					}
					cursor = next
				}

				require.Len(t, seen, n, "expected exactly %d distinct outpoints", n)
				for op, count := range seen {
					require.Equal(t, 1, count, "outpoint %v seen %d times (want 1)", op, count)
				}
			})
		})
	})
}

func TestVtxoStoreClean(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()

			t.Run("empty store", func(t *testing.T) {
				require.NoError(t, s.Clean(ctx))
			})

			t.Run("non-empty store data is removed", func(t *testing.T) {
				seedVtxos(t, s, testVtxos...)

				got, err := s.GetSpendableOrRecoverableVtxos(ctx)
				require.NoError(t, err)
				require.NotEmpty(t, got)

				require.NoError(t, s.Clean(ctx))

				got, err = s.GetSpendableOrRecoverableVtxos(ctx)
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("clean is idempotent", func(t *testing.T) {
				require.NoError(t, s.Clean(ctx))
				got, err := s.GetSpendableOrRecoverableVtxos(ctx)
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("reseed after clean works correctly", func(t *testing.T) {
				seedVtxos(t, s, testVtxos...)
				require.NoError(t, s.Clean(ctx))

				// Re-seeding the same vtxos must not collide with leftover state.
				seedVtxos(t, s, testVtxos...)
				got, err := s.GetSpendableOrRecoverableVtxos(ctx)
				require.NoError(t, err)
				require.Len(t, got, len(testVtxos))
			})
		})
	})
}

func TestVtxoStoreGetEventChannel(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachVtxoBackend(t, func(t *testing.T, s types.VtxoStore) {
			ctx := t.Context()
			timeout := time.Second

			ch := s.GetEventChannel()
			require.NotNil(t, ch)

			drainEvent := func(t *testing.T, wantType types.VtxoEventType) types.VtxoEvent {
				t.Helper()
				select {
				case ev := <-ch:
					require.Equal(t, wantType, ev.Type)
					return ev
				case <-time.After(timeout):
					t.Fatalf("timed out waiting for event %s", wantType)
					return types.VtxoEvent{}
				}
			}

			t.Run("AddVtxos emits VtxosAdded", func(t *testing.T) {
				n, err := s.AddVtxos(ctx, testVtxos)
				require.NoError(t, err)
				require.Equal(t, len(testVtxos), n)

				ev := drainEvent(t, types.VtxosAdded)
				require.Len(t, ev.Vtxos, len(testVtxos))
			})

			t.Run("SpendVtxos emits VtxosSpent", func(t *testing.T) {
				_, err := s.SpendVtxos(ctx, testSpendVtxoKeys, arkTxid)
				require.NoError(t, err)

				ev := drainEvent(t, types.VtxosSpent)
				require.Len(t, ev.Vtxos, len(testSpendVtxoKeys))
			})

			t.Run("SettleVtxos emits VtxoSettled", func(t *testing.T) {
				_, err := s.SettleVtxos(ctx, testSettleVtxoKeys, settledBy)
				require.NoError(t, err)

				ev := drainEvent(t, types.VtxoSettled)
				require.Len(t, ev.Vtxos, len(testSettleVtxoKeys))
			})

			t.Run("SweepVtxos emits VtxosSwept", func(t *testing.T) {
				toSweep := []clientTypes.Vtxo{testVtxos[2]}
				_, err := s.SweepVtxos(ctx, toSweep)
				require.NoError(t, err)

				ev := drainEvent(t, types.VtxosSwept)
				require.Len(t, ev.Vtxos, 1)
			})

			t.Run("UnrollVtxos emits VtxosUnrolled", func(t *testing.T) {
				toUnroll := []clientTypes.Vtxo{testVtxos[3]}
				_, err := s.UnrollVtxos(ctx, toUnroll)
				require.NoError(t, err)

				ev := drainEvent(t, types.VtxosUnrolled)
				require.Len(t, ev.Vtxos, 1)
			})
		})
	})
}
