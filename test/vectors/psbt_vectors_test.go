package vectors

import (
	"encoding/hex" // Standard library first
	"os"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	dummyTxID = "0000000000000000000000000000000000000000000000000000000000000001"
)

func mockVtxo(t *testing.T, amount uint64, assets []types.Asset) client.TapscriptsVtxo {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey()

	serverPriv, _ := btcec.NewPrivateKey()
	serverPub := serverPriv.PubKey()

	vtxoScript := script.NewDefaultVtxoScript(
		pubKey,
		serverPub,
		arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 51200,
		},
	)
	tapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)

	vtxoTapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)

	p2tr, err := script.P2TRScript(vtxoTapKey)
	require.NoError(t, err)

	return client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: dummyTxID,
				VOut: 0,
			},
			Amount:    amount,
			Assets:    assets,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
			Script:    hex.EncodeToString(p2tr),
		},
		Tapscripts: tapscripts,
	}
}

// TODO: Implement real creation of signer unroll script
func mockSignerUnrollScript() []byte {
	return []byte("mockSignerUnrollScript")
}

func generateArkAddress(t *testing.T) string {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey()

	serverPriv, _ := btcec.NewPrivateKey()
	serverPub := serverPriv.PubKey()

	vtxoScript := script.NewDefaultVtxoScript(
		pubKey,
		serverPub,
		arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 51200,
		},
	)
	vtxoTapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)

	addr := &arklib.Address{
		HRP:        "tark",
		Signer:     serverPub,
		VtxoTapKey: vtxoTapKey,
	}

	encoded, err := addr.EncodeV0()
	require.NoError(t, err)
	return encoded
}

func hexTo32Byte(t *testing.T, s string) [32]byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	var arr [32]byte
	copy(arr[:], b)
	return arr
}

func writeToFile(t *testing.T, name string, content string) {
	err := os.WriteFile(name+".psbt", []byte(content), 0644)
	require.NoError(t, err)
	t.Logf("Wrote PSBT to %s.psbt", name)
}

func TestPSBT_Vectors(t *testing.T) {
	// 1. Issuance with New Control Asset
	t.Run("Issuance_NewControlAsset", func(t *testing.T) {
		changeAddr := generateArkAddress(t)
		vtxos := []client.TapscriptsVtxo{
			mockVtxo(t, 10000, nil),
		}

		builder := arksdk.NewAssetTxBuilder(
			vtxos,
			false,
			changeAddr,
			546,
		)

		receivers := []types.Receiver{
			{To: changeAddr, Amount: 1000},
		}

		controlReceivers := []types.Receiver{
			{To: changeAddr, Amount: 1000},
		}

		// OpType Issuance
		idx, err := builder.InsertAssetGroup("", receivers, arksdk.AssetGroupIssuance)
		require.NoError(t, err)

		// Create Control Asset
		controlIdx, err := builder.InsertAssetGroup("", controlReceivers, arksdk.AssetGroupIssuance)
		require.NoError(t, err)

		controlAsset := extension.AssetRef{
			Type:       extension.AssetRefByGroup,
			GroupIndex: uint16(controlIdx),
		}

		err = builder.InsertIssuance(idx, &controlAsset, true)
		require.NoError(t, err)

		err = builder.InsertMetadata(idx, map[string]string{
			"name":     "Arkade Token",
			"symbol":   "ARKD",
			"decimals": "18",
		})
		require.NoError(t, err)

		err = builder.AddSatsInputs(546)
		require.NoError(t, err)

		arkTx, _, err := builder.Build(nil)
		require.NoError(t, err)

		writeToFile(t, "issuance_new_control_asset", arkTx)
	})

	// 2. Issuance with Existing Control Asset
	t.Run("Issuance_ExistingControlAsset", func(t *testing.T) {
		changeAddr := generateArkAddress(t)
		vtxos := []client.TapscriptsVtxo{
			mockVtxo(t, 10000, nil),
		}

		builder := arksdk.NewAssetTxBuilder(vtxos, false, changeAddr, 546)

		receivers := []types.Receiver{
			{To: changeAddr, Amount: 1000},
		}

		idx, err := builder.InsertAssetGroup("", receivers, arksdk.AssetGroupIssuance)
		require.NoError(t, err)

		assetID := extension.AssetId{
			Txid:  hexTo32Byte(t, dummyTxID),
			Index: 1,
		}

		controlAsset := extension.AssetRef{
			Type:    extension.AssetRefByID,
			AssetId: assetID,
		}

		err = builder.InsertIssuance(idx, &controlAsset, true)
		require.NoError(t, err)

		err = builder.InsertMetadata(idx, map[string]string{
			"name":     "Arkade Token",
			"symbol":   "ARKD",
			"decimals": "18",
		})
		require.NoError(t, err)

		err = builder.AddSatsInputs(546)
		require.NoError(t, err)

		arkTx, _, err := builder.Build(nil)
		require.NoError(t, err)

		writeToFile(t, "issuance_existing_control_asset", arkTx)
	})

	// 3. Transfer Of Mutliple Assets
	t.Run("Transfer_MultipleAssets", func(t *testing.T) {
		changeAddr := generateArkAddress(t)
		recevierAddr := generateArkAddress(t)
		recevierAddr2 := generateArkAddress(t)

		asset1 := extension.AssetId{
			Txid:  hexTo32Byte(t, "asset 1 txid"),
			Index: 1,
		}

		asset2 := extension.AssetId{
			Txid:  hexTo32Byte(t, "asset 2 txid"),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(t, 10000, nil),
			mockVtxo(t, 10000, []types.Asset{
				{
					AssetId: asset1.ToString(),
					Amount:  1000,
				},
			}),
			mockVtxo(t, 10000, []types.Asset{
				{
					AssetId: asset2.ToString(),
					Amount:  1000,
				},
			}),
		}

		builder := arksdk.NewAssetTxBuilder(vtxos, false, changeAddr, 546)

		_, err := builder.InsertAssetGroup(asset1.String(), []types.Receiver{
			{To: recevierAddr, Amount: 200},
			{To: recevierAddr2, Amount: 200},
		}, arksdk.AssetGroupTransfer)

		require.NoError(t, err)

		_, err = builder.InsertAssetGroup(asset2.String(), []types.Receiver{
			{To: recevierAddr, Amount: 200},
			{To: recevierAddr2, Amount: 200},
		}, arksdk.AssetGroupTransfer)

		require.NoError(t, err)

		err = builder.AddSatsInputs(546)
		require.NoError(t, err)

		arkTx, _, err := builder.Build(nil)
		require.NoError(t, err)

		writeToFile(t, "transfer_multiple_assets", arkTx)
	})

	// 4. Reissue of assets
	t.Run("Reissue_Assets", func(t *testing.T) {
		changeAddr := generateArkAddress(t)
		changeAddr2 := generateArkAddress(t)

		asset1 := extension.AssetId{
			Txid:  hexTo32Byte(t, "asset 1 txid"),
			Index: 1,
		}

		controlAsset := extension.AssetId{
			Txid:  hexTo32Byte(t, "control asset txid"),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(t, 10000, nil),
			mockVtxo(t, 10000, []types.Asset{
				{
					AssetId: asset1.ToString(),
					Amount:  1000,
				},
			}),
			mockVtxo(t, 10000, []types.Asset{
				{
					AssetId: controlAsset.ToString(),
					Amount:  1000,
				},
			}),
		}

		builder := arksdk.NewAssetTxBuilder(vtxos, false, changeAddr, 546)

		_, err := builder.InsertAssetGroup(asset1.String(), []types.Receiver{
			{To: changeAddr, Amount: 200},
			{To: changeAddr2, Amount: 200},
		}, arksdk.AssetGroupIssuance)

		require.NoError(t, err)

		// insert control asset
		_, err = builder.InsertAssetGroup(controlAsset.String(), []types.Receiver{
			{To: changeAddr, Amount: 200},
			{To: changeAddr2, Amount: 200},
		}, arksdk.AssetGroupIssuance)

		require.NoError(t, err)

		err = builder.AddSatsInputs(546)
		require.NoError(t, err)

		arkTx, _, err := builder.Build(nil)
		require.NoError(t, err)

		writeToFile(t, "reissue_assets", arkTx)
	})

	// 5. Reissue of assets with metadata
	t.Run("Reissue_Assets_With_Metadata", func(t *testing.T) {
		changeAddr := generateArkAddress(t)
		changeAddr2 := generateArkAddress(t)

		asset1 := extension.AssetId{
			Txid:  hexTo32Byte(t, "asset 1 txid"),
			Index: 1,
		}

		controlAsset := extension.AssetId{
			Txid:  hexTo32Byte(t, "control asset txid"),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(t, 10000, nil),
			mockVtxo(t, 10000, []types.Asset{
				{
					AssetId: asset1.ToString(),
					Amount:  1000,
				},
			}),
			mockVtxo(t, 10000, []types.Asset{
				{
					AssetId: controlAsset.ToString(),
					Amount:  1000,
				},
			}),
		}

		builder := arksdk.NewAssetTxBuilder(vtxos, false, changeAddr, 546)

		idx, err := builder.InsertAssetGroup(asset1.String(), []types.Receiver{
			{To: changeAddr, Amount: 200},
			{To: changeAddr2, Amount: 200},
		}, arksdk.AssetGroupIssuance)

		require.NoError(t, err)

		err = builder.InsertMetadata(idx, map[string]string{
			"name":     "Arkade Token",
			"symbol":   "ARKD",
			"decimals": "18",
		})

		require.NoError(t, err)

		err = builder.AddSatsInputs(546)
		require.NoError(t, err)

		arkTx, _, err := builder.Build(nil)
		require.NoError(t, err)

		writeToFile(t, "reissue_assets_with_metadata", arkTx)
	})
}
