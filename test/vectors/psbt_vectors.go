package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

const ()

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func mockVtxo(amount uint64, assets []types.Asset) client.TapscriptsVtxo {
	privKey, err := btcec.NewPrivateKey()
	check(err)
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
	check(err)

	vtxoTapKey, _, err := vtxoScript.TapTree()
	check(err)

	p2tr, err := script.P2TRScript(vtxoTapKey)
	check(err)

	return client.TapscriptsVtxo{
		Vtxo: types.Vtxo{
			Outpoint: types.Outpoint{
				Txid: randomTxID(),
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

func SignerUnrollScript() ([]byte, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	signerPub := privKey.PubKey()
	// 144 blocks ~ 24 hours
	locktime := uint(144)

	builder := txscript.NewScriptBuilder()
	builder.AddInt64(int64(locktime))
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP)
	builder.AddData(schnorr.SerializePubKey(signerPub))
	builder.AddOp(txscript.OP_CHECKSIG)
	return builder.Script()
}

func generateArkAddress() string {
	privKey, err := btcec.NewPrivateKey()
	check(err)
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
	check(err)

	addr := &arklib.Address{
		HRP:        "tark",
		Signer:     serverPub,
		VtxoTapKey: vtxoTapKey,
	}

	encoded, err := addr.EncodeV0()
	check(err)
	return encoded
}

func randomTxID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	check(err)
	return hex.EncodeToString(b)
}

func to32Byte(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

type PsbtVector struct {
	Type        string      `json:"type"`
	Psbt        string      `json:"psbt"`
	AssetPacket interface{} `json:"asset_packet"`
}

// Custom structs for hex-encoding TxIDs in JSON
type vectorExtensionPacket struct {
	Asset   *vectorAssetPacket       `json:"Asset,omitempty"`
	SubDust *extension.SubDustPacket `json:"SubDust,omitempty"`
}

type vectorAssetPacket struct {
	Assets  []vectorAssetGroup `json:"Assets"`
	Version uint8              `json:"Version"`
}

type vectorAssetGroup struct {
	AssetId      *vectorAssetId          `json:"AssetId,omitempty"`
	Outputs      []extension.AssetOutput `json:"Outputs"`
	Inputs       []vectorAssetInput      `json:"Inputs"`
	ControlAsset *vectorAssetRef         `json:"ControlAsset,omitempty"`
	Metadata     []extension.Metadata    `json:"Metadata,omitempty"`
}

type vectorAssetId struct {
	Txid  string `json:"Txid"`
	Index uint16 `json:"Index"`
}

type vectorAssetInput struct {
	Type   extension.AssetType `json:"Type"`
	Vin    uint32              `json:"Vin"`
	Amount uint64              `json:"Amount"`
}

type vectorAssetRef struct {
	Type       extension.AssetRefType `json:"Type"`
	AssetId    *vectorAssetId         `json:"AssetId,omitempty"`
	GroupIndex uint16                 `json:"GroupIndex,omitempty"`
}

func toHexPacket(p *extension.ExtensionPacket) *vectorExtensionPacket {
	if p == nil {
		return nil
	}
	out := &vectorExtensionPacket{
		SubDust: p.SubDust,
	}
	if p.Asset != nil {
		out.Asset = &vectorAssetPacket{
			Version: p.Asset.Version,
		}
		for _, ag := range p.Asset.Assets {
			vag := vectorAssetGroup{
				Outputs:  ag.Outputs,
				Metadata: ag.Metadata,
			}
			if ag.AssetId != nil {
				vag.AssetId = &vectorAssetId{
					Txid:  hex.EncodeToString(ag.AssetId.Txid[:]),
					Index: ag.AssetId.Index,
				}
			}
			if ag.ControlAsset != nil {
				vag.ControlAsset = &vectorAssetRef{
					Type:       ag.ControlAsset.Type,
					GroupIndex: ag.ControlAsset.GroupIndex,
				}
				if ag.ControlAsset.AssetId.Txid != [32]byte{} {
					vag.ControlAsset.AssetId = &vectorAssetId{
						Txid:  hex.EncodeToString(ag.ControlAsset.AssetId.Txid[:]),
						Index: ag.ControlAsset.AssetId.Index,
					}
				}
			}
			for _, inp := range ag.Inputs {
				vag.Inputs = append(vag.Inputs, vectorAssetInput{
					Type:   inp.Type,
					Vin:    inp.Vin,
					Amount: inp.Amount,
				})
			}
			out.Asset.Assets = append(out.Asset.Assets, vag)
		}
	}
	return out
}

func main() {
	var vectors []PsbtVector

	addVector := func(name string, content string, packet interface{}) {
		extPacket, ok := packet.(*extension.ExtensionPacket)
		var jsonPacket interface{} = packet
		if ok {
			jsonPacket = toHexPacket(extPacket)
		}

		vectors = append(vectors, PsbtVector{
			Type:        name,
			Psbt:        content,
			AssetPacket: jsonPacket,
		})
	}

	defer func() {
		data, err := json.MarshalIndent(vectors, "", "  ")
		check(err)
		err = os.WriteFile("psbt_vectors.json", data, 0644)
		check(err)
		fmt.Printf("Wrote %d vectors to psbt_vectors.json\n", len(vectors))
	}()

	// 1. Issuance with New Control Asset
	{
		changeAddr := generateArkAddress()
		vtxos := []client.TapscriptsVtxo{
			mockVtxo(10000, nil),
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

		// New Control Asset

		controlReceivers := []types.Receiver{
			{To: changeAddr, Amount: 1000},
		}

		// OpType Issuance
		idx, err := builder.InsertAssetGroup("", receivers, arksdk.AssetGroupIssuance)
		check(err)

		// Create Control Asset
		controlIdx, err := builder.InsertAssetGroup("", controlReceivers, arksdk.AssetGroupIssuance)
		check(err)

		controlAsset := extension.AssetRef{
			Type:       extension.AssetRefByGroup,
			GroupIndex: uint16(controlIdx),
		}

		err = builder.InsertIssuance(idx, &controlAsset)
		check(err)

		err = builder.InsertMetadata(idx, map[string]string{
			"name":     "Arkade Token",
			"symbol":   "ARKD",
			"decimals": "18",
		})
		check(err)

		// Existing Control Asset
		assetID := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		controlAsset = extension.AssetRef{
			Type:    extension.AssetRefByID,
			AssetId: assetID,
		}

		idx, err = builder.InsertAssetGroup("", receivers, arksdk.AssetGroupIssuance)
		check(err)

		err = builder.InsertIssuance(idx, &controlAsset)
		check(err)

		err = builder.AddSatsInputs(546)
		check(err)

		signerUnrollScript, err := SignerUnrollScript()
		check(err)

		arkTx, _, err := builder.Build(signerUnrollScript)
		check(err)

		addVector("issuance", arkTx, builder.GetExtensionPacket())
	}

	// 2. Transfer
	{
		changeAddr := generateArkAddress()
		recevierAddr := generateArkAddress()
		recevierAddr2 := generateArkAddress()

		asset1 := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		asset2 := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(10000, nil),
			mockVtxo(10000, []types.Asset{
				{
					AssetId: asset1.ToString(),
					Amount:  1000,
				},
			}),
			mockVtxo(10000, []types.Asset{
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
		check(err)

		_, err = builder.InsertAssetGroup(asset2.String(), []types.Receiver{
			{To: recevierAddr, Amount: 200},
			{To: recevierAddr2, Amount: 200},
		}, arksdk.AssetGroupTransfer)
		check(err)

		err = builder.AddSatsInputs(546)
		check(err)

		signerUnrollScript, err := SignerUnrollScript()
		check(err)

		arkTx, _, err := builder.Build(signerUnrollScript)
		check(err)

		addVector("transfers", arkTx, builder.GetExtensionPacket())
	}

	// 3. Reissue of assets
	{
		changeAddr := generateArkAddress()
		changeAddr2 := generateArkAddress()

		asset1 := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		controlAsset := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(10000, nil),
			mockVtxo(10000, []types.Asset{
				{
					AssetId: asset1.ToString(),
					Amount:  1000,
				},
			}),
			mockVtxo(10000, []types.Asset{
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
		check(err)

		// insert control asset
		_, err = builder.InsertAssetGroup(controlAsset.String(), []types.Receiver{
			{To: changeAddr, Amount: 200},
			{To: changeAddr2, Amount: 200},
		}, arksdk.AssetGroupIssuance)
		check(err)

		err = builder.AddSatsInputs(546)
		check(err)

		signerUnrollScript, err := SignerUnrollScript()
		check(err)

		arkTx, _, err := builder.Build(signerUnrollScript)
		check(err)

		addVector("reissue_assets", arkTx, builder.GetExtensionPacket())
	}

	// Burn Asset
	{
		changeAddr := generateArkAddress()
		asset1 := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(10000, nil),
			mockVtxo(10000, []types.Asset{
				{
					AssetId: asset1.ToString(),
					Amount:  1000,
				},
			}),
		}

		builder := arksdk.NewAssetTxBuilder(vtxos, false, changeAddr, 546)

		_, err := builder.InsertAssetGroup(asset1.String(), []types.Receiver{
			{To: changeAddr, Amount: 200},
		}, arksdk.AssetGroupIssuance)
		check(err)

		// insert control asset
		_, err = builder.InsertAssetGroup(asset1.String(), []types.Receiver{
			{To: changeAddr, Amount: 200},
		}, arksdk.AssetGroupBurn)
		check(err)

		err = builder.AddSatsInputs(546)
		check(err)

		signerUnrollScript, err := SignerUnrollScript()
		check(err)

		arkTx, _, err := builder.Build(signerUnrollScript)
		check(err)

		addVector("burn_asset", arkTx, builder.GetExtensionPacket())
	}

	// Mix Issuance and Transfer
	{
		changeAddr := generateArkAddress()
		receiverAddr := generateArkAddress()

		// Existing asset to transfer
		asset1 := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(10000, nil),
			mockVtxo(10000, []types.Asset{
				{
					AssetId: asset1.ToString(),
					Amount:  10000,
				},
			}),
		}

		builder := arksdk.NewAssetTxBuilder(vtxos, false, changeAddr, 546)

		// 1. Issuance
		issuanceReceivers := []types.Receiver{
			{To: changeAddr, Amount: 1000},
		}
		// Control Asset for issuance
		controlReceivers := []types.Receiver{
			{To: changeAddr, Amount: 1000},
		}

		idx, err := builder.InsertAssetGroup("", issuanceReceivers, arksdk.AssetGroupIssuance)
		check(err)

		controlIdx, err := builder.InsertAssetGroup("", controlReceivers, arksdk.AssetGroupIssuance)
		check(err)

		controlAsset := extension.AssetRef{
			Type:       extension.AssetRefByGroup,
			GroupIndex: uint16(controlIdx),
		}

		err = builder.InsertIssuance(idx, &controlAsset)
		check(err)

		err = builder.InsertMetadata(idx, map[string]string{
			"name": "Mixed Asset",
		})
		check(err)

		// 2. Transfer
		_, err = builder.InsertAssetGroup(asset1.String(), []types.Receiver{
			{To: receiverAddr, Amount: 500},
		}, arksdk.AssetGroupTransfer)
		check(err)

		err = builder.AddSatsInputs(546)
		check(err)

		signerUnrollScript, err := SignerUnrollScript()
		check(err)

		arkTx, _, err := builder.Build(signerUnrollScript)
		check(err)

		addVector("mix_issuance_transfer", arkTx, builder.GetExtensionPacket())
	}

	// Mix All Operations: Issuance, Transfer, Reissue, Burn
	{
		changeAddr := generateArkAddress()
		receiverAddr := generateArkAddress()

		// 1. Asset for Transfer
		assetTransfer := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		// 2. Control Asset for Reissue (must exist as VTXO)
		assetReissueControl := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		assetReissueTarget := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 2,
		}

		// 3. Asset for Burn
		assetBurn := extension.AssetId{
			Txid:  to32Byte(randomTxID()),
			Index: 1,
		}

		vtxos := []client.TapscriptsVtxo{
			mockVtxo(10000, nil), // Sats
			mockVtxo(10000, []types.Asset{
				{AssetId: assetTransfer.ToString(), Amount: 1000},
			}),
			mockVtxo(10000, []types.Asset{
				{AssetId: assetReissueControl.ToString(), Amount: 1},
			}),
			mockVtxo(10000, []types.Asset{
				{AssetId: assetBurn.ToString(), Amount: 1000},
			}),
		}

		builder := arksdk.NewAssetTxBuilder(vtxos, false, changeAddr, 546)

		// --- Operation A: Issuance (New Asset) ---
		issuanceReceivers := []types.Receiver{{To: receiverAddr, Amount: 100}}
		newAssetControlReceivers := []types.Receiver{{To: changeAddr, Amount: 1}}

		idxIssuance, err := builder.InsertAssetGroup("", issuanceReceivers, arksdk.AssetGroupIssuance)
		check(err)

		idxNewControl, err := builder.InsertAssetGroup("", newAssetControlReceivers, arksdk.AssetGroupIssuance)
		check(err)

		// Link New Asset to New Control Asset (AssetRefByGroup)
		err = builder.InsertIssuance(idxIssuance, &extension.AssetRef{
			Type:       extension.AssetRefByGroup,
			GroupIndex: uint16(idxNewControl),
		})
		check(err)

		err = builder.InsertMetadata(idxIssuance, map[string]string{"name": "New Issuance Asset"})
		check(err)

		err = builder.InsertMetadata(idxNewControl, map[string]string{"name": "New Control Asset"})
		check(err)

		// --- Operation B: Transfer ---
		_, err = builder.InsertAssetGroup(assetTransfer.String(), []types.Receiver{
			{To: receiverAddr, Amount: 500},
		}, arksdk.AssetGroupTransfer)
		check(err)

		// --- Operation C: Reissue ---
		// We issue 'assetReissueTarget'
		idxReissue, err := builder.InsertAssetGroup(assetReissueTarget.String(), []types.Receiver{
			{To: receiverAddr, Amount: 200},
		}, arksdk.AssetGroupIssuance)
		check(err)

		_, err = builder.InsertAssetGroup(assetReissueControl.String(), []types.Receiver{
			{To: changeAddr, Amount: 1},
		}, arksdk.AssetGroupTransfer)
		check(err)

		// Link Reissue to Existing Control Asset (AssetRefByID)
		err = builder.InsertIssuance(idxReissue, &extension.AssetRef{
			Type:    extension.AssetRefByID,
			AssetId: assetReissueControl,
		})
		check(err)

		// --- Operation D: Burn ---
		_, err = builder.InsertAssetGroup(assetBurn.String(), []types.Receiver{}, arksdk.AssetGroupBurn)
		check(err)

		// Finalize
		err = builder.AddSatsInputs(546)
		check(err)

		signerUnrollScript, err := SignerUnrollScript()
		check(err)

		arkTx, _, err := builder.Build(signerUnrollScript)
		check(err)

		addVector("mix_all_ops", arkTx, builder.GetExtensionPacket())
	}

}
