package arksdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/note"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/lntypes"
)

type arkTxInput struct {
	client.TapscriptsVtxo
	ForfeitLeafHash chainhash.Hash
}

func validateReceivers(
	network arklib.Network, ptx *psbt.Packet, receivers []types.Receiver, vtxoTree *tree.TxTree,
) error {
	netParams := utils.ToBitcoinNetwork(network)
	for _, receiver := range receivers {
		isOnChain, onchainScript, err := utils.ParseBitcoinAddress(receiver.To, netParams)
		if err != nil {
			return fmt.Errorf("invalid receiver address: %s err = %s", receiver.To, err)
		}

		if isOnChain {
			if err := validateOnchainReceiver(ptx, receiver, onchainScript); err != nil {
				return err
			}
		} else {
			if err := validateOffchainReceiver(vtxoTree, receiver); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateOnchainReceiver(
	ptx *psbt.Packet, receiver types.Receiver, onchainScript []byte,
) error {
	found := false
	for _, output := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(output.PkScript, onchainScript) {
			if output.Value != int64(receiver.Amount) {
				return fmt.Errorf(
					"invalid collaborative exit output amount: got %d, want %d",
					output.Value, receiver.Amount,
				)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("collaborative exit output not found: %s", receiver.To)
	}
	return nil
}

func validateOffchainReceiver(vtxoTree *tree.TxTree, receiver types.Receiver) error {
	found := false

	rcvAddr, err := arklib.DecodeAddressV0(receiver.To)
	if err != nil {
		return err
	}

	vtxoTapKey := schnorr.SerializePubKey(rcvAddr.VtxoTapKey)

	leaves := vtxoTree.Leaves()
	for _, leaf := range leaves {
		for _, output := range leaf.UnsignedTx.TxOut {
			if len(output.PkScript) == 0 {
				continue
			}

			if bytes.Equal(output.PkScript[2:], vtxoTapKey) {
				if output.Value != int64(receiver.Amount) {
					continue
				}

				found = true
				break
			}
		}

		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf("offchain send output not found: %s", receiver.To)
	}

	return nil
}

func buildTeleportClaimTx(
	vtxos []arkTxInput, nonce [32]byte, receiver types.TeleportReceiver, otherReceivers []types.Receiver, serverUnrollScript []byte,
	dustLimit uint64,
) (string, []string, *asset.AssetPacket, error) {
	if len(vtxos) <= 0 {
		return "", nil, nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(vtxos))
	for _, vtxo := range vtxos {
		in, err := createVtxoTxInput(vtxo)
		if err != nil {
			return "", nil, nil, err
		}

		ins = append(ins, *in)
	}

	outs := make([]*wire.TxOut, 0)

	sealAddr, err := arklib.DecodeAddressV0(receiver.ClaimAddress)
	if err != nil {
		return "", nil, nil, err
	}

	sealAddrScript, err := script.P2TRScript(sealAddr.VtxoTapKey)
	if err != nil {
		return "", nil, nil, err
	}

	outs = append(outs, &wire.TxOut{
		Value:    int64(dustLimit),
		PkScript: sealAddrScript,
	})

	assetOutputs := []asset.AssetOutput{{
		Type:   asset.AssetTypeLocal,
		Amount: receiver.AssetAmount,
		Vout:   uint16(0),
	}}

	decodedTeleportHash, err := hex.DecodeString(receiver.TeleportHash)
	if err != nil {
		return "", nil, nil, err
	}

	decodedAddr, err := arklib.DecodeAddressV0(receiver.ClaimAddress)
	if err != nil {
		return "", nil, nil, err
	}

	teleportScript, err := script.P2TRScript(decodedAddr.VtxoTapKey)
	if err != nil {
		return "", nil, nil, err
	}

	var teleportByte [32]byte
	copy(teleportByte[:], decodedTeleportHash)

	assetInputs := []asset.AssetInput{{
		Type:       asset.AssetTypeTeleport,
		Amount:     receiver.AssetAmount,
		Commitment: teleportByte,
		Witness: asset.TeleportWitness{
			Script: teleportScript,
			Nonce:  nonce,
		},
	}}

	decodedAssetId, err := asset.AssetIdFromString(receiver.AssetId)
	if err != nil {
		return "", nil, nil, err
	}

	normalAsset := asset.AssetGroup{
		AssetId: *decodedAssetId,
		Outputs: assetOutputs,
		Inputs:  assetInputs,
	}

	assetGroup := asset.AssetPacket{
		NormalAssets: []asset.AssetGroup{normalAsset},
	}

	// exclude SubDust receiver from other receivers
	var subdustReceiver *types.Receiver

	for i, receiver := range otherReceivers {
		if receiver.Amount < dustLimit {
			// copy value to avoid aliasing issues
			r := receiver
			subdustReceiver = &r

			// remove from slice
			otherReceivers = append(otherReceivers[:i], otherReceivers[i+1:]...)
			break
		}
	}

	var assetOpretOut wire.TxOut

	if subdustReceiver != nil {
		addr, err := arklib.DecodeAddressV0(subdustReceiver.To)
		if err != nil {
			return "", nil, nil, err
		}
		assetGroup.SubDustKey = addr.VtxoTapKey

		assetOpretOut, err = assetGroup.EncodeOpret(int64(subdustReceiver.Amount))
		if err != nil {
			return "", nil, nil, err
		}

	} else {

		assetOpretOut, err = assetGroup.EncodeOpret(0)
		if err != nil {
			return "", nil, nil, err
		}

	}

	outs = append(outs, &assetOpretOut)

	assetAnchorIndex := len(outs) - 1

	for _, receiver := range otherReceivers {
		changeAddr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, err
		}

		changeAddrScript, err := script.P2TRScript(changeAddr.VtxoTapKey)
		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: changeAddrScript,
		})

	}

	arkPtx, checkpointPtxs, err := offchain.BuildAssetTxs(outs, assetAnchorIndex, ins, serverUnrollScript)
	if err != nil {
		return "", nil, nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, nil, err
	}

	checkpointTxs := make([]string, 0, len(checkpointPtxs))
	for _, ptx := range checkpointPtxs {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", nil, nil, err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	return arkTx, checkpointTxs, &assetGroup, nil

}

func buildAssetCreationTx(
	vtxos []arkTxInput, assetRequests []types.AssetCreationRequest, otherReceivers []types.Receiver, serverUnrollScript []byte,
	dustLimit uint64,
) (string, []string, *asset.AssetPacket, error) {

	if len(vtxos) <= 0 {
		return "", nil, nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(vtxos))
	for _, vtxo := range vtxos {
		in, err := createVtxoTxInput(vtxo)
		if err != nil {
			return "", nil, nil, err
		}

		ins = append(ins, *in)
	}

	outs := make([]*wire.TxOut, 0)
	normalAssets := make([]asset.AssetGroup, 0, len(assetRequests))

	var globalVoutIndex uint16 = 0

	for i, request := range assetRequests {
		assetOutputs := make([]asset.AssetOutput, 0)
		var controlAssetId *asset.AssetId
		var err error

		if request.Params.ControlAssetId != "" {
			controlAssetId, err = asset.AssetIdFromString(request.Params.ControlAssetId)
			if err != nil {
				return "", nil, nil, err
			}
		}

		for _, assetReceiver := range request.Receivers {
			sealAddr, err := arklib.DecodeAddressV0(assetReceiver.To)
			if err != nil {
				return "", nil, nil, err
			}

			sealAddrScript, err := script.P2TRScript(sealAddr.VtxoTapKey)
			if err != nil {
				return "", nil, nil, err
			}

			outs = append(outs, &wire.TxOut{
				Value:    int64(dustLimit),
				PkScript: sealAddrScript,
			})

			assetOutputs = append(assetOutputs, asset.AssetOutput{
				Type:   asset.AssetTypeLocal,
				Amount: assetReceiver.Amount,
				Vout:   globalVoutIndex,
			})
			globalVoutIndex++
		}

		assetMetadata := toAssetMetadataList(request.Params.MetadataMap)

		assetIdBase := ins[0].Outpoint.Hash
		var assetIdBaseByte [32]byte
		copy(assetIdBaseByte[:], assetIdBase[:])

		assetDetails := asset.AssetGroup{
			AssetId: asset.AssetId{
				TxId:  assetIdBase,
				Index: uint16(i),
			},
			Outputs:        assetOutputs,
			ControlAssetId: controlAssetId,
			Inputs:         []asset.AssetInput{},
			Metadata:       assetMetadata,
			Immutable:      request.Params.Immutable,
			Version:        asset.AssetVersion,
			Magic:          asset.AssetMagic,
		}
		normalAssets = append(normalAssets, assetDetails)
	}

	assetGroup := asset.AssetPacket{
		NormalAssets: normalAssets,
	}

	// exclude SubDust receiver from other receivers
	var subdustReceiver *types.Receiver

	for i, receiver := range otherReceivers {
		if receiver.Amount < dustLimit {
			// copy value to avoid aliasing issues
			r := receiver
			subdustReceiver = &r

			// remove from slice
			otherReceivers = append(otherReceivers[:i], otherReceivers[i+1:]...)
			break
		}
	}

	var assetOpretOut wire.TxOut
	var err error

	if subdustReceiver != nil {
		addr, err := arklib.DecodeAddressV0(subdustReceiver.To)
		if err != nil {
			return "", nil, nil, err
		}
		assetGroup.SubDustKey = addr.VtxoTapKey

		assetOpretOut, err = assetGroup.EncodeOpret(int64(subdustReceiver.Amount))
		if err != nil {
			return "", nil, nil, err
		}

	} else {

		assetOpretOut, err = assetGroup.EncodeOpret(0)
		if err != nil {
			return "", nil, nil, err
		}

	}

	outs = append(outs, &assetOpretOut)

	for _, receiver := range otherReceivers {
		changeAddr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, err
		}

		changeAddrScript, err := script.P2TRScript(changeAddr.VtxoTapKey)
		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: changeAddrScript,
		})

	}

	arkPtx, checkpointPtxs, err := offchain.BuildAssetTxs(outs, int(globalVoutIndex), ins, serverUnrollScript)
	if err != nil {
		return "", nil, nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, nil, err
	}

	checkpointTxs := make([]string, 0, len(checkpointPtxs))
	for _, ptx := range checkpointPtxs {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", nil, nil, err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	return arkTx, checkpointTxs, &assetGroup, nil

}

func buildAssetTransferTx(
	sealVtxos []arkTxInput, otherVtxos []arkTxInput, assetReceivers []types.AssetReceiver, otherReceivers []types.Receiver, serverUnrollScript []byte,
	dustLimit uint64,
) (string, []string, *asset.AssetPacket, error) {
	if len(sealVtxos) <= 0 {
		return "", nil, nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(sealVtxos)+len(otherVtxos))

	//assign Index for assetReceiver
	finalAssetReceivers := assetReceivers
	for i := range assetReceivers {
		finalAssetReceivers[i].Index = uint32(i)
	}

	// Group inputs by AssetId
	inputsByAsset := make(map[string][]arkTxInput)

	for _, vtxo := range sealVtxos {
		if vtxo.Asset == nil {
			return "", nil, nil, fmt.Errorf("vtxo %s has no asset info", vtxo.Txid)
		}
		assetId := vtxo.Asset.AssetId
		inputsByAsset[assetId] = append(inputsByAsset[assetId], vtxo)
	}

	// Group outputs by AssetId
	outputsByAsset := make(map[string][]types.AssetReceiver)
	for _, receiver := range finalAssetReceivers {
		outputsByAsset[receiver.AssetId] = append(outputsByAsset[receiver.AssetId], receiver)
	}

	normalAssets := make([]asset.AssetGroup, 0)
	outs := make([]*wire.TxOut, 0)

	// To ensure deterministic order, let's collect all AssetIds
	assetIds := make([]string, 0, len(inputsByAsset))
	for id := range inputsByAsset {
		assetIds = append(assetIds, id)
	}
	// Sort not strictly necessary but good for determinism
	sort.Strings(assetIds)

	globalInputIndex := uint16(0)

	for _, assetIdStr := range assetIds {
		assetId, err := asset.AssetIdFromString(assetIdStr)
		if err != nil {
			return "", nil, nil, err
		}

		vtxos := inputsByAsset[assetIdStr]
		receivers := outputsByAsset[assetIdStr]

		newAssetInputs := make([]asset.AssetInput, 0)

		for _, vtxo := range vtxos {
			in, err := createVtxoTxInput(vtxo)
			if err != nil {
				return "", nil, nil, err
			}
			ins = append(ins, *in)

			if vtxo.Asset == nil || vtxo.Asset.Vout != vtxo.VOut {
				return "", nil, nil, fmt.Errorf("vtxo %s missing asset info for transfer", vtxo.Txid)
			}

			assetInput := asset.AssetInput{
				Type:   asset.AssetTypeLocal,
				Vin:    globalInputIndex,
				Amount: vtxo.Asset.Amount,
			}

			globalInputIndex++
			newAssetInputs = append(newAssetInputs, assetInput)
		}

		newAssetOutputs := make([]asset.AssetOutput, 0)

		for _, receiver := range receivers {

			newAssetOutputs = append(newAssetOutputs, asset.AssetOutput{
				Type:   asset.AssetTypeLocal,
				Amount: receiver.Amount,
				Vout:   uint16(receiver.Index),
			})
		}

		newAsset := asset.AssetGroup{
			AssetId: *assetId,
			Inputs:  newAssetInputs,
			Outputs: newAssetOutputs,
		}

		normalAssets = append(normalAssets, newAsset)
	}

	// add the outputs to the asset receivers to maintain indexing
	for _, receiver := range finalAssetReceivers {
		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, err
		}

		newVtxoScript, err := script.P2TRScript(addr.VtxoTapKey)
		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(dustLimit),
			PkScript: newVtxoScript,
		})
	}

	for _, vtxo := range otherVtxos {
		in, err := createVtxoTxInput(vtxo)
		if err != nil {
			return "", nil, nil, err
		}

		ins = append(ins, *in)
	}

	assetPacket := asset.AssetPacket{
		NormalAssets: normalAssets,
	}

	// exclude SubDust receiver from other receivers
	var subdustReceiver *types.Receiver

	for i, receiver := range otherReceivers {
		if receiver.Amount < dustLimit {
			// copy value to avoid aliasing issues
			r := receiver
			subdustReceiver = &r

			// remove from slice
			otherReceivers = append(otherReceivers[:i], otherReceivers[i+1:]...)
			break
		}
	}

	var assetOpretOut wire.TxOut
	var err error

	if subdustReceiver != nil {
		addr, err := arklib.DecodeAddressV0(subdustReceiver.To)
		if err != nil {
			return "", nil, nil, err
		}
		assetPacket.SubDustKey = addr.VtxoTapKey

		assetOpretOut, err = assetPacket.EncodeOpret(int64(subdustReceiver.Amount))
		if err != nil {
			return "", nil, nil, err
		}

	} else {

		assetOpretOut, err = assetPacket.EncodeOpret(0)
		if err != nil {
			return "", nil, nil, err
		}

	}

	outs = append(outs, &assetOpretOut)

	assetAnchorIndex := len(outs) - 1

	for _, receiver := range otherReceivers {

		var vtxoScript []byte
		var err error

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, err
		}

		vtxoScript, err = script.P2TRScript(addr.VtxoTapKey)

		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: vtxoScript,
		})

	}

	arkPtx, checkpointPtxs, err := offchain.BuildAssetTxs(outs, assetAnchorIndex, ins, serverUnrollScript)
	if err != nil {
		return "", nil, nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, nil, err
	}

	checkpointTxs := make([]string, 0, len(checkpointPtxs))
	for _, ptx := range checkpointPtxs {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", nil, nil, err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	return arkTx, checkpointTxs, &assetPacket, nil
}

func buildAssetModificationTx(controlAssetId, assetId string, controlSealVtxos, otherVtxos []arkTxInput, controlAssetReceivers, assetReceivers, otherReceivers []types.Receiver, metadata map[string]string, serverUnrollScript []byte,
	dustLimit uint64,
) (string, []string, *asset.AssetPacket, error) {

	ins := make([]offchain.VtxoInput, 0, len(controlSealVtxos)+len(otherVtxos))

	newAssetInputs := make([]asset.AssetInput, 0)
	newAssetOutputs := make([]asset.AssetOutput, 0)

	newControlAssetInputs := make([]asset.AssetInput, 0)
	newControlAssetOutputs := make([]asset.AssetOutput, 0)

	for i, vtxo := range controlSealVtxos {
		in, err := createVtxoTxInput(vtxo)
		if err != nil {
			return "", nil, nil, err
		}
		ins = append(ins, *in)

		if vtxo.Asset == nil || vtxo.Asset.Vout != vtxo.VOut {
			return "", nil, nil, fmt.Errorf("vtxo %s missing control asset info for modification", vtxo.Txid)

		}

		assetInput := asset.AssetInput{
			Type:   asset.AssetTypeLocal,
			Vin:    uint16(i),
			Amount: vtxo.Asset.Amount,
		}
		newControlAssetInputs = append(newControlAssetInputs, assetInput)
	}

	for _, vtxo := range otherVtxos {
		in, err := createVtxoTxInput(vtxo)
		if err != nil {
			return "", nil, nil, err
		}

		ins = append(ins, *in)
	}

	outs := make([]*wire.TxOut, 0)

	receiverIndex := uint32(0)

	for _, receiver := range controlAssetReceivers {
		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, err
		}

		newVtxoScript, err := script.P2TRScript(addr.VtxoTapKey)
		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(dustLimit),
			PkScript: newVtxoScript,
		})

		newControlAssetOutputs = append(newControlAssetOutputs, asset.AssetOutput{
			Type:   asset.AssetTypeLocal,
			Amount: receiver.Amount,
			Vout:   uint16(receiverIndex),
		})

		receiverIndex += 1

	}

	decodedControlAssetId, ferr := asset.AssetIdFromString(controlAssetId)
	if ferr != nil {
		return "", nil, nil, ferr
	}
	if decodedControlAssetId == nil {
		return "", nil, nil, fmt.Errorf("invalid control asset id: %s", controlAssetId)
	}

	newControlAsset := asset.AssetGroup{
		AssetId: *decodedControlAssetId,
		Inputs:  newControlAssetInputs,
		Outputs: newControlAssetOutputs,
	}

	for _, receiver := range assetReceivers {
		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, err
		}

		newVtxoScript, err := script.P2TRScript(addr.VtxoTapKey)
		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(dustLimit),
			PkScript: newVtxoScript,
		})

		newAssetOutputs = append(newAssetOutputs, asset.AssetOutput{
			Type:   asset.AssetTypeLocal,
			Amount: receiver.Amount,
			Vout:   uint16(receiverIndex),
		})

		receiverIndex += 1

	}

	decodedAssetId, ferr := asset.AssetIdFromString(assetId)
	if ferr != nil {
		return "", nil, nil, ferr
	}
	if decodedAssetId == nil {
		return "", nil, nil, fmt.Errorf("invalid asset id: %s", assetId)
	}

	newAsset := asset.AssetGroup{
		AssetId:        *decodedAssetId,
		Outputs:        []asset.AssetOutput{},
		Inputs:         []asset.AssetInput{},
		Metadata:       []asset.Metadata{},
		ControlAssetId: &newControlAsset.AssetId,
	}

	newAsset.Outputs = newAssetOutputs
	newAsset.Inputs = newAssetInputs
	newAsset.Metadata = toAssetMetadataList(metadata)

	assetPacket := asset.AssetPacket{
		ControlAssets: []asset.AssetGroup{newControlAsset},
		NormalAssets:  []asset.AssetGroup{newAsset},
	}

	// exclude SubDust receiver from other receivers
	var subdustReceiver *types.Receiver

	for i, receiver := range otherReceivers {
		if receiver.Amount < dustLimit {
			// copy value to avoid aliasing issues
			r := receiver
			subdustReceiver = &r

			// remove from slice
			otherReceivers = append(otherReceivers[:i], otherReceivers[i+1:]...)
			break
		}
	}

	var assetOpretOut wire.TxOut
	var err error

	if subdustReceiver != nil {
		addr, err := arklib.DecodeAddressV0(subdustReceiver.To)
		if err != nil {
			return "", nil, nil, err
		}
		assetPacket.SubDustKey = addr.VtxoTapKey

		assetOpretOut, err = assetPacket.EncodeOpret(int64(subdustReceiver.Amount))
		if err != nil {
			return "", nil, nil, err
		}

	} else {

		assetOpretOut, err = assetPacket.EncodeOpret(0)
		if err != nil {
			return "", nil, nil, err
		}

	}

	outs = append(outs, &assetOpretOut)

	assetAnchorIndex := len(outs) - 1

	for _, receiver := range otherReceivers {

		var vtxoScript []byte
		var err error

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, nil, err
		}

		vtxoScript, err = script.P2TRScript(addr.VtxoTapKey)

		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: vtxoScript,
		})

	}

	arkPtx, checkpointPtxs, err := offchain.BuildAssetTxs(outs, assetAnchorIndex, ins, serverUnrollScript)
	if err != nil {
		return "", nil, nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, nil, err
	}

	checkpointTxs := make([]string, 0, len(checkpointPtxs))
	for _, ptx := range checkpointPtxs {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", nil, nil, err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	return arkTx, checkpointTxs, &assetPacket, nil
}

func buildOffchainTx(
	vtxos []arkTxInput, receivers []types.Receiver, serverUnrollScript []byte, dustLimit uint64,
) (string, []string, error) {
	if len(vtxos) <= 0 {
		return "", nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", nil, err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", nil, err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", nil, err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", nil, err
		}

		tapscript := &waddrmgr.Tapscript{
			RevealedScript: leafProof.Script,
			ControlBlock:   ctrlBlock,
		}

		ins = append(ins, offchain.VtxoInput{
			Outpoint:           vtxoOutpoint,
			Tapscript:          tapscript,
			Amount:             int64(vtxo.Amount),
			RevealedTapscripts: vtxo.Tapscripts,
		})
	}

	outs := make([]*wire.TxOut, 0, len(receivers))

	for i, receiver := range receivers {
		if receiver.IsOnchain() {
			return "", nil, fmt.Errorf("receiver %d is onchain", i)
		}

		addr, err := arklib.DecodeAddressV0(receiver.To)
		if err != nil {
			return "", nil, err
		}

		var newVtxoScript []byte

		if receiver.Amount < dustLimit {
			newVtxoScript, err = script.SubDustScript(addr.VtxoTapKey)
		} else {
			newVtxoScript, err = script.P2TRScript(addr.VtxoTapKey)
		}
		if err != nil {
			return "", nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: newVtxoScript,
		})
	}

	arkPtx, checkpointPtxs, err := offchain.BuildTxs(ins, outs, serverUnrollScript)
	if err != nil {
		return "", nil, err
	}

	arkTx, err := arkPtx.B64Encode()
	if err != nil {
		return "", nil, err
	}

	checkpointTxs := make([]string, 0, len(checkpointPtxs))
	for _, ptx := range checkpointPtxs {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", nil, err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	return arkTx, checkpointTxs, nil
}

func inputsToDerivationPath(inputs []types.Outpoint, notesInputs []string) string {
	// sort arknotes
	slices.SortStableFunc(notesInputs, func(i, j string) int {
		return strings.Compare(i, j)
	})

	// sort outpoints
	slices.SortStableFunc(inputs, func(i, j types.Outpoint) int {
		txidCmp := strings.Compare(i.Txid, j.Txid)
		if txidCmp != 0 {
			return txidCmp
		}
		return int(i.VOut - j.VOut)
	})

	// serialize outpoints and arknotes

	var buf bytes.Buffer

	for _, input := range inputs {
		buf.WriteString(input.Txid)
		buf.WriteString(strconv.Itoa(int(input.VOut)))
	}

	for _, note := range notesInputs {
		buf.WriteString(note)
	}

	// hash the serialized data
	hash := sha256.Sum256(buf.Bytes())

	// convert hash to bip32 derivation path
	// split the 32-byte hash into 8 uint32 values (4 bytes each)
	path := "m"
	for i := 0; i < 8; i++ {
		// Convert 4 bytes to uint32 using big-endian encoding
		segment := binary.BigEndian.Uint32(hash[i*4 : (i+1)*4])
		path += fmt.Sprintf("/%d'", segment)
	}

	return path
}

func extractCollaborativePath(tapscripts []string) ([]byte, *arklib.TaprootMerkleProof, error) {
	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, nil, err
	}

	forfeitClosures := vtxoScript.ForfeitClosures()
	if len(forfeitClosures) <= 0 {
		return nil, nil, fmt.Errorf("no exit closures found")
	}

	forfeitClosure := forfeitClosures[0]
	forfeitScript, err := forfeitClosure.Script()
	if err != nil {
		return nil, nil, err
	}

	taprootKey, taprootTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}

	forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
	leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get taproot merkle proof: %s", err)
	}
	pkScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, nil, err
	}

	return pkScript, leafProof, nil
}

// convert regular coins (boarding, vtxos or notes) to intent proof inputs
// it also returns the necessary data used to sign the proof PSBT
func toIntentInputs(
	boardingUtxos []types.Utxo, vtxos []client.TapscriptsVtxo, notes []string,
) ([]intent.Input, []*arklib.TaprootMerkleProof, [][]*psbt.Unknown, error) {
	inputs := make([]intent.Input, 0, len(boardingUtxos)+len(vtxos))
	signingLeaves := make([]*arklib.TaprootMerkleProof, 0, len(boardingUtxos)+len(vtxos))
	arkFields := make([][]*psbt.Unknown, 0, len(boardingUtxos)+len(vtxos))

	for _, coin := range vtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		pkScript, leafProof, err := extractCollaborativePath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		signingLeaves = append(signingLeaves, leafProof)

		isSeal := coin.Asset != nil

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
			IsSeal: isSeal,
		})

		taptreeField, err := txutils.VtxoTaprootTreeField.Encode(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		vtxoSealField, err := txutils.AssetSealVtxoField.Encode(isSeal)
		if err != nil {
			return nil, nil, nil, err
		}

		arkFields = append(arkFields, []*psbt.Unknown{taptreeField, vtxoSealField})
	}

	for _, coin := range boardingUtxos {
		hash, err := chainhash.NewHashFromStr(coin.Txid)
		if err != nil {
			return nil, nil, nil, err
		}
		outpoint := wire.NewOutPoint(hash, coin.VOut)

		pkScript, leafProof, err := extractCollaborativePath(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		signingLeaves = append(signingLeaves, leafProof)

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		})

		taptreeField, err := txutils.VtxoTaprootTreeField.Encode(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}
		arkFields = append(arkFields, []*psbt.Unknown{taptreeField})
	}

	nextInputIndex := len(inputs)
	if nextInputIndex > 0 {
		// if there is non-notes inputs, count the extra intent proof input
		nextInputIndex++
	}

	for _, n := range notes {
		parsedNote, err := note.NewNoteFromString(n)
		if err != nil {
			return nil, nil, nil, err
		}

		outpoint, input, err := parsedNote.IntentProofInput()
		if err != nil {
			return nil, nil, nil, err
		}

		inputs = append(inputs, intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    input.WitnessUtxo.Value,
				PkScript: input.WitnessUtxo.PkScript,
			},
		})

		vtxoScript := parsedNote.VtxoScript()

		_, taprootTree, err := vtxoScript.TapTree()
		if err != nil {
			return nil, nil, nil, err
		}

		forfeitScript, err := vtxoScript.Closures[0].Script()
		if err != nil {
			return nil, nil, nil, err
		}

		forfeitLeaf := txscript.NewBaseTapLeaf(forfeitScript)
		leafProof, err := taprootTree.GetTaprootMerkleProof(forfeitLeaf.TapHash())
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get taproot merkle proof: %s", err)
		}

		nextInputIndex++
		// if the note vtxo is the first input, it will be used twice
		if nextInputIndex == 1 {
			nextInputIndex++
		}

		signingLeaves = append(signingLeaves, leafProof)

		vtxoSealField, err := txutils.AssetSealVtxoField.Encode(false)
		if err != nil {
			return nil, nil, nil, err
		}
		input.Unknowns = append(input.Unknowns, vtxoSealField)

		arkFields = append(arkFields, input.Unknowns)
	}

	return inputs, signingLeaves, arkFields, nil
}

func getOffchainBalanceDetails(amountByExpiration map[int64]uint64) (int64, []VtxoDetails) {
	nextExpiration := int64(0)
	details := make([]VtxoDetails, 0)
	for timestamp, amount := range amountByExpiration {
		if nextExpiration == 0 || timestamp < nextExpiration {
			nextExpiration = timestamp
		}

		fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
		details = append(
			details,
			VtxoDetails{
				ExpiryTime: fancyTime,
				Amount:     amount,
			},
		)
	}
	return nextExpiration, details
}

func getFancyTimeExpiration(nextExpiration int64) string {
	if nextExpiration == 0 {
		return ""
	}

	fancyTimeExpiration := ""
	t := time.Unix(nextExpiration, 0)
	if t.Before(time.Now().Add(48 * time.Hour)) {
		// print the duration instead of the absolute time
		until := time.Until(t)
		seconds := math.Abs(until.Seconds())
		minutes := math.Abs(until.Minutes())
		hours := math.Abs(until.Hours())

		if hours < 1 {
			if minutes < 1 {
				fancyTimeExpiration = fmt.Sprintf("%d seconds", int(seconds))
			} else {
				fancyTimeExpiration = fmt.Sprintf("%d minutes", int(minutes))
			}
		} else {
			fancyTimeExpiration = fmt.Sprintf("%d hours", int(hours))
		}
	} else {
		fancyTimeExpiration = t.Format(time.RFC3339)
	}
	return fancyTimeExpiration
}

func computeVSize(tx *wire.MsgTx) lntypes.VByte {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize() // including witness
	weight := totalSize + baseSize*3
	return lntypes.WeightUnit(uint64(weight)).ToVB()
}

func checkSettleOptionsType(o interface{}) (*SettleOptions, error) {
	opts, ok := o.(*SettleOptions)
	if !ok {
		return nil, fmt.Errorf("invalid options type")
	}

	return opts, nil
}

func createRegisterIntentMessage(outputs []types.Receiver, teleportOutputs []types.TeleportReceiver, cosignersPublicKeys []string) (
	string, []*wire.TxOut, error,
) {
	validAt := time.Now()
	expireAt := validAt.Add(2 * time.Minute).Unix()
	outputsTxOut := make([]*wire.TxOut, 0)
	onchainOutputsIndexes := make([]int, 0)
	assetOutputsIndexes := make([]intent.AssetOutput, 0)

	outputCounter := 0

	for _, output := range outputs {
		txOut, isOnchain, err := output.ToTxOut()
		if err != nil {
			return "", nil, err
		}

		if isOnchain {
			onchainOutputsIndexes = append(onchainOutputsIndexes, outputCounter)
		}

		outputsTxOut = append(outputsTxOut, txOut)

		outputCounter++
	}

	for _, output := range teleportOutputs {
		assetOutputsIndexes = append(assetOutputsIndexes, intent.AssetOutput{
			AssetId:      output.AssetId,
			Amount:       output.AssetAmount,
			TeleportHash: output.TeleportHash,
		})
	}

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: onchainOutputsIndexes,
		AssetOutputIndexes:   assetOutputsIndexes,
		ExpireAt:             expireAt,
		ValidAt:              validAt.Unix(),
		CosignersPublicKeys:  cosignersPublicKeys,
	}.Encode()
	if err != nil {
		return "", nil, err
	}

	return message, outputsTxOut, nil
}

func findVtxosSpentInSettlement(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSettled(vtxos, vtxo.CommitmentTxids[0])
}

func findVtxosSettled(vtxos []types.Vtxo, id string) []types.Vtxo {
	var result []types.Vtxo
	leftVtxos := make([]types.Vtxo, 0)
	for _, v := range vtxos {
		if v.SettledBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func findVtxosSpent(vtxos []types.Vtxo, id string) []types.Vtxo {
	var result []types.Vtxo
	leftVtxos := make([]types.Vtxo, 0)
	for _, v := range vtxos {
		if v.ArkTxid == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func reduceVtxosAmount(vtxos []types.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSpentBy(vtxos []types.Vtxo, spentByTxid string) []types.Vtxo {
	var result []types.Vtxo
	for _, v := range vtxos {
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []types.Vtxo, spentByVtxos []types.Vtxo) types.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return types.Vtxo{}
}

func ecPubkeyFromHex(pubkey string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(buf)
}

func getBatchExpiryLocktime(expiry uint32) arklib.RelativeLocktime {
	if expiry >= 512 {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: expiry}
	}
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: expiry}
}

func GetAssetOutput(output []asset.AssetOutput, vout uint16) (*asset.AssetOutput, error) {
	for _, out := range output {
		if out.Vout == vout {
			return &out, nil
		}
	}
	return nil, fmt.Errorf("output not found for vout %d", vout)
}

func createVtxoTxInput(vtxo arkTxInput) (*offchain.VtxoInput, error) {
	if len(vtxo.Tapscripts) <= 0 {
		return nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
	}

	vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
	if err != nil {
		return nil, err
	}

	vtxoOutpoint := &wire.OutPoint{
		Hash:  *vtxoTxID,
		Index: vtxo.VOut,
	}

	vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
	if err != nil {
		return nil, err
	}

	_, vtxoTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, err
	}

	leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
	if err != nil {
		return nil, err
	}

	ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
	if err != nil {
		return nil, err
	}

	tapscript := &waddrmgr.Tapscript{
		RevealedScript: leafProof.Script,
		ControlBlock:   ctrlBlock,
	}

	ofchainVtxoInput := offchain.VtxoInput{
		Outpoint:           vtxoOutpoint,
		Tapscript:          tapscript,
		Amount:             int64(vtxo.Amount),
		RevealedTapscripts: vtxo.Tapscripts,
	}

	return &ofchainVtxoInput, nil
}

func DerivePubKeyFromScript(scriptHex string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(scriptHex)
	if err != nil {
		return nil, err
	}
	pubkeyBytes := buf[2:]

	return schnorr.ParsePubKey(pubkeyBytes)
}

func DeriveForfeitLeafHash(tapScripts []string) (*chainhash.Hash, error) {
	vtxoScript, err := script.ParseVtxoScript(tapScripts)
	if err != nil {
		return nil, err
	}

	forfeitClosure := vtxoScript.ForfeitClosures()[0]

	forfeitScript, err := forfeitClosure.Script()
	if err != nil {
		return nil, err
	}

	forfeitLeafHash := txscript.NewBaseTapLeaf(forfeitScript).TapHash()

	return &forfeitLeafHash, nil
}

func FindAssetFromOutput(vtxo types.Vtxo, assetPacket *asset.AssetPacket) (*types.Asset, error) {
	if assetPacket == nil {
		return nil, fmt.Errorf("asset group is nil")
	}

	assetsToCheck := make([]*asset.AssetGroup, 0, len(assetPacket.NormalAssets)+len(assetPacket.ControlAssets))
	for i := range assetPacket.NormalAssets {
		assetsToCheck = append(assetsToCheck, &assetPacket.NormalAssets[i])
	}
	for i := range assetPacket.ControlAssets {
		assetsToCheck = append(assetsToCheck, &assetPacket.ControlAssets[i])
	}

	for _, asset := range assetsToCheck {
		if asset == nil {
			continue
		}

		for _, assetOut := range asset.Outputs {
			if uint16(vtxo.VOut) == assetOut.Vout {
				return &types.Asset{
					AssetId: asset.AssetId.ToString(),
					Amount:  assetOut.Amount,
					Vout:    vtxo.VOut,
				}, nil
			}

		}

	}

	return nil, fmt.Errorf("asset not found in asset group")

}

func toAssetMetadataList(metadataMap map[string]string) []asset.Metadata {
	metadataList := make([]asset.Metadata, 0, len(metadataMap))
	for k, v := range metadataMap {
		metadataList = append(metadataList, asset.Metadata{
			Key:   k,
			Value: v,
		})
	}
	return metadataList
}
