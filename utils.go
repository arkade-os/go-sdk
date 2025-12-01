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

func buildAssetCreationTx(
	vtxos []arkTxInput, assetId [32]byte, receiver types.Receiver, change *types.Receiver, assetParams types.AssetCreationParams, serverUnrollScript []byte,
	dustLimit uint64,
) (string, []string, *asset.Asset, error) {
	if len(vtxos) <= 0 {
		return "", nil, nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", nil, nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", nil, nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", nil, nil, err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", nil, nil, err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", nil, nil, err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", nil, nil, err
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
	sealAddr, err := arklib.DecodeAddressV0(receiver.To)
	if err != nil {
		return "", nil, nil, err
	}

	sealAddrScript, err := script.P2TRScript(sealAddr.VtxoTapKey)
	if err != nil {
		return "", nil, nil, err
	}

	controlKey := sealAddr.VtxoTapKey

	assetMeta := make([]asset.Metadata, 0)
	assetMeta = append(assetMeta, asset.Metadata{
		Key:   "name",
		Value: assetParams.Name,
	})
	assetMeta = append(assetMeta, asset.Metadata{
		Key:   "symbol",
		Value: assetParams.Symbol,
	})
	assetMeta = append(assetMeta, asset.Metadata{
		Key:   "decimals",
		Value: strconv.Itoa(int(assetParams.Decimals)),
	})

	assetDetails := asset.Asset{
		AssetId:       assetId,
		Outputs:       []asset.AssetOutput{{PublicKey: *controlKey, Amount: assetParams.Quantity, Vout: 0}},
		ControlPubkey: controlKey,
		Inputs:        []asset.AssetInput{},
		Metadata:      assetMeta,
		Immutable:     assetParams.Immutable,
		Version:       asset.AssetVersion,
		Magic:         asset.AssetMagic,
	}

	genesisId, err := deriveGenesisId(vtxos)
	if err != nil {
		return "", nil, nil, err
	}

	assetOpretOut, err := assetDetails.EncodeOpret(genesisId)
	if err != nil {
		return "", nil, nil, err
	}

	outs := make([]*wire.TxOut, 0)

	outs = append(outs, &wire.TxOut{
		Value:    int64(receiver.Amount),
		PkScript: sealAddrScript,
	})

	outs = append(outs, &assetOpretOut)

	if change != nil {
		changeAddrScript, err := script.P2TRScript(sealAddr.VtxoTapKey)
		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(change.Amount),
			PkScript: changeAddrScript,
		})
	}

	arkPtx, checkpointPtxs, err := offchain.BuildTxs(ins, outs, serverUnrollScript)
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

	return arkTx, checkpointTxs, &assetDetails, nil

}

func buildAssetTransferTx(
	sealVtxos []arkTxInput, otherVtxos []arkTxInput, assetId [32]byte, receivers []types.Receiver, change *types.Receiver, serverUnrollScript []byte,
	dustLimit uint64,
) (string, []string, *asset.Asset, error) {
	if len(sealVtxos) <= 0 {
		return "", nil, nil, fmt.Errorf("missing vtxos")
	}

	if len(otherVtxos) <= 0 {
		return "", nil, nil, fmt.Errorf("missing spend vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(sealVtxos)+len(otherVtxos))

	newAsset := sealVtxos[0].Vtxo.Asset
	newAssetInputs := make([]asset.AssetInput, 0)
	newAssetOutputs := make([]asset.AssetOutput, 0)

	for _, vtxo := range sealVtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", nil, nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", nil, nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", nil, nil, err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", nil, nil, err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", nil, nil, err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", nil, nil, err
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

		buf, err := hex.DecodeString(vtxo.Script)
		if err != nil {
			return "", nil, nil, err
		}
		pubkeyBytes := buf[2:]

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return "", nil, nil, err
		}

		for _, out := range vtxo.Asset.Outputs {
			if out.PublicKey.IsEqual(pubkey) {
				txId := vtxoOutpoint.Hash.CloneBytes()
				reverseBytes(txId)

				assetInput := asset.AssetInput{
					Txid:   txId,
					Vout:   out.Vout,
					Amount: out.Amount,
				}
				newAssetInputs = append(newAssetInputs, assetInput)
			}
		}
	}

	newAsset.Inputs = newAssetInputs

	fmt.Printf("This is the new asset ")

	for _, vtxo := range otherVtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", nil, nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", nil, nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", nil, nil, err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", nil, nil, err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", nil, nil, err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", nil, nil, err
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

	outs := make([]*wire.TxOut, 0)

	for i, receiver := range receivers {
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
			PublicKey: *addr.VtxoTapKey,
			Amount:    receiver.Amount,
			Vout:      uint32(i),
		})

	}

	newAsset.Outputs = newAssetOutputs

	batchCommitmentId, err := deriveGenesisId(sealVtxos)
	if err != nil {
		return "", nil, nil, err
	}

	assetOpretScript, err := newAsset.EncodeOpret(batchCommitmentId)
	if err != nil {
		return "", nil, nil, err
	}

	outs = append(outs, &assetOpretScript)

	if change != nil {
		var changeVtxoScript []byte
		var err error

		addr, err := arklib.DecodeAddressV0(change.To)
		if err != nil {
			return "", nil, nil, err
		}

		if change.Amount < dustLimit {
			changeVtxoScript, err = script.SubDustScript(addr.VtxoTapKey)
		} else {
			changeVtxoScript, err = script.P2TRScript(addr.VtxoTapKey)
		}
		if err != nil {
			return "", nil, nil, err
		}

		outs = append(outs, &wire.TxOut{
			Value:    int64(change.Amount),
			PkScript: changeVtxoScript,
		})
	}

	arkPtx, checkpointPtxs, err := offchain.BuildTxs(ins, outs, serverUnrollScript)
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

	return arkTx, checkpointTxs, newAsset, nil
}

func buildAssetModificationTx(
	sealVtxos []arkTxInput, assetId [32]byte, receivers []types.Receiver, params types.AssetModificationParams, serverUnrollScript []byte,
	dustLimit uint64,
) (string, []string, *asset.Asset, error) {
	if len(sealVtxos) <= 0 {
		return "", nil, nil, fmt.Errorf("missing vtxos")
	}

	ins := make([]offchain.VtxoInput, 0, len(sealVtxos))

	newAsset := sealVtxos[0].Vtxo.Asset
	newAssetInputs := make([]asset.AssetInput, 0)
	newAssetOutputs := make([]asset.AssetOutput, 0)

	for _, vtxo := range sealVtxos {
		if len(vtxo.Tapscripts) <= 0 {
			return "", nil, nil, fmt.Errorf("missing tapscripts for vtxo %s", vtxo.Txid)
		}

		vtxoTxID, err := chainhash.NewHashFromStr(vtxo.Txid)
		if err != nil {
			return "", nil, nil, err
		}

		vtxoOutpoint := &wire.OutPoint{
			Hash:  *vtxoTxID,
			Index: vtxo.VOut,
		}

		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return "", nil, nil, err
		}

		_, vtxoTree, err := vtxoScript.TapTree()
		if err != nil {
			return "", nil, nil, err
		}

		leafProof, err := vtxoTree.GetTaprootMerkleProof(vtxo.ForfeitLeafHash)
		if err != nil {
			return "", nil, nil, err
		}

		ctrlBlock, err := txscript.ParseControlBlock(leafProof.ControlBlock)
		if err != nil {
			return "", nil, nil, err
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

		buf, err := hex.DecodeString(vtxo.Script)
		if err != nil {
			return "", nil, nil, err
		}
		pubkeyBytes := buf[2:]

		pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
		if err != nil {
			return "", nil, nil, err
		}

		for _, out := range vtxo.Asset.Outputs {
			if out.PublicKey.IsEqual(pubkey) {
				txId := vtxoOutpoint.Hash.CloneBytes()
				reverseBytes(txId)

				assetInput := asset.AssetInput{
					Txid:   txId,
					Vout:   out.Vout,
					Amount: out.Amount,
				}
				newAssetInputs = append(newAssetInputs, assetInput)
			}
		}
	}

	newAsset.Inputs = newAssetInputs

	fmt.Printf("This is the new asset ")

	outs := make([]*wire.TxOut, 0)

	for i, receiver := range receivers {
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
			PublicKey: *addr.VtxoTapKey,
			Amount:    receiver.Amount,
			Vout:      uint32(i),
		})

	}

	newAsset.Outputs = newAssetOutputs

	// Include the metadata modifications added
	modifyAssetMetadata(newAsset, params)

	batchCommitmentId, err := deriveGenesisId(sealVtxos)
	if err != nil {
		return "", nil, nil, err
	}

	assetOpretScript, err := newAsset.EncodeOpret(batchCommitmentId)
	if err != nil {
		return "", nil, nil, err
	}

	outs = append(outs, &assetOpretScript)

	arkPtx, checkpointPtxs, err := offchain.BuildTxs(ins, outs, serverUnrollScript)
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

	return arkTx, checkpointTxs, newAsset, nil
}

func deriveGenesisId(inputVtxos []arkTxInput) ([]byte, error) {

	if len(inputVtxos) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	sort.Slice(inputVtxos, func(i, j int) bool {
		cmp := strings.Compare(inputVtxos[i].Txid, inputVtxos[j].Txid)

		if cmp < 0 {
			return true
		}
		if cmp > 0 {
			return false
		}
		// TxId equal, compare Vout
		return inputVtxos[i].Outpoint.VOut < inputVtxos[j].Outpoint.VOut
	})

	// Take the smallest outpoint after sorting
	smallest := inputVtxos[0]

	h := sha256.New()

	for _, txid := range smallest.CommitmentTxids {
		decodedTxid, err := hex.DecodeString(txid)
		if err != nil {
			return nil, err
		}
		h.Write(decodedTxid)
	}

	return h.Sum(nil), nil
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

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
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
		txOut, _, err := output.ToTxOut()
		if err != nil {
			return "", nil, err
		}
		assetOutputsIndexes = append(assetOutputsIndexes, intent.AssetOutput{
			AssetOutputIndex: outputCounter,
			AssetId:          output.AssetId,
			Amount:           output.AssetAmount,
			TeleportPubkey:   output.AssetReceiverPubkey,
		})

		outputsTxOut = append(outputsTxOut, txOut)

		outputCounter++
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

func GetAssetOutput(output []asset.AssetOutput, vout uint32) (*asset.AssetOutput, error) {
	for _, out := range output {
		if out.Vout == vout {
			return &out, nil
		}
	}
	return nil, fmt.Errorf("output not found for vout %d", vout)
}

func NewTeleportVtxoScript(
	owner, signer *btcec.PublicKey, teleportPreimage []byte, exitDelay arklib.RelativeLocktime,
) types.TeleportScript {

	preimageHash := sha256.Sum256(teleportPreimage)
	teleportPreimageHash := preimageHash[:]

	preimageCondition, _ := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SHA256).
		AddData(teleportPreimageHash).
		AddOp(txscript.OP_EQUAL).
		Script()

	claimConditionClosure := &script.ConditionMultisigClosure{
		Condition: preimageCondition,
		MultisigClosure: script.MultisigClosure{
			PubKeys: []*btcec.PublicKey{owner, signer},
		},
	}

	unilateralDelayCLosure := &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{owner}},
		Locktime:        exitDelay,
	}

	tapScriptVtxos := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			claimConditionClosure,
			unilateralDelayCLosure,
		},
	}

	return types.TeleportScript{
		TapscriptsVtxoScript: tapScriptVtxos,
		TeleportPreimage:     teleportPreimage,
		ClaimClousure:        claimConditionClosure,
	}

}

func toControlOutput(controlKey btcec.PublicKey) asset.AssetOutput {
	return asset.AssetOutput{
		PublicKey: controlKey,
		Amount:    1,
		Vout:      0,
	}
}

func modifyAssetMetadata(assetData *asset.Asset, metdataParams types.AssetModificationParams) {
	if metdataParams.Name != "" {
		for i := range assetData.Metadata {
			if assetData.Metadata[i].Key == "name" {
				assetData.Metadata[i].Value = metdataParams.Name
				return
			}
		}
		assetData.Metadata = append(assetData.Metadata, asset.Metadata{
			Key:   "name",
			Value: metdataParams.Name,
		})
	}

	if metdataParams.Symbol != "" {
		for i := range assetData.Metadata {
			if assetData.Metadata[i].Key == "symbol" {
				assetData.Metadata[i].Value = metdataParams.Symbol
				return
			}
		}
		assetData.Metadata = append(assetData.Metadata, asset.Metadata{
			Key:   "symbol",
			Value: metdataParams.Symbol,
		})
	}
}
