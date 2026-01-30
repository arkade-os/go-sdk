package arksdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
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

func buildArkInputs(vtxos []client.TapscriptsVtxo) ([]arkTxInput, error) {
	if len(vtxos) == 0 {
		return nil, nil
	}

	inputs := make([]arkTxInput, 0, len(vtxos))
	for _, vtxo := range vtxos {
		vtxoScript, err := script.ParseVtxoScript(vtxo.Tapscripts)
		if err != nil {
			return nil, err
		}

		forfeitClosures := vtxoScript.ForfeitClosures()
		if len(forfeitClosures) == 0 {
			return nil, fmt.Errorf("no forfeit closures found")
		}
		forfeitClosure := forfeitClosures[0]

		forfeitScript, err := forfeitClosure.Script()
		if err != nil {
			return nil, err
		}

		forfeitLeafHash := txscript.NewBaseTapLeaf(forfeitScript).TapHash()

		inputs = append(inputs, arkTxInput{
			TapscriptsVtxo:  vtxo,
			ForfeitLeafHash: forfeitLeafHash,
		})
	}

	return inputs, nil
}

type AssetTxBuilder struct {
	vtxos                []client.TapscriptsVtxo
	ins                  []offchain.VtxoInput
	outs                 []*wire.TxOut
	inputIndex           uint32
	outputIndex          uint32
	uniqueAssetInput     map[wire.OutPoint]uint32
	withoutExpirySorting bool
	changeAddr           string
	changeReceivers      []types.DBReceiver
	assetGroupList       []asset.AssetGroup
	assetGroupIndex      uint32
	eVtxoAmount          uint64
	extensionScript      []byte
}

func NewAssetTxBuilder(
	vtxos []client.TapscriptsVtxo,
	withoutExpirySorting bool,
	changeAddr string,
	eVtxoAmount uint64,
) *AssetTxBuilder {

	return &AssetTxBuilder{
		vtxos:                vtxos,
		ins:                  make([]offchain.VtxoInput, 0),
		outs:                 make([]*wire.TxOut, 0),
		inputIndex:           0,
		outputIndex:          0,
		uniqueAssetInput:     make(map[wire.OutPoint]uint32),
		withoutExpirySorting: withoutExpirySorting,
		changeAddr:           changeAddr,
		eVtxoAmount:          eVtxoAmount,
	}
}

func (b *AssetTxBuilder) InsertAssetGroup(
	assetIdStr string,
	receivers []types.Receiver,
	opType AssetGroupOperation,
) (uint32, error) {
	assetAmountTotal := uint64(0)
	for _, r := range receivers {
		assetAmountTotal += uint64(r.Amount)
	}

	if opType == AssetGroupIssuance || opType == AssetGroupClaimTeleport {
		assetAmountTotal = 0
	}

	if opType == AssetGroupBurn {
		receivers = []types.Receiver{}
	}

	assetCoins, assetChangeAmount, err := utils.CoinSelectAsset(
		b.vtxos, assetAmountTotal, assetIdStr, b.eVtxoAmount, b.withoutExpirySorting,
	)

	if err != nil {
		return 0, err
	}

	inputs, err := buildArkInputs(assetCoins)

	if err != nil {
		return 0, err
	}

	if assetChangeAmount > 0 {
		receivers = append(receivers, types.Receiver{
			To:     b.changeAddr,
			Amount: assetChangeAmount,
		})
	}

	var assetId *asset.AssetId

	if assetIdStr != "" {
		assetId, err = asset.NewAssetIdFromString(assetIdStr)
		if err != nil {
			return 0, err
		}
	}

	assetOutputs := make([]asset.AssetOutput, 0)
	assetInputs := make([]asset.AssetInput, 0)

	for _, rv := range receivers {
		addr, err := arklib.DecodeAddressV0(rv.To)
		if err != nil {
			return 0, err
		}

		newVtxoScript, err := script.P2TRScript(addr.VtxoTapKey)
		if err != nil {
			return 0, err
		}

		assetOutputs = append(assetOutputs, asset.AssetOutput{
			Type:   asset.AssetTypeLocal,
			Amount: rv.Amount,
			Vout:   uint16(b.outputIndex),
		})

		b.outs = append(b.outs, &wire.TxOut{
			Value:    int64(b.eVtxoAmount),
			PkScript: newVtxoScript,
		})

		if rv.To == b.changeAddr {
			b.changeReceivers = append(b.changeReceivers, types.DBReceiver{
				Receiver: rv,
				Index:    b.outputIndex,
				Assets: []types.DBAsset{{
					GroupIndex: b.assetGroupIndex,
					AssetId:    assetIdStr,
					Amount:     rv.Amount,
				}},
			})
		}

		b.outputIndex++
	}

	for _, vtxo := range inputs {
		in, err := createVtxoTxInput(vtxo)
		if err != nil {
			return 0, err
		}

		var assetAmount uint64
		var found bool
		for _, a := range vtxo.Assets {
			if a.AssetId == assetIdStr {
				assetAmount = a.Amount
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("vtxo %s has no asset %s", vtxo.Outpoint.String(), assetIdStr)
		}

		//check if it exists already
		if i, exists := b.uniqueAssetInput[*in.Outpoint]; exists {

			assetInputs = append(assetInputs, asset.AssetInput{
				Type:   asset.AssetTypeLocal,
				Vin:    uint16(i),
				Amount: assetAmount,
			})
		} else {
			b.ins = append(b.ins, *in)
			assetInputs = append(assetInputs, asset.AssetInput{
				Type:   asset.AssetTypeLocal,
				Vin:    uint16(b.inputIndex),
				Amount: assetAmount,
			})

			inputIndex := b.inputIndex
			b.uniqueAssetInput[*in.Outpoint] = inputIndex
			b.inputIndex++
		}

	}

	newAssetGroup := asset.AssetGroup{
		AssetId: assetId,
		Outputs: assetOutputs,
		Inputs:  assetInputs,
	}

	b.assetGroupList = append(b.assetGroupList, newAssetGroup)

	assetGroupIndex := b.assetGroupIndex

	b.assetGroupIndex++

	return assetGroupIndex, nil
}

func (b *AssetTxBuilder) AddWitness(
	assetGroupIndex uint32,
	intentID [32]byte,
	amount uint64,
	vout uint32,
) error {

	if assetGroupIndex >= uint32(len(b.assetGroupList)) {
		return fmt.Errorf("invalid asset group index")
	}

	b.assetGroupList[assetGroupIndex].Inputs = append(
		b.assetGroupList[assetGroupIndex].Inputs,
		asset.AssetInput{
			Type:   asset.AssetTypeIntent,
			Amount: amount,
			Txid:   intentID,
			Vin:    uint16(vout),
		},
	)
	return nil

}

func (b *AssetTxBuilder) InsertIssuance(
	assetGroupIndex uint32,
	controlAsset string,
) error {
	if assetGroupIndex >= uint32(len(b.assetGroupList)) {
		return fmt.Errorf("invalid asset group index")
	}
	var controlAssetId *asset.AssetId
	if controlAsset != "" {
		cAssetId, err := asset.NewAssetIdFromString(controlAsset)
		if err != nil {
			return err
		}
		controlAssetId = cAssetId
	}
	if controlAssetId != nil {
		b.assetGroupList[assetGroupIndex].ControlAsset = &asset.AssetRef{
			Type:    asset.AssetRefByID,
			AssetId: *controlAssetId,
		}
	}

	return nil
}

func (b *AssetTxBuilder) InsertMetadata(assetGroupIndex uint32, metadata map[string]string) error {
	if assetGroupIndex >= uint32(len(b.assetGroupList)) {
		return fmt.Errorf("invalid asset group index")
	}

	assetMetadata := make([]asset.Metadata, 0, len(metadata))
	for k, v := range metadata {
		assetMetadata = append(assetMetadata, asset.Metadata{
			Key:   []byte(k),
			Value: []byte(v),
		})
	}
	b.assetGroupList[assetGroupIndex].Metadata = assetMetadata

	return nil
}

func (b *AssetTxBuilder) AddSatsInputs(dust uint64) error {
	satsNeeded, isChange := b.calculateSatsNeeded()
	if satsNeeded == 0 {
		return nil
	}

	addr, err := arklib.DecodeAddressV0(b.changeAddr)
	if err != nil {
		return err
	}

	var receiver *types.Receiver
	if isChange {
		receiver = &types.Receiver{
			To:     b.changeAddr,
			Amount: satsNeeded,
		}
	} else {
		_, vtxos, changeAmount, err := utils.CoinSelectNormal(nil, b.vtxos, satsNeeded, dust, b.withoutExpirySorting, nil)
		if err != nil {
			return err
		}

		if changeAmount >= dust {
			receiver = &types.Receiver{
				To:     b.changeAddr,
				Amount: changeAmount,
			}
		}

		inputs, err := buildArkInputs(vtxos)
		if err != nil {
			return err
		}
		for _, vtxo := range inputs {
			in, err := createVtxoTxInput(vtxo)
			if err != nil {
				return err
			}
			if _, exists := b.uniqueAssetInput[*in.Outpoint]; exists {
				continue
			}
			b.ins = append(b.ins, *in)

			b.uniqueAssetInput[*in.Outpoint] = b.inputIndex
			b.inputIndex++
		}

	}

	if receiver != nil {
		changeAddrScript, err := script.P2TRScript(addr.VtxoTapKey)
		if err != nil {
			return err
		}

		b.outs = append(b.outs, &wire.TxOut{
			Value:    int64(receiver.Amount),
			PkScript: changeAddrScript,
		})

		b.changeReceivers = append(b.changeReceivers, types.DBReceiver{
			Receiver: *receiver,
			Index:    b.outputIndex,
		})

		b.outputIndex++
	}

	return nil
}

func (b *AssetTxBuilder) Build(signerUnrollScript []byte) (string, []string, error) {
	extensionPacket, err := asset.NewPacket(b.assetGroupList)
	if err != nil {
		return "", nil, err
	}

	pkScript, err := extensionPacket.Serialize()
	if err != nil {
		return "", nil, err
	}

	b.outs = append(b.outs, &wire.TxOut{
		Value:    0,
		PkScript: pkScript,
	})

	arkPtx, checkpointPtxs, err := offchain.BuildTxs(
		b.ins,
		b.outs,
		signerUnrollScript,
	)
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

	b.extensionScript = pkScript

	return arkTx, checkpointTxs, nil

}

func (b *AssetTxBuilder) GetSpentInputs() []client.TapscriptsVtxo {
	spentInputs := make([]client.TapscriptsVtxo, 0, len(b.uniqueAssetInput))
	for outpoint := range b.uniqueAssetInput {
		for _, vtxo := range b.vtxos {
			vtxoTxID, _ := chainhash.NewHashFromStr(vtxo.Txid)
			if outpoint.Hash.IsEqual(vtxoTxID) && outpoint.Index == vtxo.VOut {
				spentInputs = append(spentInputs, vtxo)
				break
			}
		}
	}
	return spentInputs
}

func (b *AssetTxBuilder) GetChangeReceivers() []types.DBReceiver {
	for i, rcv := range b.changeReceivers {
		for j, asset := range rcv.Assets {
			asset.ExtensionScript = b.extensionScript
			rcv.Assets[j] = asset
		}
		b.changeReceivers[i] = rcv
	}
	return b.changeReceivers
}

func (b *AssetTxBuilder) calculateSatsNeeded() (uint64, bool) {
	totalSatsOutput := uint64(0)
	for _, out := range b.outs {
		totalSatsOutput += uint64(out.Value)
	}

	totalSatsInput := uint64(0)
	for _, in := range b.ins {
		if in.Amount <= 0 {
			continue
		}
		totalSatsInput += uint64(in.Amount)
	}

	if totalSatsInput >= totalSatsOutput {
		satsChange := totalSatsInput - totalSatsOutput
		return satsChange, true
	}

	totalSatsNeeded := totalSatsOutput - totalSatsInput
	return totalSatsNeeded, false
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
) ([]IntentInput, []*arklib.TaprootMerkleProof, [][]*psbt.Unknown, error) {
	inputs := make([]IntentInput, 0, len(boardingUtxos)+len(vtxos))
	signingLeaves := make([]*arklib.TaprootMerkleProof, 0, len(boardingUtxos)+len(vtxos))
	arkFields := make([][]*psbt.Unknown, 0, len(boardingUtxos)+len(vtxos))

	for i, coin := range vtxos {
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

		rawIntentInput := intent.Input{
			OutPoint: outpoint,
			Sequence: wire.MaxTxInSequenceNum,
			WitnessUtxo: &wire.TxOut{
				Value:    int64(coin.Amount),
				PkScript: pkScript,
			},
		}

		input := IntentInput{
			Input: rawIntentInput,
		}

		taptreeField, err := txutils.VtxoTaprootTreeField.Encode(coin.Tapscripts)
		if err != nil {
			return nil, nil, nil, err
		}

		arkFields = append(arkFields, []*psbt.Unknown{taptreeField})

		if len(coin.Assets) > 0 {
			input.AssetExtension = &AssetExtension{
				Id:     coin.Assets[0].AssetId,
				Amount: coin.Assets[0].Amount,
				Index:  uint32(i),
			}
		}

		inputs = append(inputs, input)
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

		inputs = append(inputs, IntentInput{
			Input: intent.Input{
				OutPoint: outpoint,
				Sequence: wire.MaxTxInSequenceNum,
				WitnessUtxo: &wire.TxOut{
					Value:    int64(coin.Amount),
					PkScript: pkScript,
				},
			}})

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

		inputs = append(inputs, IntentInput{
			Input: intent.Input{
				OutPoint: outpoint,
				Sequence: wire.MaxTxInSequenceNum,
				WitnessUtxo: &wire.TxOut{
					Value:    input.WitnessUtxo.Value,
					PkScript: input.WitnessUtxo.PkScript,
				},
			}})

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

func checkSettleOptionsType(o interface{}) (*settleOptions, error) {
	opts, ok := o.(*settleOptions)
	if !ok {
		return nil, fmt.Errorf("invalid options type")
	}
	return opts, nil
}

func checkSendOffChainOptionsType(o interface{}) (*sendOffChainOptions, error) {
	opts, ok := o.(*sendOffChainOptions)
	if !ok {
		return nil, fmt.Errorf("invalid options type")
	}
	return opts, nil
}

func createRegisterIntentMessage(
	inputs []IntentInput,
	outputs []types.Receiver,
	cosignersPublicKeys []string,
) (
	string, []*wire.TxOut, error,
) {
	validAt := time.Now()
	expireAt := validAt.Add(2 * time.Minute).Unix()
	outputsTxOut := make([]*wire.TxOut, 0)
	onchainOutputsIndexes := make([]int, 0)

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

	assetAssetAnchor, err := createIntentAssetAnchor(inputs, outputs)
	if err != nil {
		return "", nil, err
	}
	if assetAssetAnchor != nil {
		outputsTxOut = append(outputsTxOut, assetAssetAnchor)
	}

	message, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		OnchainOutputIndexes: onchainOutputsIndexes,
		ExpireAt:             expireAt,
		ValidAt:              validAt.Unix(),
		CosignersPublicKeys:  cosignersPublicKeys,
	}.Encode()
	if err != nil {
		return "", nil, err
	}

	return message, outputsTxOut, nil
}

func createIntentAssetAnchor(
	intentInputs []IntentInput,
	outputs []types.Receiver,
) (*wire.TxOut, error) {
	if len(outputs) == 0 {
		return nil, nil
	}

	groupedIntentInputs := make(map[string][]IntentInput)
	for _, input := range intentInputs {
		if input.AssetExtension != nil {
			groupedIntentInputs[input.AssetExtension.Id] = append(
				groupedIntentInputs[input.AssetExtension.Id],
				input,
			)
		}
	}

	// Group outputs by asset ID so we create one AssetGroup per asset ID.
	outputsByAssetId := make(map[string][]asset.AssetOutput)
	for i, output := range outputs {
		if output.Asset == nil {
			continue
		}
		assetIdStr := output.Asset.AssetId
		outputsByAssetId[assetIdStr] = append(outputsByAssetId[assetIdStr], asset.AssetOutput{
			Type:   asset.AssetTypeIntent,
			Amount: output.Asset.Amount,
			Vout:   uint16(i),
		})
	}

	assetgroupList := make([]asset.AssetGroup, 0)
	for assetIdStr, assetOutputs := range outputsByAssetId {
		assetId, err := asset.NewAssetIdFromString(assetIdStr)
		if err != nil {
			return nil, err
		}

		assetInputs := make([]asset.AssetInput, 0)
		for _, input := range groupedIntentInputs[assetIdStr] {
			assetInputs = append(assetInputs, asset.AssetInput{
				Type:   asset.AssetTypeLocal,
				Vin:    uint16(input.AssetExtension.Index + 1), // +1 for the intent proof input
				Amount: input.AssetExtension.Amount,
			})
		}

		assetgroupList = append(assetgroupList, asset.AssetGroup{
			AssetId: assetId,
			Inputs:  assetInputs,
			Outputs: assetOutputs,
		})
	}

	if len(assetgroupList) == 0 {
		return nil, nil
	}

	assetPacket, err := asset.NewPacket(assetgroupList)
	if err != nil {
		return nil, err
	}
	pkScript, err := assetPacket.Serialize()
	if err != nil {
		return nil, err
	}

	return &wire.TxOut{
		Value:    0,
		PkScript: pkScript,
	}, nil
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

func findVtxosResultedFromSettledBy(vtxos []types.Vtxo, commitmentTxid string) []types.Vtxo {
	var result []types.Vtxo
	for _, v := range vtxos {
		if v.Preconfirmed || len(v.CommitmentTxids) != 1 {
			continue
		}
		if v.CommitmentTxids[0] == commitmentTxid {
			result = append(result, v)
		}
	}
	return result
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
