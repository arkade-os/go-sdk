package defaultHandler

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

const (
	ownerKeyIDParam         = "keyID"
	ownerKeyParam           = "ownerKey"
	signerKeyParam          = "signerKey"
	exitDelayParam          = "exitDelay"
	isOnchainParam          = "isOnchain"
	checkpointExitPathParam = "checkpointExitPath"
)

type defaultHandler struct {
	network arklib.Network
	client  client.TransportClient
	cache   *infoCache
}

func NewHandler(client client.TransportClient, network arklib.Network) handlers.Handler {
	return &defaultHandler{
		network: network,
		client:  client,
		cache:   newInfoCache(5 * time.Minute),
	}
}

func (h *defaultHandler) NewContract(
	ctx context.Context, keyRef wallet.KeyRef, contractOpts ...handlers.ContractOption,
) (*types.Contract, error) {
	info, err := h.getInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}

	buf, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signer pubkey: invalid format")
	}
	signerKey, err := btcec.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signer pubkey: %w", err)
	}

	o := handlers.NewDefaultContractOption()
	for _, opt := range contractOpts {
		opt(o)
	}

	delay := info.UnilateralExitDelay
	if o.IsOnchain {
		delay = info.BoardingExitDelay
	}
	exitDelay := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeSecond,
		Value: uint32(delay),
	}
	if delay < 512 {
		exitDelay = arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: uint32(delay),
		}
	}

	rawScript := script.NewDefaultVtxoScript(keyRef.PubKey, signerKey, exitDelay)
	taprootKey, _, err := rawScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to create taproot key: %w", err)
	}
	outputScript, err := txscript.PayToTaprootScript(taprootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create output script: %w", err)
	}

	var addr string
	if o.IsOnchain {
		btcNetwork := utils.ToBitcoinNetwork(h.network)
		address, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(taprootKey), &btcNetwork,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create onchain address: %w", err)
		}
		addr = address.EncodeAddress()
	} else {
		address := &arklib.Address{
			HRP:        h.network.Addr,
			Signer:     signerKey,
			VtxoTapKey: taprootKey,
		}
		addr, err = address.EncodeV0()
		if err != nil {
			return nil, fmt.Errorf("failed to create offchain address: %w", err)
		}
	}

	params := map[string]string{
		ownerKeyIDParam: keyRef.Id,
		ownerKeyParam:   hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey)),
		signerKeyParam:  hex.EncodeToString(schnorr.SerializePubKey(signerKey)),
		exitDelayParam:  strconv.FormatInt(delay, 10),
		isOnchainParam:  strconv.FormatBool(o.IsOnchain),
	}

	if !o.IsOnchain {
		params[checkpointExitPathParam] = info.CheckpointTapscript
	}

	return &types.Contract{
		Type:      types.ContractTypeDefault,
		Params:    params,
		Script:    hex.EncodeToString(outputScript),
		Address:   addr,
		State:     types.ContractStateActive,
		CreatedAt: time.Now(),
	}, nil
}

func (h *defaultHandler) GetKeyRefs(contract types.Contract) (map[string]string, error) {
	rawScript, keyID, err := h.getScript(contract)
	if err != nil {
		return nil, err
	}
	isOnchainStr := contract.Params[isOnchainParam]
	if len(isOnchainStr) <= 0 {
		isOnchainStr = "false"
	}
	isOnchain, err := strconv.ParseBool(isOnchainStr)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid isOnchain param: %w", contract.Script, err)
	}

	if isOnchain {
		return map[string]string{contract.Script: keyID}, nil
	}

	// For the offchain contract add also a key ref for the checkpoint script.
	checkpointExitPathStr, ok := contract.Params[checkpointExitPathParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing checkpoint exit path", contract.Script)
	}
	checkpointExitPath, err := hex.DecodeString(checkpointExitPathStr)
	if err != nil {
		return nil, fmt.Errorf(
			"contract %s has invalid checkpoint exit path format", contract.Script,
		)
	}

	exitPath := &script.CSVMultisigClosure{}
	valid, err := exitPath.Decode(checkpointExitPath)
	if err != nil {
		return nil, fmt.Errorf("failed to decode checkpoint exit path")
	}
	if !valid {
		return nil, fmt.Errorf("invalid checkpoint exit path")
	}

	collaborativePath := rawScript.ForfeitClosures()

	// Offchain sends spend a synthetic checkpoint VTXO whose tree is composed
	// from the server's checkpoint exit path and the vtxo's collaborative path.
	rawCheckpointScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{collaborativePath[0], exitPath},
	}
	taprootKey, _, err := rawCheckpointScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("failed to compute checkpoint script taproot key: %w", err)
	}

	checkpointScript, err := script.P2TRScript(taprootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute checkpoint: %w", err)
	}

	return map[string]string{
		contract.Script:                      keyID,
		hex.EncodeToString(checkpointScript): keyID,
	}, nil
}

func (h *defaultHandler) GetKeyRef(contract types.Contract) (*wallet.KeyRef, error) {
	if len(contract.Params) <= 0 {
		return nil, fmt.Errorf("contract %s has no parameters", contract.Script)
	}
	keyID, ok := contract.Params[ownerKeyIDParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing owner key ID", contract.Script)
	}
	if len(keyID) <= 0 {
		return nil, fmt.Errorf("contract %s has empty owner key ID", contract.Script)
	}
	key, ok := contract.Params[ownerKeyParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing owner key", contract.Script)
	}
	buf, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid owner key format", contract.Script)
	}
	ownerKey, err := schnorr.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid owner key: %w", contract.Script, err)
	}
	return &wallet.KeyRef{Id: keyID, PubKey: ownerKey}, nil
}

func (h *defaultHandler) GetExitDelay(contract types.Contract) (*arklib.RelativeLocktime, error) {
	if len(contract.Params) <= 0 {
		return nil, fmt.Errorf("contract %s has no parameters", contract.Script)
	}
	exitDelayStr, ok := contract.Params[exitDelayParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing exit delay", contract.Script)
	}
	exitDelayInt, err := strconv.ParseInt(exitDelayStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid exit delay format", contract.Script)
	}
	exitDelay := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeSecond,
		Value: uint32(exitDelayInt),
	}
	if exitDelayInt < 512 {
		exitDelay = arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: uint32(exitDelayInt),
		}
	}
	return &exitDelay, nil
}

func (h *defaultHandler) GetSignerKey(contract types.Contract) (*btcec.PublicKey, error) {
	if len(contract.Params) <= 0 {
		return nil, fmt.Errorf("contract %s has no parameters", contract.Script)
	}
	key, ok := contract.Params[signerKeyParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing signer key", contract.Script)
	}
	buf, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid signer key format", contract.Script)
	}
	signerKey, err := schnorr.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid signer key: %w", contract.Script, err)
	}
	return signerKey, nil
}

func (h *defaultHandler) GetTapscripts(contract types.Contract) ([]string, error) {
	rawScript, _, err := h.getScript(contract)
	if err != nil {
		return nil, err
	}
	return rawScript.Encode()
}

func (h *defaultHandler) getScript(
	contract types.Contract,
) (*script.TapscriptsVtxoScript, string, error) {
	keyRef, err := h.GetKeyRef(contract)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get key reference: %w", err)
	}
	signerKey, err := h.GetSignerKey(contract)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get signer key: %w", err)
	}
	exitDelay, err := h.GetExitDelay(contract)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get exit delay: %w", err)
	}
	return script.NewDefaultVtxoScript(keyRef.PubKey, signerKey, *exitDelay), keyRef.Id, nil
}

func (h *defaultHandler) getInfo(ctx context.Context) (*client.Info, error) {
	if cachedResp := h.cache.get(); cachedResp != nil {
		return cachedResp, nil
	}
	resp, err := h.client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	h.cache.set(resp)
	return resp, nil
}
