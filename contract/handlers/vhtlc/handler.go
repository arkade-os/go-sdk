package handler

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// Param keys stored in Contract.Params.
const (
	senderKeyIdParam                          = "senderKeyId"
	receiverKeyIdParam                        = "receiverKeyId"
	senderKeyParam                            = "senderKey"
	receiverKeyParam                          = "receiverKey"
	signerKeyParam                            = "signerKey"
	preimageHashParam                         = "preimageHash"
	refundLocktimeParam                       = "refundLocktime"
	unilateralClaimDelayParam                 = "unilateralClaimDelay"
	unilateralRefundDelayParam                = "unilateralRefundDelay"
	unilateralRefundWithoutReceiverDelayParam = "unilateralRefundWithoutReceiverDelay"
	// IMPORTANT: if this changes (it should not), the same should be done to the vhtlc store
	// implementaions!
	nonInteractiveReceiverParam = "nonInteractiveReceiver"
	nonInteractiveEmulatorParam = "nonInteractiveEmulator"
	checkpointExitPathParam     = "checkpointExitPath"
)

// handler is the shared stateless contract handler for VHTLC scripts.
// All VHTLC parameters are stored in Contract.Params, so the handler
// can rebuild the full tapscript tree from any persisted contract.
type handler struct {
	network arklib.Network
	client  client.Client
}

func newHandler(c client.Client, network arklib.Network) handler {
	return handler{
		network: network,
		client:  c,
	}
}

func (h handler) GetKeyRefs(contract types.Contract) (map[string]string, error) {
	keyRef, err := h.GetKeyRef(contract)
	if err != nil {
		return nil, err
	}

	keys := map[string]string{contract.Script: keyRef.Id}

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

	vhtlcScript, err := h.getVhtlc(contract)
	if err != nil {
		return nil, err
	}

	// Add the checkpoint exit closure to any vhtlc closures that contain the key ref.
	for _, closure := range []script.Closure{
		vhtlcScript.ClaimClosure,
		vhtlcScript.RefundClosure,
		vhtlcScript.RefundWithoutReceiverClosure,
	} {
		if !closureContainsKey(closure, keyRef.PubKey) {
			continue
		}

		rawCheckpointScript := script.TapscriptsVtxoScript{
			Closures: []script.Closure{closure, exitPath},
		}
		taprootKey, _, err := rawCheckpointScript.TapTree()
		if err != nil {
			return nil, fmt.Errorf("failed to compute checkpoint script taproot key: %w", err)
		}

		checkpointScript, err := script.P2TRScript(taprootKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute checkpoint: %w", err)
		}

		keys[hex.EncodeToString(checkpointScript)] = keyRef.Id
	}

	return keys, nil
}

func (h handler) GetKeyRef(contract types.Contract) (*identity.KeyRef, error) {
	if len(contract.Params) <= 0 {
		return nil, fmt.Errorf("contract %s has no parameters", contract.Script)
	}

	if keyId, ok := contract.Params[senderKeyIdParam]; ok {
		buf, err := hex.DecodeString(contract.Params[senderKeyParam])
		if err != nil {
			return nil, fmt.Errorf("contract %s has invalid sender key format", contract.Script)
		}
		pubkey, err := schnorr.ParsePubKey(buf)
		if err != nil {
			return nil, fmt.Errorf("contract %s has invalid sender key: %w", contract.Script, err)
		}
		return &identity.KeyRef{Id: keyId, PubKey: pubkey}, nil
	}

	keyId, ok := contract.Params[receiverKeyIdParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing sender or receiver key ID", contract.Script)
	}

	buf, err := hex.DecodeString(contract.Params[receiverKeyParam])
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid receiver key format", contract.Script)
	}
	pubkey, err := schnorr.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid receiver key: %w", contract.Script, err)
	}
	return &identity.KeyRef{Id: keyId, PubKey: pubkey}, nil
}

func (h handler) GetSignerKey(contract types.Contract) (*btcec.PublicKey, error) {
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

// GetExitDelay returns the conservative (longest) exit delay:
// refundWithoutReceiverDelay. This is always safe regardless of
// whether the wallet is the sender or receiver.
func (h handler) GetExitDelay(c types.Contract) (*arklib.RelativeLocktime, error) {
	if len(c.Params) <= 0 {
		return nil, fmt.Errorf("contract %s has no parameters", c.Script)
	}
	delay, ok := c.Params[unilateralRefundWithoutReceiverDelayParam]
	if !ok {
		return nil, fmt.Errorf(
			"contract %s is missing unilateral refund without receiver delay", c.Script,
		)
	}
	return utils.ParseDelay(delay)
}

func (h handler) GetTapscripts(c types.Contract) ([]string, error) {
	vhtlcScript, err := h.getVhtlc(c)
	if err != nil {
		return nil, err
	}
	return vhtlcScript.Encode()
}

func (h handler) GetCheckpointExitPath(contract types.Contract) ([]byte, error) {
	if len(contract.Params) <= 0 {
		return nil, fmt.Errorf("contract %s has no parameters", contract.Script)
	}
	checkpointExitPath, ok := contract.Params[checkpointExitPathParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing checkpoint exit path", contract.Script)
	}
	if len(checkpointExitPath) <= 0 {
		return nil, fmt.Errorf("contract %s has empty checkpoint exit path", contract.Script)
	}
	buf, err := hex.DecodeString(checkpointExitPath)
	if err != nil {
		return nil, fmt.Errorf(
			"contract %s has invalid checkpoint exit path format", contract.Script,
		)
	}
	return buf, nil
}

// newContract builds a new VHTLC contract from the given args. Is is used by both the vhtlc and
// non-interactive vhtlc handlers, therefore takes the extended NonInteractiveContractArgs type and
// expects the non interactive args for the closure to be optional.
func (h handler) newContract(
	serverParams *client.Info, args NonInteractiveContractArgs,
	contractType types.ContractType, withNonInteractive bool,
) (*types.Contract, error) {
	buf, err := hex.DecodeString(serverParams.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signer pubkey: invalid format")
	}
	fetchedSignerKey, err := btcec.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signer pubkey: %w", err)
	}
	signerKey := args.Signer
	if signerKey != nil {
		// Compare x-only: callers typically hold the signer key from an
		// x-only source (ark address, persisted signerKey param), so the
		// y parity of the provided point is meaningless.
		if !bytes.Equal(
			schnorr.SerializePubKey(signerKey), schnorr.SerializePubKey(fetchedSignerKey),
		) {
			keyStr := func(key *btcec.PublicKey) string {
				return hex.EncodeToString(schnorr.SerializePubKey(key))
			}
			return nil, fmt.Errorf(
				"invalid signer key: got %s, expected %s",
				keyStr(signerKey), keyStr(fetchedSignerKey),
			)
		}
	} else {
		signerKey = fetchedSignerKey
	}

	opts := args.ContractArgs.vhtlcOpts(signerKey)
	if withNonInteractive {
		opts = args.vhtlcOpts(signerKey)
	}
	s, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("build vhtlc script: %w", err)
	}

	tapKey, _, err := s.TapTree()
	if err != nil {
		return nil, fmt.Errorf("compute vhtlc tap tree: %w", err)
	}
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return nil, fmt.Errorf("compute vhtlc pkScript: %w", err)
	}
	addr, err := s.Address(h.network.Addr)
	if err != nil {
		return nil, fmt.Errorf("encode vhtlc address: %w", err)
	}

	params := map[string]string{
		senderKeyParam:            hex.EncodeToString(schnorr.SerializePubKey(args.Sender)),
		receiverKeyParam:          hex.EncodeToString(schnorr.SerializePubKey(args.Receiver)),
		signerKeyParam:            hex.EncodeToString(schnorr.SerializePubKey(signerKey)),
		preimageHashParam:         hex.EncodeToString(args.PreimageHash),
		refundLocktimeParam:       strconv.FormatUint(uint64(args.RefundLocktime), 10),
		unilateralClaimDelayParam: strconv.FormatUint(uint64(args.UnilateralClaimDelay.Value), 10),
		unilateralRefundDelayParam: strconv.FormatUint(
			uint64(opts.UnilateralRefundDelay.Value), 10,
		),
		unilateralRefundWithoutReceiverDelayParam: strconv.FormatUint(
			uint64(opts.UnilateralRefundWithoutReceiverDelay.Value), 10,
		),
		checkpointExitPathParam: serverParams.CheckpointTapscript,
	}

	// Only persist the key id of the role(s) the wallet actually owns: an
	// empty senderKeyId param would shadow the receiver one in GetKeyRef.
	if len(args.SenderKeyId) > 0 {
		params[senderKeyIdParam] = args.SenderKeyId
	}
	if len(args.ReceiverKeyId) > 0 {
		params[receiverKeyIdParam] = args.ReceiverKeyId
	}

	if opts.NonInteractiveClaim != nil {
		params[nonInteractiveReceiverParam] = hex.EncodeToString(
			opts.NonInteractiveClaim.ReceiverPkScript,
		)
		params[nonInteractiveEmulatorParam] = hex.EncodeToString(
			schnorr.SerializePubKey(opts.NonInteractiveClaim.EmulatorPubKey),
		)
	}

	return &types.Contract{
		Type:      contractType,
		Params:    params,
		Script:    hex.EncodeToString(pkScript),
		Address:   addr,
		State:     types.ContractStateActive,
		CreatedAt: time.Now(),
	}, nil
}

func (h handler) getVhtlc(contract types.Contract) (*vhtlc.VHTLCScript, error) {
	opts, err := h.parseContractParams(contract)
	if err != nil {
		return nil, err
	}

	return vhtlc.NewVHTLCScriptFromOpts(*opts)
}

func (h handler) parseContractParams(contract types.Contract) (*vhtlc.Opts, error) {
	senderKey, ok := contract.Params[senderKeyParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing sender key", contract.Script)
	}
	sender, err := parsePubkey(senderKey, "sender")
	if err != nil {
		return nil, fmt.Errorf("contract %s %w", contract.Script, err)
	}

	receiverKey, ok := contract.Params[receiverKeyParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing receiver key", contract.Script)
	}
	receiver, err := parsePubkey(receiverKey, "receiver")
	if err != nil {
		return nil, fmt.Errorf("contract %s %w", contract.Script, err)
	}

	signerKey, ok := contract.Params[signerKeyParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing signer key", contract.Script)
	}
	signer, err := parsePubkey(signerKey, "signer")
	if err != nil {
		return nil, fmt.Errorf("contract %s %w", contract.Script, err)
	}

	preimageHashHex, ok := contract.Params[preimageHashParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing preimage hash", contract.Script)
	}
	preimageHash, err := hex.DecodeString(preimageHashHex)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid preimage hash format", contract.Script)
	}

	refundLocktimeStr, ok := contract.Params[refundLocktimeParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing refund locktime", contract.Script)
	}
	refundLocktime, err := strconv.ParseUint(refundLocktimeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("contract %s has invalid refund locktime format", contract.Script)
	}

	unilateralClaimDelayStr, ok := contract.Params[unilateralClaimDelayParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing unilateral claim delay", contract.Script)
	}
	unilateralClaimDelay, err := utils.ParseDelay(unilateralClaimDelayStr)
	if err != nil {
		return nil, err
	}

	unilateralRefundDelayStr, ok := contract.Params[unilateralRefundDelayParam]
	if !ok {
		return nil, fmt.Errorf("contract %s is missing unilateral refund delay", contract.Script)
	}
	unilateralRefundDelay, err := utils.ParseDelay(unilateralRefundDelayStr)
	if err != nil {
		return nil, err
	}

	unilateralRefundWithoutReceiverDelayStr, ok :=
		contract.Params[unilateralRefundWithoutReceiverDelayParam]
	if !ok {
		return nil, fmt.Errorf(
			"contract %s is missing unilateral refund without receiver delay", contract.Script,
		)
	}
	unilateralRefundWithoutReceiverDelay, err := utils.ParseDelay(
		unilateralRefundWithoutReceiverDelayStr,
	)
	if err != nil {
		return nil, err
	}

	var nonInteractiveClaim *vhtlc.NonInteractiveClaimOpts
	// Non-interactive claim params are optional.
	if recvHex, ok := contract.Params[nonInteractiveReceiverParam]; ok {
		recv, err := hex.DecodeString(recvHex)
		if err != nil {
			return nil, fmt.Errorf(
				"contract %s has invalid non interactive receiver script: %w",
				contract.Script, err,
			)
		}
		emulator, err := parsePubkey(contract.Params[nonInteractiveEmulatorParam], "emulator")
		if err != nil {
			return nil, fmt.Errorf("contract %s %w", contract.Script, err)
		}
		nonInteractiveClaim = &vhtlc.NonInteractiveClaimOpts{
			ReceiverPkScript: recv,
			EmulatorPubKey:   emulator,
		}
	}

	return &vhtlc.Opts{
		Sender:                               sender,
		Receiver:                             receiver,
		Server:                               signer,
		PreimageHash:                         preimageHash,
		RefundLocktime:                       arklib.AbsoluteLocktime(refundLocktime),
		UnilateralClaimDelay:                 *unilateralClaimDelay,
		UnilateralRefundDelay:                *unilateralRefundDelay,
		UnilateralRefundWithoutReceiverDelay: *unilateralRefundWithoutReceiverDelay,
		NonInteractiveClaim:                  nonInteractiveClaim,
	}, nil
}

func closureContainsKey(closure script.Closure, pubkey *btcec.PublicKey) bool {
	for _, pk := range closurePubKeys(closure) {
		if pk.IsEqual(pubkey) {
			return true
		}
	}
	return false
}

func closurePubKeys(closure script.Closure) []*btcec.PublicKey {
	switch c := closure.(type) {
	case *script.MultisigClosure:
		return c.PubKeys
	case *script.CLTVMultisigClosure:
		return c.PubKeys
	case *script.ConditionMultisigClosure:
		return c.PubKeys
	case *script.CSVMultisigClosure:
		return c.PubKeys
	default:
		return nil
	}
}
