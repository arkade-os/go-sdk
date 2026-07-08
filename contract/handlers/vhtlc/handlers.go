package handler

import (
	"context"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
)

type vhtlcHandler struct {
	handler
}

// NewHandler returns the VHTLC contract handler
func NewHandler(c client.Client, network arklib.Network) handlers.Handler {
	handler := newHandler(c, network)
	return vhtlcHandler{handler}
}

func (h vhtlcHandler) NewContract(ctx context.Context, args any) (*types.Contract, error) {
	parsed, ok := args.(ContractArgs)
	if !ok {
		return nil, fmt.Errorf(
			"invalid contract args type: got %T, expected %T", args, ContractArgs{},
		)
	}
	contractArgs := NonInteractiveContractArgs{ContractArgs: parsed}

	serverParams, err := h.client.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get server params: %w", err)
	}

	if err := parsed.validate(*serverParams); err != nil {
		return nil, err
	}
	return h.newContract(serverParams, contractArgs, types.ContractTypeVHTLC, false)
}

func (h vhtlcHandler) GetArgs(contract types.Contract) (any, error) {
	signerKey, err := h.GetSignerKey(contract)
	if err != nil {
		return nil, err
	}
	senderKey, err := parsePubkey(contract.Params[senderKeyParam], "sender")
	if err != nil {
		return nil, err
	}
	receiverKey, err := parsePubkey(contract.Params[receiverKeyParam], "receiver")
	if err != nil {
		return nil, err
	}
	preimageHash, err := parsePreimageHash(contract.Params[preimageHashParam])
	if err != nil {
		return nil, err
	}
	refundLocktime, err := parseAbsoluteLocktime(contract.Params[refundLocktimeParam])
	if err != nil {
		return nil, err
	}

	unilateralClaimDelay, err := parseRelativeLocktime(contract.Params[unilateralClaimDelayParam])
	if err != nil {
		return nil, err
	}
	unilateralRefundDelay, err := parseRelativeLocktime(contract.Params[unilateralRefundDelayParam])
	if err != nil {
		return nil, err
	}
	unilateralRefundWithoutReceiverDelay, err := parseRelativeLocktime(
		contract.Params[unilateralRefundWithoutReceiverDelayParam],
	)
	if err != nil {
		return nil, err
	}

	return ContractArgs{
		SenderKeyId:                          contract.Params[senderKeyIdParam],
		ReceiverKeyId:                        contract.Params[receiverKeyIdParam],
		Sender:                               senderKey,
		Receiver:                             receiverKey,
		Signer:                               signerKey,
		PreimageHash:                         preimageHash,
		RefundLocktime:                       refundLocktime,
		UnilateralClaimDelay:                 *unilateralClaimDelay,
		UnilateralRefundDelay:                *unilateralRefundDelay,
		UnilateralRefundWithoutReceiverDelay: *unilateralRefundWithoutReceiverDelay,
	}, nil
}

type vhtlcNonInteractiveHandler struct {
	handler
}

// NewHandler returns the VHTLC contract handler
func NewNonInteractiveHandler(c client.Client, network arklib.Network) handlers.Handler {
	handler := newHandler(c, network)
	return vhtlcNonInteractiveHandler{handler}
}

func (h vhtlcNonInteractiveHandler) NewContract(
	ctx context.Context, args any,
) (*types.Contract, error) {
	contractArgs, ok := args.(NonInteractiveContractArgs)
	if !ok {
		return nil, fmt.Errorf(
			"invalid contract args type: got %T, expected %T", args, NonInteractiveContractArgs{},
		)
	}

	serverParams, err := h.client.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get server params: %w", err)
	}

	if err := contractArgs.validate(*serverParams); err != nil {
		return nil, err
	}
	return h.newContract(serverParams, contractArgs, types.ContractTypeNonInteractiveVHTLC, true)
}

func (h vhtlcNonInteractiveHandler) GetArgs(contract types.Contract) (any, error) {
	signerKey, err := h.GetSignerKey(contract)
	if err != nil {
		return nil, err
	}
	senderKey, err := parsePubkey(contract.Params[senderKeyParam], "sender")
	if err != nil {
		return nil, err
	}
	receiverKey, err := parsePubkey(contract.Params[receiverKeyParam], "receiver")
	if err != nil {
		return nil, err
	}
	preimageHash, err := parsePreimageHash(contract.Params[preimageHashParam])
	if err != nil {
		return nil, err
	}
	refundLocktime, err := parseAbsoluteLocktime(contract.Params[refundLocktimeParam])
	if err != nil {
		return nil, err
	}

	unilateralClaimDelay, err := parseRelativeLocktime(contract.Params[unilateralClaimDelayParam])
	if err != nil {
		return nil, err
	}
	unilateralRefundDelay, err := parseRelativeLocktime(contract.Params[unilateralRefundDelayParam])
	if err != nil {
		return nil, err
	}
	unilateralRefundWithoutReceiverDelay, err := parseRelativeLocktime(
		contract.Params[unilateralRefundWithoutReceiverDelayParam],
	)
	if err != nil {
		return nil, err
	}
	nonInteractiveReceiver, err := parseReceiverScript(contract.Params[nonInteractiveReceiverParam])
	if err != nil {
		return nil, err
	}
	emulatorKey, err := parsePubkey(contract.Params[nonInteractiveEmulatorParam], "emulator")
	if err != nil {
		return nil, err
	}

	return NonInteractiveContractArgs{
		ContractArgs: ContractArgs{
			SenderKeyId:                          contract.Params[senderKeyIdParam],
			ReceiverKeyId:                        contract.Params[receiverKeyIdParam],
			Sender:                               senderKey,
			Receiver:                             receiverKey,
			Signer:                               signerKey,
			PreimageHash:                         preimageHash,
			RefundLocktime:                       refundLocktime,
			UnilateralClaimDelay:                 *unilateralClaimDelay,
			UnilateralRefundDelay:                *unilateralRefundDelay,
			UnilateralRefundWithoutReceiverDelay: *unilateralRefundWithoutReceiverDelay,
		},
		NonInteractiveReceiver: nonInteractiveReceiver,
		NonInteractiveEmulator: emulatorKey,
	}, nil
}
