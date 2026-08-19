package handler

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
)

const hash160Len = 20

type ContractArgs struct {
	SenderKeyId                          string
	ReceiverKeyId                        string
	Sender                               *btcec.PublicKey
	Receiver                             *btcec.PublicKey
	Signer                               *btcec.PublicKey
	PreimageHash                         []byte
	RefundLocktime                       arklib.AbsoluteLocktime
	UnilateralClaimDelay                 arklib.RelativeLocktime
	UnilateralRefundDelay                arklib.RelativeLocktime
	UnilateralRefundWithoutReceiverDelay arklib.RelativeLocktime
}

// validate checks that all required arguments are present.
// The validation of exit delays is left to the handler, which ensures that they are all at least
// match the unilateral exit delay fetched from server params.
// validate DOES NOT require the signer key to be present, the handler handles both cases:
// - if not present, uses the one fetched from server params
// - if present, ensures it matches the one fetched from server params
func (a ContractArgs) validate(serverParams client.Info) error {
	if len(a.SenderKeyId) <= 0 && len(a.ReceiverKeyId) <= 0 {
		return fmt.Errorf("key id ref must be provided for sender or receiver")
	}
	if a.Sender == nil {
		return fmt.Errorf("missing sender pubkey")
	}
	if a.Receiver == nil {
		return fmt.Errorf("missing receiver pubkey")
	}
	if len(a.PreimageHash) <= 0 {
		return fmt.Errorf("missing preimage hash")
	}
	if len(a.PreimageHash) != hash160Len {
		return fmt.Errorf("preimage hash must be %d bytes", hash160Len)
	}
	return a.validateLocktimes(serverParams)
}

func (a ContractArgs) validateLocktimes(serverParams client.Info) error {
	if a.RefundLocktime == 0 {
		return fmt.Errorf("refund locktime must be greater than 0")
	}
	if int64(a.UnilateralClaimDelay.Value) < serverParams.UnilateralExitDelay {
		return fmt.Errorf(
			"unilateral claim delay must be greater than %d", serverParams.UnilateralExitDelay,
		)
	}
	if int64(a.UnilateralRefundDelay.Value) < serverParams.UnilateralExitDelay {
		return fmt.Errorf(
			"unilateral refund delay must be greater than %d", serverParams.UnilateralExitDelay,
		)
	}
	if int64(a.UnilateralRefundWithoutReceiverDelay.Value) < serverParams.UnilateralExitDelay {
		return fmt.Errorf(
			"unilateral refund without receiver delay must be greater than %d",
			serverParams.UnilateralExitDelay,
		)
	}
	return nil
}

func (a ContractArgs) vhtlcOpts(signerKey *btcec.PublicKey) vhtlc.Opts {
	return vhtlc.Opts{
		Sender:                               a.Sender,
		Receiver:                             a.Receiver,
		Server:                               signerKey,
		PreimageHash:                         a.PreimageHash,
		RefundLocktime:                       a.RefundLocktime,
		UnilateralClaimDelay:                 a.UnilateralClaimDelay,
		UnilateralRefundDelay:                a.UnilateralRefundDelay,
		UnilateralRefundWithoutReceiverDelay: a.UnilateralRefundWithoutReceiverDelay,
	}
}

type NonInteractiveContractArgs struct {
	ContractArgs
	NonInteractiveReceiver []byte
	NonInteractiveEmulator *btcec.PublicKey
}

func (a NonInteractiveContractArgs) validate(serverParams client.Info) error {
	if err := a.ContractArgs.validate(serverParams); err != nil {
		return err
	}
	if len(a.NonInteractiveReceiver) <= 0 {
		return fmt.Errorf("missing non-interactive receiver script")
	}
	if a.NonInteractiveEmulator == nil {
		return fmt.Errorf("missing non-interactive emulator pubkey")
	}
	return nil
}

func (a NonInteractiveContractArgs) vhtlcOpts(signerKey *btcec.PublicKey) vhtlc.Opts {
	opts := a.ContractArgs.vhtlcOpts(signerKey)
	opts.NonInteractiveClaim = &vhtlc.NonInteractiveClaimOpts{
		ReceiverPkScript: a.NonInteractiveReceiver,
		EmulatorPubKey:   a.NonInteractiveEmulator,
	}
	return opts
}
