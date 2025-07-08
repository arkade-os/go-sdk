package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

type Option func(options interface{}) error

// SettleOptions allows to customize the vtxo signing process
type SettleOptions struct {
	ExtraSignerSessions    []tree.SignerSession
	WalletSignerDisabled   bool
	SelectRecoverableVtxos bool

	CancelCh <-chan struct{}
	EventsCh chan<- any
}

// name alias, sub-dust vtxos are recoverable vtxos
var WithSubDustVtxos = WithRecoverableVtxos

func WithRecoverableVtxos(o any) error {
	opts, err := checkSettleOptionsType(o)
	if err != nil {
		return err
	}

	opts.SelectRecoverableVtxos = true
	return nil
}

func WithEventsCh(ch chan<- any) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.EventsCh = ch
		return nil
	}
}

// WithoutWalletSigner disables the wallet signer
func WithoutWalletSigner(o any) error {
	opts, err := checkSettleOptionsType(o)
	if err != nil {
		return err
	}

	opts.WalletSignerDisabled = true
	return nil
}

// WithExtraSigner allows to use a set of custom signer for the vtxo tree signing process
func WithExtraSigner(signerSessions ...tree.SignerSession) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		if len(signerSessions) == 0 {
			return fmt.Errorf("no signer sessions provided")
		}

		opts.ExtraSignerSessions = signerSessions
		return nil
	}
}

// WithCancelCh allows to cancel the settlement process
func WithCancelCh(ch <-chan struct{}) Option {
	return func(o any) error {
		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.CancelCh = ch
		return nil
	}
}
