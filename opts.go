package arksdk

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

type Option func(options any) error

// SettleOptions allows to customize the vtxo signing process
type SettleOptions struct {
	ExtraSignerSessions    []tree.SignerSession
	WalletSignerDisabled   bool
	SelectRecoverableVtxos bool
	ExpiryPercentage       int64

	CancelCh <-chan struct{}
	EventsCh chan<- any
}

func newDefaultSettleOptions() *SettleOptions {
	return &SettleOptions{
		ExpiryPercentage: 10, // default to 10%
	}
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

// WithoutExpiryPercentage disables the percentage filtering regarding vtxo expiry
func WithoutExpiryPercentage(o any) error {
	opts, err := checkSettleOptionsType(o)
	if err != nil {
		return err
	}

	opts.ExpiryPercentage = 0
	return nil
}

func WithExpiryPercentage(percentage uint) Option {
	return func(o any) error {
		if percentage > 100 {
			return fmt.Errorf("percentage must be less than or equal to 100")
		}

		opts, err := checkSettleOptionsType(o)
		if err != nil {
			return err
		}

		opts.ExpiryPercentage = int64(percentage)
		return nil
	}
}
