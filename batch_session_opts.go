package arksdk

import (
	"fmt"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

const maxRetryNum = 5

type BatchSessionOption func(options *batchSessionOptions) error

// ApplyBatchOptions applies the given BatchSessionOption functions to a new default
// batchSessionOptions struct and returns the first error encountered, if any.
// Exposed for use in external (arksdk_test) test packages.
func ApplyBatchSessionOptions(opts ...BatchSessionOption) error {
	_, err := applyBatchSessionOptions(opts...)
	return err
}

func WithRetries(num int) BatchSessionOption {
	return func(o *batchSessionOptions) error {
		if o.retryNum > 0 {
			return fmt.Errorf("retry num already set")
		}
		if num <= 0 || num > maxRetryNum {
			return fmt.Errorf("retry num must be in range [1, %d]", maxRetryNum)
		}
		o.retryNum = num
		return nil
	}
}

// WithSettleVtxos restricts a Settle call to exactly the provided vtxos.
// When set (non-nil), Settle skips getSpendableVtxos and uses only the provided
// vtxos as inputs. Used by reconcileDeprecatedSigners to settle only the
// ToMigrate subset rather than the full spendable set.
//
// Semantics of the argument:
//   - nil slice: "not set" sentinel — Settle behaves exactly as if the option
//     were not provided (full spendable settle).
//   - non-nil empty slice ([]clienttypes.Vtxo{}): settle zero vtxos, which
//     returns ErrNoFundsToSettle.
//
// The vtxos must be present in the wallet's contract store; any vtxo missing a
// contract entry is silently omitted from signing-key resolution (same behavior
// as today for vtxos without a contract).
func WithSettleVtxos(vtxos []clienttypes.Vtxo) BatchSessionOption {
	return func(o *batchSessionOptions) error {
		o.settleVtxos = vtxos
		return nil
	}
}

func applyBatchSessionOptions(opts ...BatchSessionOption) (*batchSessionOptions, error) {
	o := newDefaultBatchSessionOptions()
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("batch session option cannot be nil")
		}
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

type batchSessionOptions struct {
	retryNum int
	// settleVtxos, when non-nil, overrides getSpendableVtxos in Settle and
	// restricts the settlement to exactly these vtxos. A nil value means "not
	// set" (full settle); a non-nil empty slice means "settle zero vtxos".
	settleVtxos []clienttypes.Vtxo
}

func newDefaultBatchSessionOptions() *batchSessionOptions {
	return &batchSessionOptions{}
}
