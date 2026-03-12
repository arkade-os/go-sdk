package arksdk

import (
	"fmt"
)

const maxRetryNum = 5

type BatchSessionOption func(options *batchSessionOptions) error

// ApplyBatchOptions applies the given BatchSessionOption functions to a new default
// batchSessionOptions struct and returns the first error encountered, if any.
// Exposed for use in external (arksdk_test) test packages.
func ApplyBatchSessionOptions(opts ...BatchSessionOption) error {
	o := newDefaultBatchSessionOptions()
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return err
		}
	}
	return nil
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

type batchSessionOptions struct {
	retryNum int
}

func newDefaultBatchSessionOptions() *batchSessionOptions {
	return &batchSessionOptions{}
}
