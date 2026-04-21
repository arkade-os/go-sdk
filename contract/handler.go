package contract

import (
	"context"

	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

// Keystore is the subset of wallet.WalletService the Manager needs for key management.
// wallet.WalletService satisfies this interface automatically.
type Keystore interface {
	NewKey(ctx context.Context, opts ...wallet.KeyOption) (*wallet.KeyRef, error)
	GetKey(ctx context.Context, opts ...wallet.KeyOption) (*wallet.KeyRef, error)
	ListKeys(ctx context.Context) ([]wallet.KeyRef, error)
}
