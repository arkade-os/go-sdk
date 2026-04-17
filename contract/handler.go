package contract

import (
	"context"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

// Keystore is the subset of wallet.WalletService the Manager needs for key management.
// wallet.WalletService satisfies this interface automatically.
type Keystore interface {
	NewKey(ctx context.Context, opts ...wallet.KeyOption) (*wallet.KeyRef, error)
	GetKey(ctx context.Context, opts ...wallet.KeyOption) (*wallet.KeyRef, error)
	ListKeys(ctx context.Context) ([]wallet.KeyRef, error)
}

// Handler knows how to derive all address facets from a wallet key for one contract type.
type Handler interface {
	Type() string
	// DeriveContract produces a fully populated Contract from a key and server config.
	DeriveContract(ctx context.Context, key wallet.KeyRef, cfg *clientTypes.Config) (*Contract, error)
	// SerializeParams converts type-specific params to a string map for storage.
	SerializeParams(params any) (map[string]string, error)
	// DeserializeParams restores type-specific params from a string map.
	DeserializeParams(params map[string]string) (any, error)
}
