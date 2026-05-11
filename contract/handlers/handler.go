package handlers

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

type Handler interface {
	NewContract(ctx context.Context, keyRef wallet.KeyRef) (*types.Contract, error)
	GetKeyRefs(contract types.Contract) (map[string]string, error)
	GetKeyRef(contract types.Contract) (*wallet.KeyRef, error)
	GetSignerKey(contract types.Contract) (*btcec.PublicKey, error)
	GetExitDelay(contract types.Contract) (*arklib.RelativeLocktime, error)
	GetTapscripts(contract types.Contract) ([]string, error)
}
