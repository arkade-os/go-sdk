package handlers

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

type Handler interface {
	// Derivable returns whether this handler can derive contracts from an HD key
	// alone. Derivable handlers participate in ScanContracts gap-limit recovery.
	// Non-derivable handlers (VHTLC, delegate, covenant) require external params
	// passed via Manager.NewContract with WithParams.
	Derivable() bool
	// NewContract builds a contract from a key reference and optional handler-specific
	// params. Derivable handlers ignore params (may be nil). Non-derivable handlers
	// type-assert params to their concrete type (e.g. *VHTLCContractParams).
	NewContract(ctx context.Context, keyRef identity.KeyRef, params any) (*types.Contract, error)
	GetKeyRefs(contract types.Contract) (map[string]string, error)
	GetKeyRef(contract types.Contract) (*identity.KeyRef, error)
	GetSignerKey(contract types.Contract) (*btcec.PublicKey, error)
	GetExitDelay(contract types.Contract) (*arklib.RelativeLocktime, error)
	GetTapscripts(contract types.Contract) ([]string, error)
}
