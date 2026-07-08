package handlers

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

type Handler interface {
	// NewContract builds a contract from a key reference and optional handler-specific
	// params. Derivable handlers ignore params (may be nil). Non-derivable handlers
	// type-assert params to their concrete type (e.g. *VHTLCContractParams).
	NewContract(ctx context.Context, args any) (*types.Contract, error)
	GetKeyRefs(contract types.Contract) (map[string]string, error)
	GetKeyRef(contract types.Contract) (*identity.KeyRef, error)
	GetSignerKey(contract types.Contract) (*btcec.PublicKey, error)
	GetExitDelay(contract types.Contract) (*arklib.RelativeLocktime, error)
	GetTapscripts(contract types.Contract) ([]string, error)
	GetArgs(contract types.Contract) (any, error)
	GetCheckpointExitPath(contract types.Contract) ([]byte, error)
}
