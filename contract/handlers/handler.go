package handlers

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

type Handler interface {
	NewContract(ctx context.Context, keyRef identity.KeyRef) (*types.Contract, error)
	GetKeyRefs(contract types.Contract) (map[string]string, error)
	GetKeyRef(contract types.Contract) (*identity.KeyRef, error)
	GetSignerKey(contract types.Contract) (*btcec.PublicKey, error)
	GetExitDelay(contract types.Contract) (*arklib.RelativeLocktime, error)
	GetTapscripts(contract types.Contract) ([]string, error)
	// CandidateContracts derives one contract per accepted signer for the
	// given owner key. Used only by discovery (ScanContracts): each returned
	// contract carries the correct signerKey param so that, once persisted,
	// every downstream signing and reconstruction is signer-correct — even for
	// a contract that commits to a now-deprecated server signer.
	//
	// NewContract remains the allocation path (current signer only);
	// CandidateContracts is the discovery path (current + deprecated signers).
	CandidateContracts(
		ctx context.Context,
		keyRef identity.KeyRef,
		signers []*btcec.PublicKey,
	) ([]types.Contract, error)
}

// DefaultCandidateContracts is a fallback implementation of CandidateContracts
// for custom handlers that are not rotation-aware. It returns a single contract
// built from the current signer (equivalent to calling NewContract once),
// ignoring the signers argument. Custom handler authors with no rotation logic
// can delegate to this helper so they keep satisfying the Handler interface
// without losing allocation behavior.
func DefaultCandidateContracts(
	ctx context.Context,
	h Handler,
	keyRef identity.KeyRef,
	_ []*btcec.PublicKey,
) ([]types.Contract, error) {
	c, err := h.NewContract(ctx, keyRef)
	if err != nil {
		return nil, err
	}
	return []types.Contract{*c}, nil
}
