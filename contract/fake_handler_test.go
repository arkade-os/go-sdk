package contract_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

// fakeHandler is a minimal handlers.Handler used by the registry tests so
// they don't depend on the default/boarding handlers' wiring (transport
// client, network, etc.). It produces a deterministic contract from a
// keyRef so the scan-loop tests can predict scripts and stage indexer
// hits the same way the default-handler tests do.
type fakeHandler struct {
	typ       types.ContractType
	exitDelay arklib.RelativeLocktime
}

func newFakeHandler(typ types.ContractType) *fakeHandler {
	return &fakeHandler{
		typ: typ,
		exitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 144,
		},
	}
}

func (h *fakeHandler) NewContract(
	_ context.Context, keyRef identity.KeyRef,
) (*types.Contract, error) {
	script := fakeScript(h.typ, keyRef.Id)
	return &types.Contract{
		Type:    h.typ,
		State:   types.ContractStateActive,
		Script:  script,
		Address: "fake:" + script,
		Params: map[string]string{
			ownerKeyIdParam: keyRef.Id,
		},
	}, nil
}

func (h *fakeHandler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	return map[string]string{ownerKeyIdParam: c.Params[ownerKeyIdParam]}, nil
}

func (h *fakeHandler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	id, ok := c.Params[ownerKeyIdParam]
	if !ok {
		return nil, fmt.Errorf("missing %s in params", ownerKeyIdParam)
	}
	return &identity.KeyRef{Id: id}, nil
}

func (h *fakeHandler) GetSignerKey(_ types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}

func (h *fakeHandler) GetExitDelay(_ types.Contract) (*arklib.RelativeLocktime, error) {
	d := h.exitDelay
	return &d, nil
}

func (h *fakeHandler) GetTapscripts(_ types.Contract) ([]string, error) {
	return nil, nil
}

// fakeScript mirrors fakeHandler.NewContract so tests can predict the
// script a given (type, keyId) pair will produce without going through the
// handler.
func fakeScript(typ types.ContractType, keyId string) string {
	h := sha256.Sum256([]byte(string(typ) + ":" + keyId))
	return hex.EncodeToString(h[:])
}

// compile-time check that fakeHandler satisfies the Handler interface.
var _ handlers.Handler = (*fakeHandler)(nil)
