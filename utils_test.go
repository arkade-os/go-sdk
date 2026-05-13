package arksdk_test

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/btcsuite/btcd/chaincfg"
)

type mockIdentity struct{}

func (m *mockIdentity) GetType() string {
	return "mock"
}
func (m *mockIdentity) Create(_ context.Context, _ chaincfg.Params, _, _ string) (string, error) {
	return "", nil
}
func (m *mockIdentity) Lock(_ context.Context) error {
	return nil
}
func (m *mockIdentity) Unlock(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (m *mockIdentity) IsLocked() bool {
	return false
}
func (m *mockIdentity) NextKeyId(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (m *mockIdentity) GetKeyIndex(_ context.Context, _ string) (uint32, error) {
	return 0, nil
}
func (m *mockIdentity) NewKey(_ context.Context) (*identity.KeyRef, error) {
	return &identity.KeyRef{}, nil
}
func (m *mockIdentity) GetKey(_ context.Context, _ string) (*identity.KeyRef, error) {
	return &identity.KeyRef{}, nil
}
func (m *mockIdentity) ListKeys(_ context.Context) ([]identity.KeyRef, error) {
	return nil, nil
}
func (m *mockIdentity) SignTransaction(
	_ context.Context, _ string, _ map[string]string,
) (string, error) {
	return "", nil
}
func (m *mockIdentity) SignMessage(_ context.Context, _ []byte) (string, error) {
	return "", nil
}
func (m *mockIdentity) Dump(_ context.Context) (string, error) {
	return "", nil
}
func (m *mockIdentity) NewVtxoTreeSigner(_ context.Context) (tree.SignerSession, error) {
	return nil, nil
}
