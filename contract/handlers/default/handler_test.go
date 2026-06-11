package defaultHandler_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

const (
	testUnilateralExitDelay int64 = 144
	testBoardingExitDelay   int64 = 1024
	testCheckpointTapscript       = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"
	signerKeyParam                = "signerKey"
)

var testNetwork = arklib.BitcoinRegTest

// stubClient is a minimal client.Client whose GetInfo returns a fixed Info.
// Only GetInfo (and Close) are exercised by the default handler.
type stubClient struct {
	info *client.Info
}

func (s *stubClient) GetInfo(context.Context) (*client.Info, error) { return s.info, nil }
func (s *stubClient) RegisterIntent(context.Context, string, string) (string, error) {
	return "", nil
}
func (s *stubClient) DeleteIntent(context.Context, string, string) error { return nil }
func (s *stubClient) EstimateIntentFee(context.Context, string, string) (int64, error) {
	return 0, nil
}
func (s *stubClient) ConfirmRegistration(context.Context, string) error { return nil }
func (s *stubClient) SubmitTreeNonces(context.Context, string, string, tree.TreeNonces) error {
	return nil
}
func (s *stubClient) SubmitTreeSignatures(
	context.Context, string, string, tree.TreePartialSigs,
) error {
	return nil
}
func (s *stubClient) SubmitSignedForfeitTxs(context.Context, []string, string) error { return nil }
func (s *stubClient) GetEventStream(
	context.Context, []string,
) (<-chan client.BatchEventChannel, func(), error) {
	return nil, func() {}, nil
}
func (s *stubClient) SubmitTx(
	context.Context, string, []string,
) (string, string, []string, error) {
	return "", "", nil, nil
}
func (s *stubClient) FinalizeTx(context.Context, string, []string) error { return nil }
func (s *stubClient) GetPendingTx(
	context.Context, string, string,
) ([]client.AcceptedOffchainTx, error) {
	return nil, nil
}
func (s *stubClient) GetTransactionsStream(
	context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	return nil, func() {}, nil
}
func (s *stubClient) ModifyStreamTopics(
	context.Context, []string, []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}
func (s *stubClient) OverwriteStreamTopics(
	context.Context, []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}
func (s *stubClient) Close() {}

func newKeyRef(t *testing.T) identity.KeyRef {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return identity.KeyRef{Id: "m/0/0", PubKey: priv.PubKey()}
}

func newSigner(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv.PubKey()
}

func newInfo(current *btcec.PublicKey) *client.Info {
	return &client.Info{
		SignerPubKey:        hex.EncodeToString(current.SerializeCompressed()),
		UnilateralExitDelay: testUnilateralExitDelay,
		BoardingExitDelay:   testBoardingExitDelay,
		CheckpointTapscript: testCheckpointTapscript,
		Network:             chaincfg.RegressionNetParams.Name,
	}
}

func xOnly(key *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

// TestCandidateContractsDistinctSigners verifies CandidateContracts returns one
// contract per signer, each with a distinct script and the matching signerKey
// param (offchain).
func TestCandidateContractsDistinctSigners(t *testing.T) {
	current := newSigner(t)
	deprecated := newSigner(t)
	h := defaultHandler.NewHandler(&stubClient{info: newInfo(current)}, testNetwork, false)

	keyRef := newKeyRef(t)
	signers := []*btcec.PublicKey{current, deprecated}
	got, err := h.CandidateContracts(t.Context(), keyRef, signers)
	require.NoError(t, err)
	require.Len(t, got, 2)

	require.NotEqual(t, got[0].Script, got[1].Script, "distinct signers must yield distinct scripts")
	require.Equal(t, xOnly(current), got[0].Params[signerKeyParam])
	require.Equal(t, xOnly(deprecated), got[1].Params[signerKeyParam])

	// NewContract (allocation path) must still produce the current-signer
	// contract identical to the first candidate.
	alloc, err := h.NewContract(t.Context(), keyRef)
	require.NoError(t, err)
	require.Equal(t, alloc.Script, got[0].Script)
	require.Equal(t, xOnly(current), alloc.Params[signerKeyParam])
}

// TestCandidateContractsBoardingVsOffchain verifies both the offchain
// (isOnchain=false) and boarding (isOnchain=true) handlers produce distinct
// per-signer addresses and scripts (EC-7).
func TestCandidateContractsBoardingVsOffchain(t *testing.T) {
	current := newSigner(t)
	deprecated := newSigner(t)
	keyRef := newKeyRef(t)
	signers := []*btcec.PublicKey{current, deprecated}

	for _, isOnchain := range []bool{false, true} {
		h := defaultHandler.NewHandler(&stubClient{info: newInfo(current)}, testNetwork, isOnchain)
		got, err := h.CandidateContracts(t.Context(), keyRef, signers)
		require.NoError(t, err)
		require.Len(t, got, 2)
		require.NotEqual(t, got[0].Address, got[1].Address, "per-signer addresses must differ")
		require.NotEqual(t, got[0].Script, got[1].Script, "per-signer scripts must differ")
		require.Equal(t, xOnly(current), got[0].Params[signerKeyParam])
		require.Equal(t, xOnly(deprecated), got[1].Params[signerKeyParam])
	}
}

// TestCandidateContractsXOnlyNormalization verifies a 33-byte compressed signer
// key is normalized to a 32-byte x-only signerKey param, and that a compressed
// and x-only form of the same key produce the SAME script (EC-4).
func TestCandidateContractsXOnlyNormalization(t *testing.T) {
	current := newSigner(t)
	deprecated := newSigner(t)
	h := defaultHandler.NewHandler(&stubClient{info: newInfo(current)}, testNetwork, false)
	keyRef := newKeyRef(t)

	// Compressed (33-byte) form.
	compressed := deprecated
	// x-only (32-byte) form parsed back to a pubkey.
	xOnlyKey, err := schnorr.ParsePubKey(schnorr.SerializePubKey(deprecated))
	require.NoError(t, err)

	got, err := h.CandidateContracts(
		t.Context(), keyRef, []*btcec.PublicKey{compressed, xOnlyKey},
	)
	require.NoError(t, err)
	require.Len(t, got, 2)

	// Stored param is always 32-byte x-only hex (64 hex chars).
	require.Len(t, got[0].Params[signerKeyParam], 64)
	require.Equal(t, xOnly(deprecated), got[0].Params[signerKeyParam])
	// Both forms of the same key collapse to the same script.
	require.Equal(t, got[0].Script, got[1].Script)
}
