//go:build smoke

package e2e_test

import (
	"testing"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

func TestSmokeWalletRestore(t *testing.T) {
	ctx := t.Context()
	alice := setupClient(t, "")

	mnemonic, err := alice.Dump(ctx)
	require.NoError(t, err, "❌ dump failed: expected no error, got %w", err)
	require.NotEmpty(t, mnemonic, "❌ dump failed: got empty mnemonic")

	t.Logf("✅ setup alice client [mnemonic='%s']", mnemonic)

	gapLimit := 100
	totalAddresses := 10_000
	expectedVtxos := totalAddresses / gapLimit

	t.Log("ℹ️ funding alice client...")
	c := 0
	for i := range totalAddresses {
		if (i+1)%gapLimit == 0 {
			faucetOffchain(t, alice, 0.0001)
			c++
			continue
		}
		_, err := alice.NewOffchainAddress(ctx)
		require.NoError(
			t, err, "❌ funding failed: expected no error on deriving address, got %w", err,
		)
	}

	_, offchainAddresses, _, _, err := alice.GetAddresses(ctx)
	require.NoError(
		t, err, "❌ funding failed: expected no error on getting derived addresses, got %w", err,
	)
	require.Len(
		t, offchainAddresses, totalAddresses,
		"❌ funding failed: got %d derived addresses, expected %d",
		len(offchainAddresses), totalAddresses,
	)

	vtxos, _, err := alice.ListVtxos(ctx)
	require.NoError(t, err, "❌ funding failed: expected no error on getting vtxos, got %w", err)
	require.Len(
		t, vtxos, expectedVtxos,
		"❌ funding failed: got %d vtxos, expected %d", len(vtxos), expectedVtxos,
	)

	totAmount := uint64(0)
	for _, vtxo := range vtxos {
		totAmount += vtxo.Amount
	}

	balance, err := alice.Balance(ctx)
	require.NoError(t, err, "❌ funding failed: expected no error on getting balance, got %w", err)
	require.NotEmpty(t, balance, "❌ funding failed: got empty balance")
	require.Equal(
		t, 1000000, int(balance.OffchainBalance.Total),
		"❌ funding failed: got %d balance, expected %d", balance.OffchainBalance.Total, 1000000,
	)

	t.Logf(
		"✅ funded alice client [addresses=%d vtxos=%d balance=%d]",
		len(offchainAddresses), len(vtxos), balance.OffchainBalance.Total,
	)

	t.Log("ℹ️ restoring alice client...")
	aliceRestored := setupClient(t, mnemonic, arksdk.WithGapLimit(100))
	balanceRestored, err := aliceRestored.Balance(ctx)
	require.NoError(t, err, "❌ restore failed: expected no error on getting balance, got %w", err)
	require.NotEmpty(t, balance, "❌ restore failed: got empty balance")
	require.Equal(
		t, int(balance.OffchainBalance.Total), int(balanceRestored.OffchainBalance.Total),
		"❌ restore failed: got %d balance, expected %d",
		balanceRestored.OffchainBalance.Total, balance.OffchainBalance.Total,
	)

	_, offchainAddressesRestored, _, _, err := aliceRestored.GetAddresses(ctx)
	require.NoError(t, err, "❌ restore failed: expected no error, got %w", err)
	require.Len(
		t, offchainAddressesRestored, totalAddresses,
		"❌ restore failed: got %d derived addresses, expected %d",
		len(offchainAddressesRestored), totalAddresses,
	)

	vtxosRestored, _, err := aliceRestored.ListVtxos(ctx)
	require.NoError(t, err, "❌ restore failed: expected no error, got %w", err)
	require.Len(
		t, vtxosRestored, len(vtxos),
		"❌ restore failed: got %d restored vtxos, expected %d",
		len(vtxosRestored), len(vtxos),
	)

	t.Logf(
		"✅ restored alice client [addresses=%d vtxos=%d balance=%d]",
		len(offchainAddressesRestored), len(vtxosRestored), balanceRestored.OffchainBalance.Total,
	)
}
