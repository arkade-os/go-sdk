package e2e_test

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

const (
	// aliceVtxoCount is the total number of VTXOs Alice receives before rotation.
	aliceVtxoCount = 150
	// aliceAssetCount is how many of Alice's VTXOs carry one issued asset.
	aliceAssetCount = 20
	// satsPerVtxo is the BTC amount attached to each funded VTXO.
	satsPerVtxo = uint64(2_000)
	// satsPerAssetVtxo is the BTC amount attached to each asset-carrying VTXO.
	satsPerAssetVtxo = uint64(333)
	// assetAmount is the amount attached to each asset-carrying VTXO.
	assetAmount = uint64(1000)
	// funderBalance gives the funder wallet extra BTC headroom for sends.
	funderBalance = uint64(1_000_000)
	// signerRotationSpendSats is the BTC amount spent after migration to prove funds are usable.
	signerRotationSpendSats = uint64(1_000)
)

type signerRotationExpected struct {
	Sats          uint64
	AssetBalances map[string]uint64
	VtxoCount     int
}

type signerRotationFundingConfig struct {
	VtxoCount  int
	AssetCount int
}

func TestSignerRotationRestartSmoke(t *testing.T) {
	datadir := t.TempDir()
	alice := setupClientWithDir(t, datadir, "")
	expected, oldSigner := fundSignerRotationWallet(t, alice)

	t.Logf("funded wallet under signer %s", oldSigner)
	currentSigner := waitForSignerRotation(
		t,
		alice,
		oldSigner,
		"Rotate arkd now: make a new signer current, keep the old signer deprecated before cutoff",
	)

	alice.Stop()
	restarted := loadClientWithDir(t, datadir)

	requireMigratedToCurrentSigner(t, restarted, currentSigner, expected)
	requireInactiveContracts(t, restarted)

	restarted.Stop()
	restartedAgain := loadClientWithDir(t, datadir)

	requireMigratedToCurrentSigner(t, restartedAgain, currentSigner, expected)
	requireInactiveContracts(t, restartedAgain)
	requireSpendableMigratedFunds(t, restartedAgain, expected)
}

func TestSignerRotationRuntimeSmoke(t *testing.T) {
	ctx := t.Context()

	alice := setupClient(t, "", arksdk.WithRefreshDbInterval(30*time.Second))
	expected, oldSigner := fundSignerRotationWallet(t, alice)

	t.Logf("funded live wallet under signer %s", oldSigner)
	currentSigner := waitForSignerRotation(
		t,
		alice,
		oldSigner,
		"Rotate arkd now without restarting Alice: make a new signer current, keep the old signer deprecated before cutoff",
	)

	require.Eventually(t, func() bool {
		vtxos, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
		if err != nil || len(vtxos) == 0 || totalVtxoAmount(vtxos) != expected.Sats {
			return false
		}
		if !assetBalancesEqual(assetBalancesFromVtxos(vtxos), expected.AssetBalances) {
			return false
		}
		for _, v := range vtxos {
			if vtxoSignerKey(t, alice, v) != currentSigner {
				return false
			}
		}
		return true
	}, 3*time.Minute, 2*time.Second,
		"live wallet should migrate after the next periodic refresh")

	requireMigratedToCurrentSigner(t, alice, currentSigner, expected)
	requireInactiveContracts(t, alice)
	requireSpendableMigratedFunds(t, alice, expected)
}

func btcFromSats(sats uint64) float64 {
	return float64(sats) / 1e8
}

func (c signerRotationFundingConfig) BtcOnlyVtxoCount() int {
	return c.VtxoCount - c.AssetCount
}

func (c signerRotationFundingConfig) ExpectedSats() uint64 {
	return uint64(c.BtcOnlyVtxoCount())*satsPerVtxo +
		uint64(c.AssetCount)*satsPerAssetVtxo
}

func fundSignerRotationWallet(
	t *testing.T, alice arksdk.Wallet,
) (signerRotationExpected, string) {
	t.Helper()
	ctx := t.Context()

	cfg := signerRotationFundingConfig{
		VtxoCount:  aliceVtxoCount,
		AssetCount: aliceAssetCount,
	}
	require.LessOrEqual(t, cfg.AssetCount, cfg.VtxoCount,
		"asset VTXO count must not exceed total VTXO count")
	expectedSats := cfg.ExpectedSats()
	require.Greater(t, expectedSats, signerRotationSpendSats,
		"configured signer rotation funding must leave enough BTC to spend after migration")

	funder := setupClient(t, "")
	funderSats := expectedSats + funderBalance
	t.Logf(
		"signer rotation funding: vtxos=%d btc_only=%d assets=%d vtxo_sats=%d asset_amount=%d sats=%d funder_sats=%d",
		cfg.VtxoCount, cfg.BtcOnlyVtxoCount(), cfg.AssetCount,
		satsPerVtxo, assetAmount, expectedSats, funderSats,
	)
	faucetOffchain(t, funder, btcFromSats(funderSats))

	expected := signerRotationExpected{
		AssetBalances: make(map[string]uint64, cfg.AssetCount),
		VtxoCount:     cfg.VtxoCount,
	}

	for i := 0; i < cfg.BtcOnlyVtxoCount(); i++ {
		addr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, addr)

		sendOffchainEventually(t, funder, []clientTypes.Receiver{{
			To:     addr,
			Amount: satsPerVtxo,
		}})
		expected.Sats += satsPerVtxo
	}

	for i := 0; i < cfg.AssetCount; i++ {
		_, assetIDs, err := funder.IssueAsset(ctx, assetAmount, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIDs, 1)
		assetID := assetIDs[0].String()

		requireAssetBalance(t, funder, assetID, assetAmount)

		addr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, addr)

		sendOffchainEventually(t, funder, []clientTypes.Receiver{{
			To:     addr,
			Amount: satsPerAssetVtxo,
			Assets: []clientTypes.Asset{{
				AssetId: assetID,
				Amount:  assetAmount,
			}},
		}})

		expected.Sats += satsPerAssetVtxo
		expected.AssetBalances[assetID] = assetAmount
	}

	preVtxos := requireSpendableFunding(t, alice, expected)

	oldSigner := vtxoSignerKey(t, alice, preVtxos[0])
	require.NotEmpty(t, oldSigner)
	for _, vtxo := range preVtxos {
		require.Equal(t, oldSigner, vtxoSignerKey(t, alice, vtxo),
			"every pre-rotation funding vtxo must commit to the same old signer")
	}

	return expected, oldSigner
}

func requireMigratedToCurrentSigner(
	t *testing.T, w arksdk.Wallet, currentSigner string, expected signerRotationExpected,
) {
	t.Helper()
	ctx := t.Context()
	// All surviving spendable vtxos must now commit to KEY B.
	postVtxos, _, err := w.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, postVtxos, "wallet must hold the migrated funds")
	for _, v := range postVtxos {
		require.Equal(t, currentSigner, vtxoSignerKey(t, w, v),
			"every migrated vtxo must commit to the current signer KEY B (#822)")
	}

	require.Equal(t, expected.Sats, totalVtxoAmount(postVtxos),
		"offchain migration must preserve the sats balance")
	require.Equal(t, expected.AssetBalances, assetBalancesFromVtxos(postVtxos),
		"offchain migration must preserve asset balances")

	bal, err := w.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, expected.Sats, bal.OffchainBalance.Total,
		"offchain sats balance preserved across the migration")
	require.Equal(t, expected.AssetBalances, bal.AssetBalances,
		"asset balances preserved across the migration")
}

func requireInactiveContracts(t *testing.T, w arksdk.Wallet) {
	t.Helper()

	inactive, err := w.ContractManager().GetContracts(
		t.Context(), contract.WithState(types.ContractStateInactive),
	)
	require.NoError(t, err)
	require.NotEmpty(t, inactive,
		"the migrated deprecated-signer contract must be marked inactive")
	for _, c := range inactive {
		require.Equal(t, types.ContractStateInactive, c.State)
	}
}

func requireSpendableMigratedFunds(
	t *testing.T, sender arksdk.Wallet, expected signerRotationExpected,
) {
	t.Helper()
	ctx := t.Context()

	bob := setupClient(t, "")
	bobAddr, err := bob.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobAddr)

	const sendBtc = signerRotationSpendSats // a small BTC portion of the consolidated vtxo
	require.Less(t, sendBtc, expected.Sats, "the BTC spend must be a portion of the balance")

	_, err = sender.SendOffChain(ctx, []clientTypes.Receiver{
		{
			To: bobAddr, Amount: sendBtc,
		},
	})
	require.NoError(t, err, "spending from the migrated vtxo must succeed")

	bobBal, err := bob.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, sendBtc, bobBal.OffchainBalance.Total,
		"recipient must hold exactly the sent BTC portion")

	require.Eventually(t, func() bool {
		senderBal, err := sender.Balance(ctx)
		if err != nil {
			return false
		}
		return senderBal.OffchainBalance.Total == expected.Sats-sendBtc &&
			assetBalancesEqual(senderBal.AssetBalances, expected.AssetBalances)
	}, 10*time.Second, 500*time.Millisecond,
		"sender must retain remaining BTC and all migrated assets after spending only BTC")
}

// totalVtxoAmount sums the amounts of the given vtxos.
func totalVtxoAmount(vtxos []clientTypes.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func requireAssetBalance(t *testing.T, w arksdk.Wallet, assetID string, amount uint64) {
	t.Helper()

	require.Eventually(t, func() bool {
		bal, err := w.Balance(t.Context())
		if err != nil {
			return false
		}
		return bal.AssetBalances[assetID] == amount
	}, 20*time.Second, 500*time.Millisecond,
		"wallet should hold asset %s amount %d", assetID, amount)
}

func requireSpendableFunding(
	t *testing.T, w arksdk.Wallet, expected signerRotationExpected,
) []clientTypes.Vtxo {
	t.Helper()

	require.Eventually(t, func() bool {
		vtxos, _, err := w.ListVtxos(t.Context(), arksdk.WithSpendableOnly())
		if err != nil {
			return false
		}
		return len(vtxos) == expected.VtxoCount &&
			totalVtxoAmount(vtxos) == expected.Sats &&
			assetBalancesEqual(assetBalancesFromVtxos(vtxos), expected.AssetBalances)
	}, 30*time.Second, 500*time.Millisecond,
		"wallet should hold %d spendable pre-rotation vtxos with sats=%d assets=%v",
		expected.VtxoCount, expected.Sats, expected.AssetBalances)

	vtxos, _, err := w.ListVtxos(t.Context(), arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.Len(t, vtxos, expected.VtxoCount)
	require.Equal(t, expected.Sats, totalVtxoAmount(vtxos))
	require.Equal(t, expected.AssetBalances, assetBalancesFromVtxos(vtxos))
	return vtxos
}

func assetBalancesFromVtxos(vtxos []clientTypes.Vtxo) map[string]uint64 {
	balances := make(map[string]uint64)
	for _, vtxo := range vtxos {
		for _, asset := range vtxo.Assets {
			balances[asset.AssetId] += asset.Amount
		}
	}
	return balances
}

func assetBalancesEqual(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for id, amount := range a {
		if b[id] != amount {
			return false
		}
	}
	return true
}

// vtxoSignerKey returns the stored contract signer's x-only hex.
func vtxoSignerKey(t *testing.T, w arksdk.Wallet, vtxo clientTypes.Vtxo) string {
	t.Helper()
	mgr := w.ContractManager()
	require.NotNil(t, mgr)

	contracts, err := mgr.GetContracts(t.Context(), contract.WithScripts([]string{vtxo.Script}))
	require.NoError(t, err)
	require.Len(t, contracts, 1, "expected exactly one contract for vtxo script %s", vtxo.Script)

	handler, err := mgr.GetHandler(t.Context(), contracts[0])
	require.NoError(t, err)
	signerKey, err := handler.GetSignerKey(contracts[0])
	require.NoError(t, err)
	return hex.EncodeToString(schnorr.SerializePubKey(signerKey))
}

func waitForSignerRotation(
	t *testing.T, w arksdk.Wallet, oldSigner, msg string,
) string {
	t.Helper()
	t.Log(msg)
	fmt.Fprintln(os.Stderr, msg)
	t.Log("polling arkd GetInfo every second until active signer changes")

	var (
		currentSigner string
		lastErr       error
	)
	require.Eventually(t, func() bool {
		currentSigner, lastErr = arkdCurrentSigner(t, w)
		return lastErr == nil && currentSigner != oldSigner
	}, 5*time.Minute, time.Second,
		"rotation must change the active signer (A -> B); last current signer=%s lastErr=%v",
		currentSigner, lastErr)

	return currentSigner
}

// arkdCurrentSigner returns arkd's current signer as x-only hex.
func arkdCurrentSigner(t *testing.T, w arksdk.Wallet) (string, error) {
	t.Helper()
	info, err := w.Client().GetInfo(t.Context())
	if err != nil {
		return "", err
	}
	buf, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return "", err
	}
	// btcec.ParsePubKey accepts both compressed and x-only inputs.
	key, err := btcec.ParsePubKey(buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(schnorr.SerializePubKey(key)), nil
}

func setupClientWithDir(t *testing.T, dir, seed string, opts ...arksdk.WalletOption) arksdk.Wallet {
	t.Helper()

	arkClient, err := arksdk.NewWallet(dir, opts...)
	require.NoError(t, err)

	err = arkClient.Init(t.Context(), serverUrl, seed, password)
	require.NoError(t, err)

	unlockClient(t, arkClient)
	return arkClient
}

func loadClientWithDir(t *testing.T, dir string, opts ...arksdk.WalletOption) arksdk.Wallet {
	t.Helper()

	arkClient, err := arksdk.LoadWallet(dir, opts...)
	require.NoError(t, err)

	unlockClient(t, arkClient)
	return arkClient
}

func unlockClient(t *testing.T, arkClient arksdk.Wallet) {
	t.Helper()

	err := arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.Nil(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(arkClient.Stop)
}
