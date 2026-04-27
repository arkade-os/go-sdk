package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

const (
	password    = "secret"
	serverUrl   = "127.0.0.1:7070"
	explorerUrl = "http://127.0.0.1:3000"
)

func setupClient(t *testing.T, seed string, opts ...sdk.ClientOption) sdk.ArkClient {
	t.Helper()

	arkClient, err := sdk.NewArkClient(t.TempDir(), opts...)
	require.NoError(t, err)

	err = arkClient.Init(t.Context(), serverUrl, seed, password)
	require.NoError(t, err)

	err = arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.True(t, synced.Synced)
	require.Nil(t, synced.Err)

	t.Cleanup(arkClient.Stop)

	return arkClient
}

func relativeLocktimeFromValue(value uint32) arklib.RelativeLocktime {
	locktimeType := arklib.LocktimeTypeBlock
	if value >= 512 {
		locktimeType = arklib.LocktimeTypeSecond
	}

	return arklib.RelativeLocktime{
		Type:  locktimeType,
		Value: value,
	}
}

func faucetOnchain(t *testing.T, address string, amount float64) {
	_, err := runCommand("nigiri", "faucet", address, fmt.Sprintf("%.8f", amount))
	require.NoError(t, err)
}

func faucetOffchain(
	t *testing.T, client sdk.ArkClient, offchainAddr string, amount float64,
) clientTypes.Vtxo {
	ctx := t.Context()
	require.NotEmpty(t, offchainAddr)

	note := generateNote(t, uint64(amount*1e8))

	aliceVtxoCh := client.GetVtxoEventChannel(ctx)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var vtxo clientTypes.Vtxo
	go func() {
		defer wg.Done()
		for event := range aliceVtxoCh {
			if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
				continue
			}
			vtxo = event.Vtxos[0]
			break
		}
	}()

	txid, err := client.RedeemNotes(ctx, []string{note})
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()

	return vtxo
}

func deriveWalletAddresses(
	t *testing.T, ctx context.Context, client sdk.ArkClient, walletSvc wallet.WalletService,
) ([]string, []clientTypes.Address, []clientTypes.Address, []clientTypes.Address) {
	t.Helper()

	cfg, err := client.GetConfigData(ctx)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	keys, err := walletSvc.ListKeys(ctx)
	require.NoError(t, err)

	onchainAddrs := make([]string, 0, len(keys))
	offchainAddrs := make([]clientTypes.Address, 0, len(keys))
	boardingAddrs := make([]clientTypes.Address, 0, len(keys))
	redemptionAddrs := make([]clientTypes.Address, 0, len(keys))

	for _, key := range keys {
		defaultVtxoScript := script.NewDefaultVtxoScript(
			key.PubKey, cfg.SignerPubKey, cfg.UnilateralExitDelay,
		)
		vtxoTapKey, _, err := defaultVtxoScript.TapTree()
		require.NoError(t, err)

		offchainAddress := &arklib.Address{
			HRP:        cfg.Network.Addr,
			Signer:     cfg.SignerPubKey,
			VtxoTapKey: vtxoTapKey,
		}
		encodedOffchainAddr, err := offchainAddress.EncodeV0()
		require.NoError(t, err)

		tapscripts, err := defaultVtxoScript.Encode()
		require.NoError(t, err)

		boardingVtxoScript := script.NewDefaultVtxoScript(
			key.PubKey, cfg.SignerPubKey, cfg.BoardingExitDelay,
		)
		boardingTapKey, _, err := boardingVtxoScript.TapTree()
		require.NoError(t, err)

		netParams := chaincfg.MainNetParams
		switch cfg.Network.Name {
		case arklib.BitcoinRegTest.Name:
			netParams = chaincfg.RegressionNetParams
		case arklib.BitcoinTestNet.Name:
			netParams = chaincfg.TestNet3Params
		case arklib.BitcoinSigNet.Name:
			netParams = chaincfg.SigNetParams
		}
		boardingTaprootAddr, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(boardingTapKey), &netParams,
		)
		require.NoError(t, err)

		boardingTapscripts, err := boardingVtxoScript.Encode()
		require.NoError(t, err)

		redemptionTaprootAddr, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(vtxoTapKey), &netParams,
		)
		require.NoError(t, err)

		onchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
		onchainTaprootAddr, err := btcutil.NewAddressTaproot(
			schnorr.SerializePubKey(onchainTapKey), &netParams,
		)
		require.NoError(t, err)

		onchainAddrs = append(onchainAddrs, onchainTaprootAddr.EncodeAddress())
		offchainAddrs = append(offchainAddrs, clientTypes.Address{
			KeyID:      key.Id,
			Tapscripts: tapscripts,
			Address:    encodedOffchainAddr,
		})
		boardingAddrs = append(boardingAddrs, clientTypes.Address{
			KeyID:      key.Id,
			Tapscripts: boardingTapscripts,
			Address:    boardingTaprootAddr.EncodeAddress(),
		})
		redemptionAddrs = append(redemptionAddrs, clientTypes.Address{
			KeyID:      key.Id,
			Tapscripts: tapscripts,
			Address:    redemptionTaprootAddr.EncodeAddress(),
		})
	}

	return onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs
}

func findOffchainAddressByScript(
	t *testing.T, addrs []clientTypes.Address, scriptHex string,
) clientTypes.Address {
	t.Helper()

	for _, addr := range addrs {
		decodedAddr, err := arklib.DecodeAddressV0(addr.Address)
		require.NoError(t, err)

		pkScript, err := decodedAddr.GetPkScript()
		require.NoError(t, err)

		if hex.EncodeToString(pkScript) == scriptHex {
			return addr
		}
	}

	t.Fatalf("offchain address with script %s not found", scriptHex)
	return clientTypes.Address{}
}

func generateNote(t *testing.T, amount uint64) string {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", "http://127.0.0.1:7071/v1/admin/note", reqBody)
	if err != nil {
		t.Fatalf("failed to prepare note request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	resp, err := adminHttpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create note: %s", err)
	}

	var noteResp struct {
		Notes []string `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&noteResp); err != nil {
		t.Fatalf("failed to parse response: %s", err)
	}

	return noteResp.Notes[0]
}

func runCommand(name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := newCommand(name, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}
	output := new(strings.Builder)
	errorb := new(strings.Builder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(output, stdout); err != nil {
			fmt.Fprintf(errb, "error reading stdout: %s", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(errorb, stderr); err != nil {
			fmt.Fprintf(errb, "error reading stderr: %s", err)
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if errMsg := errorb.String(); len(errMsg) > 0 {
			return "", fmt.Errorf("%s", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("%s", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("%s", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}

func generateBlocks(n int) error {
	_, err := runCommand("nigiri", "rpc", "--generate", fmt.Sprintf("%d", n))
	return err
}
