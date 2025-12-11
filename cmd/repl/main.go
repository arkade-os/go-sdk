package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

var (
	Version      string
	arkSdkClient arksdk.ArkClient
)

func main() {
	app := cli.NewApp()
	app.Version = Version
	app.Name = "Ark REPL"
	app.Usage = "interactive shell using the stateful DB (SQL store + tx feed)"
	app.Flags = []cli.Flag{datadirFlag, verboseFlag, urlFlag, explorerFlag, restFlag, passwordFlag}
	app.Action = func(ctx *cli.Context) error {
		client, err := getReplClient(ctx)
		if err != nil {
			return err
		}
		arkSdkClient = client
		return repl(ctx)
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(fmt.Errorf("error: %v", err))
		os.Exit(1)
	}
}

var (
	datadirFlag = &cli.StringFlag{
		Name:  "datadir",
		Usage: "Specify the data directory",
		Value: arklib.AppDataDir("ark-repl", false),
	}
	explorerFlag = &cli.StringFlag{
		Name:  "explorer",
		Usage: "the url of the explorer to use",
	}
	passwordFlag = &cli.StringFlag{
		Name:  "password",
		Usage: "password to unlock the wallet",
	}
	urlFlag = &cli.StringFlag{
		Name:  "server-url",
		Usage: "the url of the Ark server to connect to (required on first run)",
	}
	restFlag = &cli.BoolFlag{
		Name:        "rest",
		Usage:       "use REST client instead of gRPC",
		Value:       false,
		DefaultText: "false",
	}
	verboseFlag = &cli.BoolFlag{
		Name:        "verbose",
		Usage:       "enable debug logs",
		Value:       false,
		DefaultText: "false",
	}
)

func getReplClient(ctx *cli.Context) (arksdk.ArkClient, error) {
	dataDir := ctx.String(datadirFlag.Name)
	sdkRepository, err := store.NewStore(store.Config{
		ConfigStoreType:  types.FileStore,
		AppDataStoreType: types.SQLStore,
		BaseDir:          dataDir,
	})
	if err != nil {
		return nil, err
	}

	cfgData, err := sdkRepository.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	opts := make([]arksdk.ClientOption, 0)
	if ctx.Bool(verboseFlag.Name) {
		opts = append(opts, arksdk.WithVerbose())
	}

	client, err := loadOrCreateClient(
		arksdk.LoadArkClient, arksdk.NewArkClient, sdkRepository, opts,
	)
	if err != nil {
		return nil, err
	}

	if cfgData == nil {
		serverURL := ctx.String(urlFlag.Name)
		if serverURL == "" {
			return nil, fmt.Errorf("missing config; provide --server-url to initialize the REPL client")
		}

		password, err := readPassword(ctx)
		if err != nil {
			return nil, err
		}

		clientType := arksdk.GrpcClient
		if ctx.Bool(restFlag.Name) {
			clientType = arksdk.RestClient
		}

		if err := client.Init(ctx.Context, arksdk.InitArgs{
			ClientType:           clientType,
			WalletType:           arksdk.SingleKeyWallet,
			ServerUrl:            serverURL,
			Password:             string(password),
			ExplorerURL:          ctx.String(explorerFlag.Name),
			ExplorerPollInterval: 30 * time.Second,
			WithTransactionFeed:  true,
		}); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func loadOrCreateClient(
	loadFunc, newFunc func(types.Store, ...arksdk.ClientOption) (arksdk.ArkClient, error),
	sdkRepository types.Store, opts []arksdk.ClientOption,
) (arksdk.ArkClient, error) {
	client, err := loadFunc(sdkRepository, opts...)
	if err != nil {
		if errors.Is(err, arksdk.ErrNotInitialized) {
			return newFunc(sdkRepository, opts...)
		}
		return nil, err
	}
	return client, err
}

func repl(ctx *cli.Context) error {
	fmt.Println("Ark REPL (stateful) - commands: help, unlock, lock, balance, send <to> <amount>, sendasset <assetid> <to> <amount>, createasset <name> <quantity> [symbol] [control-asset-id], reissueasset <assetid> <amount> [control-asset-id], settle, recover, vtxos [all|spendable|spent], txs, config, receive, quit")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("ark> ")
		if !scanner.Scan() {
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		cmd := strings.ToLower(fields[0])

		switch cmd {
		case "quit", "exit":
			return nil
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  unlock [password]     - unlock the wallet (password optional, will prompt if omitted)")
			fmt.Println("  lock                  - lock the wallet")
			fmt.Println("  balance [expiry]      - show balance, include 'expiry' to compute expiration details")
			fmt.Println("  send <to> <amount>    - send sats offchain")
			fmt.Println("  sendasset <assetid> <to> <amount> - send asset offchain")
			fmt.Println("  createasset <name> <quantity> [symbol] [control-asset-id] - create asset")
			fmt.Println("  reissueasset <assetid> <amount> [control-asset-id] - mint more of an asset")
			fmt.Println("  settle                - settle onboarding/pending funds")
			fmt.Println("  recover               - settle recoverable vtxos")
			fmt.Println("  vtxos [all|spendable|spent] - list VTXOs from DB")
			fmt.Println("  txs                   - list transactions from DB")
			fmt.Println("  config                - show current config")
			fmt.Println("  receive               - show current addresses")
			fmt.Println("  quit / exit           - leave the REPL")
		case "unlock":
			var pwd string
			if flagPwd := ctx.String(passwordFlag.Name); flagPwd != "" {
				pwd = flagPwd
			}
			if len(fields) > 1 {
				pwd = strings.Join(fields[1:], " ")
			}
			if pwd == "" {
				fmt.Print("unlock your wallet with password: ")
				rawPwd, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err != nil {
					fmt.Printf("error reading password: %v\n", err)
					continue
				}
				pwd = string(rawPwd)
			}
			if err := arkSdkClient.Unlock(ctx.Context, pwd); err != nil {
				fmt.Printf("unlock error: %v\n", err)
				continue
			}
			fmt.Println("wallet unlocked")
		case "lock":
			if err := arkSdkClient.Lock(ctx.Context); err != nil {
				fmt.Printf("lock error: %v\n", err)
				continue
			}
			fmt.Println("wallet locked")
		case "balance":
			compute := false
			if len(fields) > 1 && strings.ToLower(fields[1]) == "expiry" {
				compute = true
			}
			bal, err := arkSdkClient.Balance(ctx.Context, compute)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(bal)
		case "vtxos":
			mode := "all"
			if len(fields) > 1 {
				mode = strings.ToLower(fields[1])
			}
			switch mode {
			case "spendable":
				spendable, err := arkSdkClient.ListSpendableVtxos(ctx.Context)
				if err != nil {
					fmt.Printf("error: %v\n", err)
					continue
				}
				_ = printJSON(spendable)
			case "spent":
				_, spent, err := arkSdkClient.ListVtxos(ctx.Context)
				if err != nil {
					fmt.Printf("error: %v\n", err)
					continue
				}
				_ = printJSON(spent)
			default:
				spendable, spent, err := arkSdkClient.ListVtxos(ctx.Context)
				if err != nil {
					fmt.Printf("error: %v\n", err)
					continue
				}
				fmt.Println("spendable:")
				_ = printJSON(spendable)
				fmt.Println("spent:")
				_ = printJSON(spent)
			}
		case "txs":
			txs, err := arkSdkClient.GetTransactionHistory(ctx.Context)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(txs)
		case "config":
			cfg, err := arkSdkClient.GetConfigData(ctx.Context)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(cfg)
		case "receive":
			onchain, offchain, boarding, err := arkSdkClient.Receive(ctx.Context)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(map[string]string{
				"onchain_address":  onchain,
				"offchain_address": offchain,
				"boarding_address": boarding,
			})
		case "send":
			if len(fields) < 3 {
				fmt.Println("usage: send <to> <amount>")
				continue
			}
			if err := ensureUnlocked(ctx); err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			amount, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				fmt.Printf("invalid amount: %v\n", err)
				continue
			}
			txid, err := arkSdkClient.SendOffChain(ctx.Context, false, []types.Receiver{
				{To: fields[1], Amount: amount},
			})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(map[string]string{"txid": txid})
		case "sendasset":
			if len(fields) < 4 {
				fmt.Println("usage: sendasset <assetid> <to> <amount>")
				continue
			}
			if err := ensureUnlocked(ctx); err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			assetID, err := parseAssetID(fields[1])
			if err != nil {
				fmt.Printf("invalid asset id: %v\n", err)
				continue
			}
			amount, err := strconv.ParseUint(fields[3], 10, 64)
			if err != nil {
				fmt.Printf("invalid amount: %v\n", err)
				continue
			}
			txid, err := arkSdkClient.SendAsset(ctx.Context, assetID, []types.Receiver{{To: fields[2], Amount: amount}})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(map[string]string{"txid": txid})
		case "createasset":
			if len(fields) < 3 {
				fmt.Println("usage: createasset <name> <quantity> [symbol] [control-asset-id]")
				continue
			}
			if err := ensureUnlocked(ctx); err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			quantity, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				fmt.Printf("invalid quantity: %v\n", err)
				continue
			}
			assetParams := types.AssetCreationParams{
				Quantity: quantity,
				MetadataMap: map[string]string{
					"name": fields[1],
				},
			}
			if len(fields) > 3 && fields[3] != "" {
				assetParams.MetadataMap["symbol"] = fields[3]
			}
			if len(fields) > 4 && fields[4] != "" {
				controlID, err := parseAssetID(fields[4])
				if err != nil {
					fmt.Printf("invalid control asset id: %v\n", err)
					continue
				}
				assetParams.ControlAssetId = controlID
			}
			txid, err := arkSdkClient.CreateAsset(ctx.Context, assetParams)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(map[string]string{"txid": txid})
		case "reissueasset":
			if len(fields) < 3 {
				fmt.Println("usage: reissueasset <assetid> <amount> [control-asset-id]")
				continue
			}
			if err := ensureUnlocked(ctx); err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			assetID, err := parseAssetID(fields[1])
			if err != nil {
				fmt.Printf("invalid asset id: %v\n", err)
				continue
			}
			amount, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				fmt.Printf("invalid amount: %v\n", err)
				continue
			}
			var controlID [32]byte
			if len(fields) > 3 && fields[3] != "" {
				controlID, err = parseAssetID(fields[3])
				if err != nil {
					fmt.Printf("invalid control asset id: %v\n", err)
					continue
				}
			}
			txid, err := arkSdkClient.ModifyAsset(ctx.Context, controlID, assetID, amount, map[string]string{})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(map[string]string{"txid": txid})
		case "settle":
			if err := ensureUnlocked(ctx); err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			txid, err := arkSdkClient.Settle(ctx.Context)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(map[string]string{"txid": txid})
		case "recover":
			if err := ensureUnlocked(ctx); err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			txid, err := arkSdkClient.Settle(ctx.Context, arksdk.WithRecoverableVtxos)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			_ = printJSON(map[string]string{"txid": txid})
		default:
			fmt.Printf("unknown command: %s (type 'help' for options)\n", cmd)
		}
	}
}

func ensureUnlocked(ctx *cli.Context) error {
	if !arkSdkClient.IsLocked(ctx.Context) {
		return nil
	}
	pwd, err := readPassword(ctx)
	if err != nil {
		return err
	}
	return arkSdkClient.Unlock(ctx.Context, string(pwd))
}

func parseAssetID(assetIDHex string) ([32]byte, error) {
	var assetID [32]byte
	b, err := hex.DecodeString(assetIDHex)
	if err != nil {
		return assetID, err
	}
	if len(b) != 32 {
		return assetID, fmt.Errorf("asset id must be 32 bytes, got %d", len(b))
	}
	copy(assetID[:], b)
	return assetID, nil
}

func readPassword(ctx *cli.Context) ([]byte, error) {
	password := []byte(ctx.String(passwordFlag.Name))
	if len(password) == 0 {
		fmt.Print("unlock your wallet with password: ")
		var err error
		password, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, err
		}
	}
	return password, nil
}

func printJSON(resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}
	fmt.Println(string(jsonBytes))
	return nil
}
