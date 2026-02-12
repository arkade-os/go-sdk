## Arkade Go SDK

The complete API documentation for the Go SDK is automatically generated and published on **pkg.go.dev** with each GitHub release. To view the documentation, visit: [https://pkg.go.dev/github.com/arkade-os/go-sdk](https://pkg.go.dev/github.com/arkade-os/go-sdk)

## Installation

To install the Arkade Go SDK, use the following command:

```bash
go get github.com/arkade-os/go-sdk
```

## Usage

Here's a comprehensive guide on how to use the Arkade Go SDK:

### 1. Setting up the Ark Client

The Ark client can be set up with different storage options and configurations. Here's how you can create and initialize an Ark client with different storage options:

#### Using In-Memory Storage (only for testing)

The code snippet below demonstrates how to set up an Ark client with in-memory storage. This will create a new seed and holds it in the storeSvc variable.

```go
import (
    arksdk "github.com/arkade-os/go-sdk"
    inmemorystore "github.com/arkade-os/go-sdk/store/inmemory"
)

func setupInMemoryArkClient() (arksdk.ArkClient, error) {
    storeSvc, err := store.NewStore(store.Config{ConfigStoreType:  types.InMemoryStore})
	if err != nil {
		return nil, fmt.Errorf("failed to setup store: %s", err)
	}

	client, err := arksdk.NewArkClient(storeSvc)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), arksdk.InitArgs{
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  "localhost:7070",
		Password:   "your_password",
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize wallet: %s", err)
	}

	return client, nil
}
```

#### Using Persistent File Storage

For production use, it's recommended to use persistent storage. Here's how you can set up a file-based storage:

```go
import (
    arksdk "github.com/arkade-os/go-sdk"
    filestore "github.com/arkade-os/go-sdk/store/file"
)

func setupFileBasedArkClient() (arksdk.ArkClient, error) {
    storeSvc, err := store.NewStore(store.Config{
		ConfigStoreType:  types.FileStore,
		BaseDir:          "/path/to/storage/directory",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to setup file store: %s", err)
	}

	client, err := arksdk.NewArkClient(storeSvc)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ark client: %s", err)
	}

	if err := client.Init(context.Background(), arksdk.InitArgs{
		WalletType: arksdk.SingleKeyWallet,
		ClientType: arksdk.GrpcClient,
		ServerUrl:  "localhost:7070",
		Password:   "your_password",
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize wallet: %s", err)
	}

	return client, nil
}
```

### 2. Client Configuration Options

The `Init` function accepts various configuration options through the `InitArgs` struct. Here's a breakdown of all available options:

```go
type InitArgs struct {
    ClientType          string // Type of client connection (e.g., "grpc")
    WalletType          string // Type of wallet (e.g., "singlekey" or "hd")
    ServerUrl           string // URL of the Ark Server
    Seed                string // Private Key hex encoded for wallet initialization or restoration
    Password            string // Wallet password
    WithTransactionFeed bool // Receive notifications about received or spent funds
}
```

Let's explore each field in detail:

- `ClientType`: Specifies the type of connection to use with the Ark Server.`"grpc"` is the only supported option currently.

- `WalletType`: Defines the type of wallet to create or restore. Options include:
  - `"singlekey"`: A wallet using a single key for all transactions

- `ServerUrl`: The URL of the Ark Server to connect to. For example, `"localhost:7070"` for a local instance.

- `Seed`: The hex-encoded private key used to initialize or restore a wallet. This should be a secure, randomly generated string for new wallets, or the backup key for restoring an existing wallet.

- `Password`: The password used to encrypt and protect the wallet.

- `WithTransactionFeed`: Enable receiving notifications about received or spent funds.

Note: Always ensure that you keep your seed phrase and password secure. Never share them or store them in plaintext.

### 3. Wallet Operations

#### Unlock and Lock the Wallet

```go
if err := arkClient.Unlock(ctx, password); err != nil {
    log.Fatal(err)
}
defer arkClient.Lock(ctx, password)
```

#### Receive Funds

```go
offchainAddr, boardingAddr, err := arkClient.Receive(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Offchain address: %s", offchainAddr)
log.Infof("Boarding address: %s", boardingAddr)
```

#### Check Balance

```go
balance, err := arkClient.Balance(ctx, false)
if err != nil {
    log.Fatal(err)
}
log.Infof("Onchain balance: %d", balance.OnchainBalance.SpendableAmount)
log.Infof("Offchain balance: %d", balance.OffchainBalance.Total)
```

#### Send Offchain

```go
amount := uint64(1000)
receivers := []arksdk.Receiver{
    arksdk.NewBitcoinReceiver(recipientOffchainAddr, amount),
}
txid, err = arkClient.SendOffChain(ctx, false, receivers)
if err != nil {
    log.Fatal(err)
}
log.Infof("Transaction completed: %s", txid)
```

#### Submit Transaction

`SendOffChain` is useful for simple send operations. But complex contract or collaborative transactions require more flexibility. In this case, you can use the `TransportClient.SubmitTx` and `TransportClient.FinalizeTx` APIs.

```go
// Create a new transport client
transportClient, err := grpcclient.NewClient("localhost:7070")
require.NoError(t, err)

// Use ark-lib/tree util function to build ark and checkpoint transactions.
arkTx, checkpointTxs, err := offchain.BuildTxs(
	[]offchain.VtxoInput{
		// ... your inputs here
	},
	[]*wire.TxOut{
		// ... your outputs here
	},
	batchOutputSweepClosure,
)

signedArkTx, err := arkClient.SignTransaction(ctx, arkTx)
if err != nil {
	return "", err
}

arkTxid, _, signedCheckpointTxs, err := grpcclient.SubmitTx(ctx, signedArkTx, checkpointTxs)
if err != nil {
	return "", err
}

// Counter-sign and checkpoint txs and send them back to the server to complete the process.
finalCheckpointTxs := make([]string, 0, len(signedCheckpointTxs))
for _, checkpointTx := range signedCheckpointTxs {
	finalCheckpointTx, err := a.SignTransaction(ctx, checkpointTx)
	if err != nil {
		return "", nil
	}
	finalCheckpointTxs = append(finalCheckpointTxs, finalCheckpointTx)
}

if err = a.client.FinalizeTx(ctx, arkTxid, finalCheckpointTxs); err != nil {
	return "", err
}
```


### 4. Advanced Usage

#### Multiple Recipients

You can send to multiple recipients in a single transaction:

```go
receivers := []arksdk.Receiver{
    arksdk.NewBitcoinReceiver(recipient1OffchainAddr, amount1),
    arksdk.NewBitcoinReceiver(recipient2OffchainAddr, amount2),
}
txid, err = arkClient.SendOffChain(ctx, false, receivers)
```

#### Cooperative Exit

To move funds from offchain to onchain:

```go
txid, err := arkClient.CollaborativeExit(ctx, onchainAddress, redeemAmount, false)
if err != nil {
    log.Fatal(err)
}
log.Infof("Redeemed with tx: %s", txid)
```

### 5. Additional Client Functions

The `ArkClient` interface exposes a number of utility methods beyond the
basic workflow shown above. Here is a quick overview:

- `GetVersion()` - return the SDK version.
- `GetConfigData(ctx)` - retrieve Ark server configuration details.
- `Init(ctx, args)` / `InitWithWallet(ctx, args)` - create or restore a wallet.
- `IsLocked(ctx)` - check if the wallet is currently locked.
- `Unlock(ctx, password)` / `Lock(ctx)` - unlock or lock the wallet.
- `Balance(ctx, computeExpiryDetails)` - query onchain and offchain balances.
- `Receive(ctx)` - generate onchain, offchain and boarding addresses.
- `SendOffChain(ctx, withExpiryCoinselect, receivers)` - send funds offchain.
- `Settle(ctx, opts ...) (string, error)` - finalize pending or preconfirmed funds into a commitment transaction.

- `RegisterIntent(...)` / `DeleteIntent(...)` - manage spend intents for collaborative transactions.
- `CollaborativeExit(ctx, addr, amount, withExpiryCoinselect, opts ...) (string, error)` - redeem offchain funds onchain.
- `Unroll(ctx) error` - broadcast unroll transactions when ready.
- `CompleteUnroll(ctx, to string) (string, error)` - finalize an unroll and sweep to an onchain address.
- `OnboardAgainAllExpiredBoardings(ctx) (string, error)` - onboard again using expired boarding UTXOs.
- `WithdrawFromAllExpiredBoardings(ctx, to string) (string, error)` - withdraw expired boarding amounts onchain.
- `ListVtxos(ctx) (spendable, spent []types.Vtxo, err error)` - list virtual UTXOs.
- `Dump(ctx) (seed string, error)` - export the wallet seed.
- `GetTransactionHistory(ctx)` - fetch past transactions.
- `GetTransactionEventChannel(ctx)` and `GetVtxoEventChannel(ctx)` - subscribe to wallet events.
- `RedeemNotes(ctx, notes, opts ...)` - redeem Ark notes back to your wallet.
- `SignTransaction(ctx, tx)` - sign an arbitrary transaction.
- `NotifyIncomingFunds(ctx, address)` - wait until a specific offchain address receives funds.
- `Reset(ctx)` - clear local caches and state.
- `Stop()` - stop any running listeners.

### 6. Transport Client

For lower-level control over transaction batching you can use the `TransportClient` interface directly:

- `GetInfo(ctx)` - return server configuration and network data.
- `RegisterIntent(ctx, signature, message)` and `DeleteIntent(ctx, signature, message)` - manage collaborative intents.
- `ConfirmRegistration(ctx, intentID)` - confirm intent registration on chain.
- `SubmitTreeNonces(ctx, batchId, cosignerPubkey, nonces)` and `SubmitTreeSignatures(ctx, batchId, cosignerPubkey, sigs)` - coordinate cosigner trees.
- `SubmitSignedForfeitTxs(ctx, signedForfeitTxs, signedCommitmentTx)` - provide fully signed forfeit and commitment transactions.
- `GetEventStream(ctx, topics)` - subscribe to batch events from the server.
- `SubmitTx(ctx, signedArkTx, checkpointTxs)` and `FinalizeTx(ctx, arkTxid, finalCheckpointTxs)` - submit collaborative transactions.
- `GetTransactionsStream(ctx)` - stream transaction notifications.
- `Close()` - close the transport connection.

See the [pkg.go.dev documentation](https://pkg.go.dev/github.com/arkade-os/go-sdk) for detailed API information.

### Testing

Run integration tests ([start nigiri](https://github.com/arkade-os/arkd/blob/e33bee6196586b5f4d6ed57abe071458f49ed7ed/README.md?plain=1#L263) if needed first):

```sh
make regtest
make integrationtest
make regtestdown
```

## Full Example

For a complete end-to-end example demonstrating the usage of the Arkade Go SDK, including setting up multiple clients, boarding, and transferring funds, please refer to our [GitHub repository](https://github.com/arkade-os/go-sdk/blob/master/example/alice_to_bob/alice_to_bob.go).

## Support

If you encounter any issues or have questions, please file an issue on our [GitHub repository](https://github.com/arkade-os/go-sdk/issues).

Happy coding with Ark and Go! 🚀
