## Arkade Go SDK

The complete API documentation for the Go SDK is automatically generated and published on **pkg.go.dev** with each GitHub release. To view the documentation, visit: [https://pkg.go.dev/github.com/ark-network/sdk](https://pkg.go.dev/github.com/ark-network/sdk)

## Installation

To install the Arkade Go SDK, use the following command:

```bash
go get github.com/ark-network/sdk
```

## Usage

Here's a comprehensive guide on how to use the Arkade Go SDK:

### 1. Setting up the Ark Client

The Ark client can be set up with different storage options and configurations. Here's how you can create and initialize an Ark client with different storage options:

#### Using In-Memory Storage (only for testing)

The code snippet below demonstrates how to set up an Ark client with in-memory storage. This will create a new seed and holds it in the storeSvc variable.

```go
import (
    arksdk "github.com/ark-network/sdk"
    inmemorystore "github.com/ark-network/sdk/store/inmemory"
)

func setupInMemoryArkClient() (arksdk.ArkClient, error) {
    storeSvc, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
	})
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
		ServerUrl:     "localhost:7070",
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
    arksdk "github.com/ark-network/sdk"
    filestore "github.com/ark-network/sdk/store/file"
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
		ServerUrl:     "localhost:7070",
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
    ClientType          string // Type of client connection (e.g., "grpc" or "rest")
    WalletType          string // Type of wallet (e.g., "singlekey" or "hd")
    ServerUrl           string // URL of the Ark Server
    Seed                string // Private Key hex encoded for wallet initialization or restoration
    Password            string // Wallet password
    WithTransactionFeed bool // Receive notifications about received or spent funds
}
```

Let's explore each field in detail:

- `ClientType`: Specifies the type of connection to use with the Ark Server. Options include:
  - `"grpc"`: Uses gRPC for communication (recommended for better performance)
  - `"rest"`: Uses REST API for communication

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
txid, err = arkClient.SendOffchain(ctx, false, receivers)
if err != nil {
    log.Fatal(err)
}
log.Infof("Transaction completed in round tx: %s", txid)
```

#### Submit Redeem Transaction

`SendOffchain` is useful for simple send operations. But complex contract or collaborative transactions require more flexibility. In this case, you can use the `TransportClient.SubmitRedeemTx` function.

```go
// Create a new transport client
transportClient, err := grpcclient.NewClient("localhost:7070")
require.NoError(t, err)

// use common/bitcointree utility function to build redeem transactions
redeemPartialTx, err := bitcointree.BuildRedeemTx(
	[]common.VtxoInput{
		// ... your inputs here
	},
	[]*wire.TxOut{
		// ... your outputs here
	},
)

// once signed, submit the transaction to the Ark
// if accepted, the Ark server will counter sign and returns the fully signed transaction
fullySignedRedeemTx, err := transportClient.SubmitRedeemTx(ctx, redeemPartialTx)
```


### 4. Advanced Usage

#### Multiple Recipients

You can send to multiple recipients in a single transaction:

```go
receivers := []arksdk.Receiver{
    arksdk.NewBitcoinReceiver(recipient1OffchainAddr, amount1),
    arksdk.NewBitcoinReceiver(recipient2OffchainAddr, amount2),
}
txid, err = arkClient.SendOffchain(ctx, false, receivers)
```

#### Redeem Funds

To move funds from offchain to onchain:

```go
txid, err := arkClient.CollaborativeRedeem(
    ctx, onchainAddress, redeemAmount, false,
)
if err != nil {
    log.Fatal(err)
}
log.Infof("Redeemed with tx: %s", txid)
```

## Full Example

For a complete end-to-end example demonstrating the usage of the Arkade Go SDK, including setting up multiple clients, boarding, and transferring funds, please refer to our [GitHub repository](https://github.com/ark-network/go-sdk/blob/master/example/alice_to_bob.go).

## Support

If you encounter any issues or have questions, please file an issue on our [GitHub repository](https://github.com/ark-network/go-sdk/issues).

Happy coding with Ark and Go! 🚀
