package scanner

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/types"
)

// BlockchainScanner defines the interface for blockchain data fetching and address subscription.
// Implementations include Mempool (with connection pooling) and Electrum (single connection with native batching).
//
// The scanner abstraction allows different backend strategies:
//   - Mempool: Multiple WebSocket connections with hash-based routing to handle rate limits
//   - Electrum: Single persistent connection using JSON-RPC batch subscriptions
//
// All scanners must emit identical OnchainAddressEvent structures for consistency.
type BlockchainScanner interface {
	// Start initializes the scanner and begins tracking subscribed addresses.
	// Must be called before subscribing to addresses.
	Start()

	// Stop gracefully shuts down the scanner, closing all connections and channels.
	Stop()

	// GetTxHex retrieves the raw transaction hex for a given transaction ID.
	GetTxHex(txid string) (string, error)

	// Broadcast broadcasts one or more raw transactions to the network.
	// Returns the transaction ID of the first transaction on success.
	Broadcast(txs ...string) (string, error)

	// GetTxs retrieves all transactions associated with a given address.
	GetTxs(addr string) ([]Tx, error)

	// GetTxOutspends returns the spent status of all outputs for a given transaction.
	GetTxOutspends(tx string) ([]SpentStatus, error)

	// GetUtxos retrieves all unspent transaction outputs (UTXOs) for a given address.
	GetUtxos(addr string) ([]Utxo, error)

	// GetRedeemedVtxosBalance calculates the redeemed virtual UTXO balance for an address
	// considering the unilateral exit delay.
	GetRedeemedVtxosBalance(
		addr string, unilateralExitDelay arklib.RelativeLocktime,
	) (uint64, map[int64]uint64, error)

	// GetTxBlockTime returns whether a transaction is confirmed and its block time.
	GetTxBlockTime(txid string) (confirmed bool, blocktime int64, err error)

	// BaseUrl returns the base URL of the scanner service.
	BaseUrl() string

	// GetFeeRate retrieves the current recommended fee rate in sat/vB.
	GetFeeRate() (float64, error)

	// GetConnectionCount returns the number of active connections.
	// For Mempool: number of WebSocket connections in the pool
	// For Electrum: 1 (single persistent connection) or 0 (disconnected)
	GetConnectionCount() int

	// GetSubscribedAddresses returns a list of all currently subscribed addresses.
	GetSubscribedAddresses() []string

	// IsAddressSubscribed checks if a specific address is currently subscribed.
	IsAddressSubscribed(address string) bool

	// GetAddressesEvents returns a channel that receives onchain address events
	// (new UTXOs, spent UTXOs, confirmed UTXOs) for all subscribed addresses.
	GetAddressesEvents() <-chan types.OnchainAddressEvent

	// SubscribeForAddresses subscribes to address updates.
	// Implementation details:
	//   - Mempool: Distributes addresses across connection pool using hash-based routing
	//   - Electrum: Batch subscribes via blockchain.scripthash.subscribe JSON-RPC
	// Duplicate subscriptions are automatically prevented.
	SubscribeForAddresses(addresses []string) error

	// UnsubscribeForAddresses removes address subscriptions.
	UnsubscribeForAddresses(addresses []string) error
}
