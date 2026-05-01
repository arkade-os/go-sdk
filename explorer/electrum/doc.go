// Package electrum_explorer provides an Explorer implementation backed by an
// ElectrumX server over TCP or SSL. It is modeled on the ocean project's
// electrum blockchain scanner and requires no third-party ElectrumX library.
//
// # Overview
//
// The package has two layers:
//
//   - electrumClient (transport, client.go) — owns a single multiplexed
//     TCP/SSL connection. Multiplexes JSON-RPC requests via atomic request
//     IDs over one socket, runs a listen + keepAlive goroutine pair per
//     connection cycle, and reconnects with exponential backoff on any
//     disconnect.
//
//   - explorerSvc (protocol, explorer.go) — implements the
//     explorer.Explorer interface. Does Bitcoin-aware encoding/decoding,
//     address tracking with a poll loop, and event broadcasting through a
//     non-blocking listeners hub.
//
// Both layers are safe to call from any goroutine; internal locks serialise
// concurrent access. Callers do not need to provide their own synchronisation.
//
// # Lifecycle
//
// The Explorer transitions through these states:
//
//	created  ─Start()─►  connecting  ─handshake OK─►  ready  ─Stop()─►  stopped
//	                          │
//	                          └─dial fail─► (background reconnect goroutine)
//
//	ready  ─clean EOF / I/O err─►  reconnecting  ─dial OK + handshake─►  ready
//	                                     │
//	                                     └─dial fail─► (exp. backoff 5 s → 60 s)
//
// Start dials, completes the server.version handshake, and (if tracking is
// enabled) launches the polling loop. Stop cancels the root context, drains
// per-address notification consumers, closes listener channels, and resets
// the subscription map.
//
// # Reconnection model
//
// The connection is owned by electrumClient. On any disconnect — including a
// clean EOF from a server restart — listen() exits and falls through to
// reconnect(). reconnect dials with exponential backoff and, on success,
// replays every scripthash recorded in storedSubs by issuing a fresh
// blockchain.scripthash.subscribe RPC per address.
//
// Two contexts cooperate to bound goroutine lifetimes:
//
//   - c.ctx / c.cancel — the root context. Cancelled only by shutdown(),
//     which is reached via explorerSvc.Stop(). Unblocks the reconnect loop's
//     time.After backoff and prevents zombie reconnect goroutines from
//     outliving the explorer.
//
//   - cycleCtx / cycleCancel — a per-connection-cycle context. Cancelled at
//     every reconnect to terminate the listen + keepAlive goroutine pair of
//     the previous cycle. The new cycle starts a fresh pair under a fresh
//     context. This is what prevents goroutine accumulation across multiple
//     reconnects in one process lifetime — without it every reconnect would
//     leak two goroutines.
//
// Pending requests in c.pending are drained when close() is called (either
// from a failed connect or from shutdown). On a natural disconnect-then-
// reconnect path the pending map is left intact across the gap; in-flight
// requests time out individually after requestTimeout (default 15 s).
//
// # Restart and restore semantics
//
// The explorer is stateless across process boundaries by design. The only
// piece of explorer-related state persisted by the surrounding SDK is the
// server URL (recorded in arkClient's ConfigStore via Init). On a fresh
// process start, the path is:
//
//  1. LoadArkClient reads the persisted URL from ConfigStore.
//  2. newExplorer (init.go) dispatches on URL scheme:
//     "tcp://" or "ssl://" → this package; anything else → mempool.space.
//  3. NewExplorer constructs a fresh electrumClient with empty subscription
//     and cache state.
//  4. Unlock() calls Explorer().Start(), which dials, runs
//     discoverHDWalletKeys + refreshDb to rebuild wallet state from the
//     persistent store + chain, then hands off to the polling loop.
//
// During restore the SDK fires bursts of GetTxs / GetUtxos calls. The
// transport multiplexes them on the single TCP connection via atomic request
// IDs — but they all share one 15 s requestTimeout per call, so a slow
// server stalls the burst rather than parallelising it.
//
// Anyone refactoring this package should NOT introduce on-disk explorer
// state without also adding a corresponding crash-recovery path. The current
// design is deliberate: the persistent state-of-record lives in arkd and the
// SDK's app-data store; the explorer is a fresh, transient view of it.
//
// # Concurrency contract
//
// All exported methods on the Explorer interface are safe to call from any
// goroutine. Implementation notes:
//
//   - Address subscriptions are protected by subscribedMu (RWMutex on the
//     map) plus a per-address state.mu that serialises concurrent
//     pollAddress calls for the same address.
//   - The listeners hub uses an RWMutex around the listener-channel map;
//     broadcasts non-blockingly fan out to every consumer and auto-evict
//     consumers that fall behind.
//   - The transport-level c.subs map (scripthash → notif channel) is
//     protected by subsMu and is read/written by listen() under RLock and
//     by subscribe/unsubscribeLocal under Lock.
//   - storedSubs is replayed on every reconnect; it is protected by its own
//     mutex separate from subsMu so that subscribe() can drop one lock
//     before acquiring the other (enforces lock ordering and avoids holding
//     either lock across a blocking RPC).
//
// # Known limitations vs the mempool.space explorer
//
//   - Broadcast of multiple txs is sequential, not atomic.
//   - UnsubscribeForAddresses removes the address locally only; ElectrumX
//     has no unsubscribe wire message.
//   - OnchainAddressEvent.Replacements is always empty (ElectrumX has no
//     RBF notification).
//   - GetConnectionCount always returns 1 (single multiplexed TCP
//     connection).
//   - GetTxOutspends is O(outputs × history length) rather than a dedicated
//     endpoint.
package electrum_explorer
