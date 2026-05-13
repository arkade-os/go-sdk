package electrum_explorer

import (
	"crypto/tls"
	"time"
)

// Option is a functional option for configuring the ElectrumX Explorer.
type Option func(*explorerSvc)

// WithPollInterval sets how often the explorer polls for address updates when
// push subscriptions are not reliable (e.g. regtest). Default: 10 seconds.
func WithPollInterval(interval time.Duration) Option {
	return func(svc *explorerSvc) {
		svc.pollInterval = interval
	}
}

// WithTracker enables or disables address tracking via ElectrumX subscriptions.
// When disabled the explorer only handles one-shot queries (GetTxHex, Broadcast, etc.).
// Default: tracking is disabled.
func WithTracker(withTracker bool) Option {
	return func(svc *explorerSvc) {
		svc.noTracking = !withTracker
	}
}

// WithTLSConfig sets a custom TLS configuration for ssl:// connections.
// Use this to supply a self-signed CA certificate or to disable certificate
// verification when connecting to a self-hosted ElectrumX server.
// If not set, the default system roots are used with TLS 1.2 as the minimum version.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(svc *explorerSvc) {
		svc.client.tlsConfig = cfg
	}
}

// WithEsploraURL sets an esplora-compatible REST base URL used exclusively for
// broadcasting transaction packages (multiple transactions submitted as a
// single unit via POST /txs/package). This is required when broadcasting v3
// transactions that carry a P2A (pay-to-anchor) output with zero fee: Bitcoin
// Core rejects them individually via sendrawtransaction but accepts them via
// submitpackage. When not set, Broadcast falls back to individual electrum
// broadcasts (which will fail for zero-fee v3 parent transactions).
func WithEsploraURL(url string) Option {
	return func(svc *explorerSvc) {
		svc.esploraURL = url
	}
}

// WithWebSocketURL enables a mempool.space-compatible WebSocket notification
// path (track-addresses protocol) used in parallel with Electrum scripthash
// subscriptions. Required when the upstream electrs build does not index
// taproot scripts: scripthash queries silently return empty for P2TR, so the
// WS payload (which carries full output address/amount data live) is the only
// path that surfaces boarding-address activity. Expected URL form:
// ws://host:port/v1/ws or wss://host:port/v1/ws.
func WithWebSocketURL(url string) Option {
	return func(svc *explorerSvc) {
		svc.wsURL = url
	}
}
