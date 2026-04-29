package electrum_explorer

import "time"

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
