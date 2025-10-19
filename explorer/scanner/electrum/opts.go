package electrum_scanner

// Option is a functional option for configuring the Electrum scanner.
type Option func(*electrumScanner)

// WithTracker enables or disables address tracking.
// When disabled, the scanner only provides REST API functionality without subscriptions.
// Default: tracking is disabled.
func WithTracker(withTracker bool) Option {
	return func(svc *electrumScanner) {
		if !withTracker {
			svc.noTracking = true
		}
	}
}
