package explorer

import "time"

// Option is a functional option for configuring the Explorer service.
type Option func(*explorerSvc)

// WithPollInterval sets the polling interval for address tracking when WebSocket is unavailable.
// Default: 10 seconds.
func WithPollInterval(interval time.Duration) Option {
	return func(svc *explorerSvc) {
		svc.pollInterval = interval
	}
}

// WithTracker enables or disables address tracking.
// When disabled, the explorer only provides REST API functionality without WebSocket connections.
// Default: tracking is disabled.
func WithTracker(withTracker bool) Option {
	return func(svc *explorerSvc) {
		if !withTracker {
			svc.noTracking = true
		}
	}
}

// WithBatchSize sets the number of addresses to subscribe per batch.
// Batching prevents overwhelming individual WebSocket connections with large subscription requests.
// Default: 50 addresses per batch.
func WithBatchSize(batchSize int) Option {
	return func(svc *explorerSvc) {
		svc.batchSize = batchSize
	}
}

// WithBatchDelay sets the delay between subscription batches.
// This helps rate-limit subscription requests to avoid overwhelming the explorer service.
// Default: 100 milliseconds.
func WithBatchDelay(batchDelay time.Duration) Option {
	return func(svc *explorerSvc) {
		svc.batchDelay = batchDelay
	}
}

// WithMaxConnections sets the maximum number of concurrent WebSocket connections.
// Multiple connections distribute the load and prevent I/O timeouts when subscribing to many addresses.
// Addresses are distributed across connections using consistent hash-based routing.
// Default: 3 connections.
func WithMaxConnections(maxConnections int) Option {
	return func(svc *explorerSvc) {
		svc.maxConnections = maxConnections
	}
}
