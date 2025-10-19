package explorer

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	electrum_scanner "github.com/arkade-os/go-sdk/explorer/scanner/electrum"
	mempool_scanner "github.com/arkade-os/go-sdk/explorer/scanner/mempool"
)

// ScannerType specifies which blockchain scanner implementation to use.
type ScannerType string

const (
	// MempoolScanner uses mempool.space WebSocket API with connection pooling.
	// Required for handling mempool.space public API rate limits.
	// Best for: Development, public mempool.space instances
	MempoolScanner ScannerType = "mempool"

	// ElectrumScanner uses Electrum protocol (TCP or WebSocket) with single connection.
	// Handles thousands of address subscriptions via native JSON-RPC batching.
	// Best for: Production, self-hosted servers, high address volume
	ElectrumScanner ScannerType = "electrum"
)

// ExplorerOption is a functional option for configuring the Explorer.
type ExplorerOption func(*explorerOptions)

type explorerOptions struct {
	scannerType  ScannerType
	withTracker  bool
	pollInterval time.Duration
}

// WithScannerType explicitly sets the scanner type to use.
// If not specified, the scanner type is auto-detected from the URL scheme.
func WithScannerType(scannerType ScannerType) ExplorerOption {
	return func(opts *explorerOptions) {
		opts.scannerType = scannerType
	}
}

// WithTracker enables or disables address tracking.
// When enabled, the explorer provides real-time WebSocket subscriptions.
// When disabled, only REST API methods are available.
// Default: disabled
func WithTracker(enabled bool) ExplorerOption {
	return func(opts *explorerOptions) {
		opts.withTracker = enabled
	}
}

// WithPollInterval sets the polling interval for Mempool scanner fallback.
// Only applies to Mempool scanner when WebSocket connections fail.
// Default: 10 seconds
func WithPollInterval(interval time.Duration) ExplorerOption {
	return func(opts *explorerOptions) {
		opts.pollInterval = interval
	}
}

// NewExplorer creates a new blockchain explorer instance.
//
// The scanner type is auto-detected from the URL scheme:
//   - http://, https://              → Mempool scanner
//   - ws://, wss:// (mempool.space)  → Mempool scanner
//   - ssl://, electrum://            → Electrum scanner
//   - wss:// (electrum server)       → Electrum scanner
//
// Use WithScannerType() to explicitly override auto-detection.
//
// Examples:
//
//	// Auto-detect: Mempool scanner
//	explorer, err := explorer.NewExplorer("https://mempool.space/api", arklib.Bitcoin,
//	    explorer.WithTracker(true))
//
//	// Auto-detect: Electrum scanner
//	explorer, err := explorer.NewExplorer("ssl://electrum.blockstream.info:50002", arklib.Bitcoin,
//	    explorer.WithTracker(true))
//
//	// Explicit scanner type
//	explorer, err := explorer.NewExplorer("https://mempool.space/api", arklib.Bitcoin,
//	    explorer.WithScannerType(explorer.MempoolScanner),
//	    explorer.WithTracker(true))
func NewExplorer(baseUrl string, net arklib.Network, opts ...ExplorerOption) (Explorer, error) {
	// Apply options
	options := &explorerOptions{
		scannerType:  "", // Auto-detect by default
		withTracker:  false,
		pollInterval: 10 * time.Second,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Auto-detect scanner type from URL if not explicitly set
	if options.scannerType == "" {
		scannerType, err := detectScannerType(baseUrl)
		if err != nil {
			return nil, err
		}
		options.scannerType = scannerType
	}

	// Create appropriate scanner
	switch options.scannerType {
	case MempoolScanner:
		return createMempoolScanner(baseUrl, net, options)
	case ElectrumScanner:
		return createElectrumScanner(baseUrl, net, options)
	default:
		return nil, fmt.Errorf("unsupported scanner type: %s", options.scannerType)
	}
}

func detectScannerType(baseUrl string) (ScannerType, error) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	switch u.Scheme {
	case "http", "https":
		return MempoolScanner, nil
	case "ws":
		// WebSocket could be either - default to Mempool for backward compatibility
		return MempoolScanner, nil
	case "wss":
		// Check if it's a known Electrum server by port or host pattern
		if strings.Contains(u.Host, "electrum") || u.Port() == "50002" {
			return ElectrumScanner, nil
		}
		// Default to Mempool for backward compatibility
		return MempoolScanner, nil
	case "ssl", "electrum":
		return ElectrumScanner, nil
	default:
		return "", fmt.Errorf("unsupported URL scheme: %s (expected http://, https://, ssl://, or wss://)", u.Scheme)
	}
}

func createMempoolScanner(baseUrl string, net arklib.Network, options *explorerOptions) (Explorer, error) {
	var mempoolOpts []mempool_scanner.Option
	if options.withTracker {
		mempoolOpts = append(mempoolOpts, mempool_scanner.WithTracker(true))
	}
	if options.pollInterval > 0 {
		mempoolOpts = append(mempoolOpts, mempool_scanner.WithPollInterval(options.pollInterval))
	}

	scanner, err := mempool_scanner.NewScanner(baseUrl, net, mempoolOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create mempool scanner: %w", err)
	}

	return scanner, nil
}

func createElectrumScanner(baseUrl string, net arklib.Network, options *explorerOptions) (Explorer, error) {
	var electrumOpts []electrum_scanner.Option
	if options.withTracker {
		electrumOpts = append(electrumOpts, electrum_scanner.WithTracker(true))
	}

	scanner, err := electrum_scanner.NewScanner(baseUrl, net, electrumOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create electrum scanner: %w", err)
	}

	return scanner, nil
}
