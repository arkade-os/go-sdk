package contract

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// delegateInfoCacheTTL is how long a fetched delegate public key is reused
// before the next lookup hits the URL again.
const delegateInfoCacheTTL = 5 * time.Minute

// delegateInfoCache memoizes the delegate public key resolved from the
// configured URL so the delegate handler shares one cache instead of
// re-fetching on every contract derivation.
type delegateInfoCache struct {
	mu                   sync.Mutex
	key                  *btcec.PublicKey
	lastUpdate           time.Time
	invalidationDuration time.Duration
}

func newDelegateInfoCache(invalidationDuration time.Duration) *delegateInfoCache {
	return &delegateInfoCache{invalidationDuration: invalidationDuration}
}

func (c *delegateInfoCache) get() *btcec.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastUpdate.IsZero() {
		return nil
	}
	if time.Since(c.lastUpdate) > c.invalidationDuration {
		c.key = nil
	}
	return c.key
}

func (c *delegateInfoCache) set(key *btcec.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.key = key
	c.lastUpdate = time.Now()
}

// fetchDelegateKey resolves the delegate public key from url, expecting a
// 200 response with a JSON body {"pubkey":"<hex-encoded compressed pubkey>"}.
func fetchDelegateKey(ctx context.Context, url string) (*btcec.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build delegate request: %w", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch delegate key: %w", err)
	}
	// nolint:errcheck
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch delegate key: unexpected status %s", resp.Status,
		)
	}

	var body struct {
		PubKey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to decode delegate key: %w", err)
	}

	keyBytes, err := hex.DecodeString(body.PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode delegate pubkey: %w", err)
	}
	if len(keyBytes) != 33 {
		return nil, fmt.Errorf(
			"delegate pubkey must be 33-byte compressed, got %d bytes", len(keyBytes),
		)
	}

	key, err := btcec.ParsePubKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse delegate pubkey: %w", err)
	}
	return key, nil
}
