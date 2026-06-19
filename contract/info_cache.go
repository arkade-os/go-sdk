package contract

import (
	"context"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
)

// infoCacheTTL is how long a cached client.Info response is reused before
// the next GetInfo call hits the transport.
const infoCacheTTL = 5 * time.Minute

// infoCache memoizes the response of client.TransportClient.GetInfo so
// every handler attached to the same manager shares one cache instead of
// each owning its own (which would multiply redundant GetInfo calls as
// new handler kinds — vhtlc, delegate — are added).
type infoCache struct {
	mu                   sync.Mutex
	resp                 *client.Info
	lastUpdate           time.Time
	invalidationDuration time.Duration
}

func newInfoCache(invalidationDuration time.Duration) *infoCache {
	return &infoCache{invalidationDuration: invalidationDuration}
}

func (c *infoCache) get() *client.Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastUpdate.IsZero() {
		return nil
	}
	if time.Since(c.lastUpdate) > c.invalidationDuration {
		c.resp = nil
	}
	return c.resp
}

func (c *infoCache) set(resp *client.Info) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resp = resp
	c.lastUpdate = time.Now()
}

// cachingClient is a transport-client decorator that intercepts GetInfo
// and serves it from a shared infoCache. Every other call passes through
// to the embedded client unchanged via Go's method promotion.
type cachingClient struct {
	client.Client
	cache *infoCache
}

func newCachingClient(c client.Client, cache *infoCache) *cachingClient {
	return &cachingClient{Client: c, cache: cache}
}

func (c *cachingClient) GetInfo(ctx context.Context) (*client.Info, error) {
	if cached := c.cache.get(); cached != nil {
		return cached, nil
	}
	resp, err := c.Client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	c.cache.set(resp)
	return resp, nil
}
