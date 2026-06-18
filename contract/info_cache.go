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

// infoCache memoizes GetInfo across handlers attached to one manager.
type infoCache struct {
	mu                   sync.Mutex
	resp                 *client.Info
	lastUpdate           time.Time
	invalidationDuration time.Duration
	epoch                uint64
}

func newInfoCache(invalidationDuration time.Duration) *infoCache {
	return &infoCache{invalidationDuration: invalidationDuration}
}

func (c *infoCache) get() (*client.Info, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	epoch := c.epoch
	if c.lastUpdate.IsZero() {
		return nil, epoch
	}
	if time.Since(c.lastUpdate) > c.invalidationDuration {
		c.resp = nil
	}
	return c.resp, epoch
}

func (c *infoCache) set(resp *client.Info, epoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epoch != epoch {
		return
	}
	c.resp = resp
	c.lastUpdate = time.Now()
}

// Invalidate forces the next GetInfo call to hit the transport.
func (c *infoCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	c.resp = nil
	c.lastUpdate = time.Time{}
}

// cachingClient serves GetInfo from infoCache; other calls are promoted through.
type cachingClient struct {
	client.Client
	cache *infoCache
}

func newCachingClient(c client.Client, cache *infoCache) *cachingClient {
	return &cachingClient{Client: c, cache: cache}
}

func (c *cachingClient) GetInfo(ctx context.Context) (*client.Info, error) {
	cached, epoch := c.cache.get()
	if cached != nil {
		return cached, nil
	}
	resp, err := c.Client.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	c.cache.set(resp, epoch)
	return resp, nil
}
