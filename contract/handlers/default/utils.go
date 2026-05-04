package defaultHandler

import (
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
)

type infoCache struct {
	lock                 *sync.Mutex
	resp                 *client.Info
	lastUpdate           time.Time
	invalidationDuration int64
}

func newInfoCache(invalidationDuration time.Duration) *infoCache {
	return &infoCache{
		lock:                 &sync.Mutex{},
		invalidationDuration: int64(invalidationDuration.Seconds()),
	}
}

func (c *infoCache) get() *client.Info {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.lastUpdate.IsZero() {
		return nil
	}
	// Reset the cached response lazily at every get
	if time.Now().Unix()-c.lastUpdate.Unix() > c.invalidationDuration {
		c.resp = nil
	}
	return c.resp
}

func (c *infoCache) set(resp *client.Info) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.resp = resp
	c.lastUpdate = time.Now()
}
