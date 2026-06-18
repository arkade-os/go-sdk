package contract

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/stretchr/testify/require"
)

func TestInfoCache(t *testing.T) {
	t.Run("empty cache returns nil", func(t *testing.T) {
		c := newInfoCache(time.Minute)
		got, _ := c.get()
		require.Nil(t, got)
	})

	t.Run("set then get returns the stored response", func(t *testing.T) {
		c := newInfoCache(time.Minute)
		info := &client.Info{SignerPubKey: "abcd"}
		_, epoch := c.get()
		c.set(info, epoch)

		got, _ := c.get()
		require.NotNil(t, got)
		require.Equal(t, info, got)
	})

	t.Run("expired entry is dropped on the next get", func(t *testing.T) {
		// Tiny TTL keeps the real sleep short.
		c := newInfoCache(20 * time.Millisecond)
		_, epoch := c.get()
		c.set(&client.Info{SignerPubKey: "abcd"}, epoch)

		got, _ := c.get()
		require.NotNil(t, got, "fresh entry must still be served")
		time.Sleep(40 * time.Millisecond)
		got, _ = c.get()
		require.Nil(t, got, "entry past TTL must be cleared")
	})

	t.Run("forceSet stores a fresh entry", func(t *testing.T) {
		c := newInfoCache(time.Minute)
		_, epoch := c.get()
		c.set(&client.Info{SignerPubKey: "abcd"}, epoch)
		got, _ := c.get()
		require.NotNil(t, got, "fresh entry must be served before forceSet")

		forced := &client.Info{SignerPubKey: "fresh"}
		c.forceSet(forced)
		got, _ = c.get()
		require.Equal(t, forced, got)
	})

	t.Run("forceSet discards stale in-flight set", func(t *testing.T) {
		c := newInfoCache(time.Minute)

		_, epoch := c.get()

		// forceSet must reject a response started under the old epoch.
		fresh := &client.Info{SignerPubKey: "fresh"}
		c.forceSet(fresh)
		c.set(&client.Info{SignerPubKey: "stale"}, epoch)

		got, _ := c.get()
		require.Equal(t, fresh, got, "stale in-flight response must be discarded")
	})

	t.Run("concurrent get/set does not race", func(t *testing.T) {
		// Meaningful with -race; also catches deadlocks.
		c := newInfoCache(time.Minute)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_, epoch := c.get()
				c.set(&client.Info{SignerPubKey: "abcd"}, epoch)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_, _ = c.get()
			}
		}()
		wg.Wait()
	})
}

func TestCachingClient(t *testing.T) {
	t.Run("first GetInfo hits the transport", func(t *testing.T) {
		mock := &countingTransport{info: &client.Info{SignerPubKey: "abcd"}}
		c := newCachingClient(mock, newInfoCache(time.Minute))

		got, err := c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, "abcd", got.SignerPubKey)
		require.Equal(t, 1, mock.callCount())
	})

	t.Run("subsequent GetInfo within TTL reuses the cache", func(t *testing.T) {
		// Regression guard: one shared GetInfo call, not one per handler.
		mock := &countingTransport{info: &client.Info{SignerPubKey: "abcd"}}
		c := newCachingClient(mock, newInfoCache(time.Minute))

		for i := 0; i < 5; i++ {
			got, err := c.GetInfo(t.Context())
			require.NoError(t, err)
			require.Equal(t, "abcd", got.SignerPubKey)
		}
		require.Equal(t, 1, mock.callCount())
	})

	t.Run("forceSet serves fresh info without another transport call", func(t *testing.T) {
		cache := newInfoCache(time.Minute)
		mock := &countingTransport{info: &client.Info{SignerPubKey: "old"}}
		c := newCachingClient(mock, cache)

		got, err := c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, "old", got.SignerPubKey)
		require.Equal(t, 1, mock.callCount())

		cache.forceSet(&client.Info{SignerPubKey: "new"})

		got, err = c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, "new", got.SignerPubKey, "forceSet must surface the rotated signer")
		require.Equal(t, 1, mock.callCount())
	})

	t.Run("after TTL the next GetInfo hits the transport again", func(t *testing.T) {
		mock := &countingTransport{info: &client.Info{SignerPubKey: "abcd"}}
		c := newCachingClient(mock, newInfoCache(20*time.Millisecond))

		_, err := c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, 1, mock.callCount())

		time.Sleep(40 * time.Millisecond)

		_, err = c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, 2, mock.callCount())
	})

	t.Run("transport error is propagated and not cached", func(t *testing.T) {
		mock := &countingTransport{err: errors.New("transport down")}
		c := newCachingClient(mock, newInfoCache(time.Minute))

		got, err := c.GetInfo(t.Context())
		require.ErrorContains(t, err, "transport down")
		require.Nil(t, got)
		require.Equal(t, 1, mock.callCount())

		mock.setInfo(&client.Info{SignerPubKey: "abcd"})
		got, err = c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, "abcd", got.SignerPubKey)
		require.Equal(t, 2, mock.callCount())
	})
}

// countingTransport only implements GetInfo; other promoted methods would panic.
type countingTransport struct {
	client.Client
	mu    sync.Mutex
	info  *client.Info
	err   error
	calls int
}

func (c *countingTransport) GetInfo(_ context.Context) (*client.Info, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	return c.info, nil
}

func (c *countingTransport) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingTransport) setInfo(info *client.Info) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.info = info
	c.err = nil
}
