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
		// Tiny TTL so we don't sit in time.Sleep. The cache uses real
		// time.Now() so a real (short) sleep is the simplest exercise.
		c := newInfoCache(20 * time.Millisecond)
		_, epoch := c.get()
		c.set(&client.Info{SignerPubKey: "abcd"}, epoch)

		got, _ := c.get()
		require.NotNil(t, got, "fresh entry must still be served")
		time.Sleep(40 * time.Millisecond)
		got, _ = c.get()
		require.Nil(t, got, "entry past TTL must be cleared")
	})

	t.Run("invalidate clears a fresh entry", func(t *testing.T) {
		// Invalidate must drop a still-fresh (within-TTL) entry so the next
		// GetInfo re-reads the signer set — the restore / live-rotation
		// freshness guarantee.
		c := newInfoCache(time.Minute)
		_, epoch := c.get()
		c.set(&client.Info{SignerPubKey: "abcd"}, epoch)
		got, _ := c.get()
		require.NotNil(t, got, "fresh entry must be served before invalidate")

		c.Invalidate()
		got, _ = c.get()
		require.Nil(t, got, "invalidated entry must be cleared even within TTL")
	})

	t.Run("invalidate discards stale in-flight set", func(t *testing.T) {
		c := newInfoCache(time.Minute)

		// Simulate a GetInfo cache miss that captures the current epoch before
		// it starts its transport call.
		_, epoch := c.get()

		// A rotation invalidates the cache while that transport call is in
		// flight. The stale response must not repopulate the cache afterward.
		c.Invalidate()
		c.set(&client.Info{SignerPubKey: "stale"}, epoch)

		got, _ := c.get()
		require.Nil(t, got, "stale in-flight response must be discarded")

		// A fresh request after invalidation captures the new epoch and can
		// populate the cache normally.
		_, freshEpoch := c.get()
		fresh := &client.Info{SignerPubKey: "fresh"}
		c.set(fresh, freshEpoch)

		got, _ = c.get()
		require.Equal(t, fresh, got)
	})

	t.Run("concurrent get/set does not race", func(t *testing.T) {
		// Run with -race for this to mean anything; the assertion is just
		// that both goroutines complete without deadlock or panic.
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
		// This is the regression guard for the original review feedback:
		// every handler attached to the manager must observe one shared
		// GetInfo call, not N (one per handler).
		mock := &countingTransport{info: &client.Info{SignerPubKey: "abcd"}}
		c := newCachingClient(mock, newInfoCache(time.Minute))

		for i := 0; i < 5; i++ {
			got, err := c.GetInfo(t.Context())
			require.NoError(t, err)
			require.Equal(t, "abcd", got.SignerPubKey)
		}
		require.Equal(t, 1, mock.callCount())
	})

	t.Run("invalidate forces the next GetInfo to hit the transport", func(t *testing.T) {
		// Restore / live-rotation path: after Invalidate the cache must re-read
		// the (possibly rotated) signer set from the transport.
		cache := newInfoCache(time.Minute)
		mock := &countingTransport{info: &client.Info{SignerPubKey: "old"}}
		c := newCachingClient(mock, cache)

		got, err := c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, "old", got.SignerPubKey)
		require.Equal(t, 1, mock.callCount())

		// Server rotates while cached; without invalidate the stale value sticks.
		mock.setInfo(&client.Info{SignerPubKey: "new"})
		cache.Invalidate()

		got, err = c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, "new", got.SignerPubKey, "invalidate must surface the rotated signer")
		require.Equal(t, 2, mock.callCount())
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
		// On error we must not poison the cache — the next call should
		// retry the transport rather than serving the failure forever.
		mock := &countingTransport{err: errors.New("transport down")}
		c := newCachingClient(mock, newInfoCache(time.Minute))

		got, err := c.GetInfo(t.Context())
		require.ErrorContains(t, err, "transport down")
		require.Nil(t, got)
		require.Equal(t, 1, mock.callCount())

		// Recover the transport, then verify the cache didn't latch the
		// previous failure.
		mock.setInfo(&client.Info{SignerPubKey: "abcd"})
		got, err = c.GetInfo(t.Context())
		require.NoError(t, err)
		require.Equal(t, "abcd", got.SignerPubKey)
		require.Equal(t, 2, mock.callCount())
	})
}

// countingTransport is a partial mock for client.TransportClient — only
// GetInfo is called by these tests, so the rest of the interface is left
// unimplemented via the embedded nil interface and would panic if invoked.
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
