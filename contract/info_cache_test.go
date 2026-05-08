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
		require.Nil(t, c.get())
	})

	t.Run("set then get returns the stored response", func(t *testing.T) {
		c := newInfoCache(time.Minute)
		info := &client.Info{SignerPubKey: "abcd"}
		c.set(info)

		got := c.get()
		require.NotNil(t, got)
		require.Equal(t, info, got)
	})

	t.Run("expired entry is dropped on the next get", func(t *testing.T) {
		// Tiny TTL so we don't sit in time.Sleep. The cache uses real
		// time.Now() so a real (short) sleep is the simplest exercise.
		c := newInfoCache(20 * time.Millisecond)
		c.set(&client.Info{SignerPubKey: "abcd"})

		require.NotNil(t, c.get(), "fresh entry must still be served")
		time.Sleep(40 * time.Millisecond)
		require.Nil(t, c.get(), "entry past TTL must be cleared")
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
				c.set(&client.Info{SignerPubKey: "abcd"})
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_ = c.get()
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
	client.TransportClient
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
