package arksdk

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBroadcaster(t *testing.T) {
	// All broadcaster operations are unconditionally valid — there are no
	// invalid cases to exercise.
	t.Run("valid", func(t *testing.T) {
		t.Run("subscribe buffer", func(t *testing.T) {
			fixtures := []struct {
				name    string
				buf     int
				wantCap int
			}{
				{
					name:    "zero defaults to 64",
					buf:     0,
					wantCap: 64,
				},
				{
					name:    "explicit buffer is used as-is",
					buf:     16,
					wantCap: 16,
				},
			}

			for _, f := range fixtures {
				t.Run(f.name, func(t *testing.T) {
					b := newBroadcaster[int]()
					ch := b.subscribe(f.buf)
					require.Equal(t, f.wantCap, cap(ch))
				})
			}
		})

		t.Run(
			"subscribe on closed broadcaster returns already-closed channel", func(t *testing.T) {
				b := newBroadcaster[int]()
				b.close()
				ch := b.subscribe(1)
				_, open := <-ch
				require.False(t, open)
			},
		)

		t.Run("unsubscribe closes and removes the channel", func(t *testing.T) {
			b := newBroadcaster[int]()
			ch := b.subscribe(1)
			b.unsubscribe(ch)
			_, open := <-ch
			require.False(t, open)
			// after removal, publish no longer sends to the channel
			b.publish(42)
			require.Empty(t, ch)
		})

		t.Run("unsubscribe unknown channel is a no-op", func(t *testing.T) {
			b := newBroadcaster[int]()
			other := make(chan int, 1)
			require.NotPanics(t, func() { b.unsubscribe(other) })
		})

		t.Run("publish", func(t *testing.T) {
			fixtures := []struct {
				name        string
				subscribers int
			}{
				{name: "no subscribers", subscribers: 0},
				{name: "single subscriber", subscribers: 1},
				{name: "multiple subscribers", subscribers: 3},
			}

			for _, f := range fixtures {
				t.Run(f.name, func(t *testing.T) {
					b := newBroadcaster[int]()
					channels := make([]<-chan int, f.subscribers)
					for i := range f.subscribers {
						channels[i] = b.subscribe(1)
					}
					dropped := b.publish(42)
					require.Equal(t, 0, dropped)
					for _, ch := range channels {
						require.Len(t, ch, 1)
						require.Equal(t, 42, <-ch)
					}
				})
			}
		})

		t.Run(
			"publish returns dropped count and schedules removal of full-buffer listeners",
			func(t *testing.T) {
				b := newBroadcaster[int]()
				ch := b.subscribe(1)
				b.publish(1)            // fills the buffer
				dropped := b.publish(2) // buffer full → listener dropped
				require.Equal(t, 1, dropped)

				// wait for the async remove goroutine to close the channel
				require.Eventually(t, func() bool {
					select {
					case _, open := <-ch:
						return !open
					default:
						return false
					}
				}, 100*time.Millisecond, time.Millisecond)
			},
		)

		t.Run("publish after close is a no-op", func(t *testing.T) {
			b := newBroadcaster[int]()
			_ = b.subscribe(1)
			b.close()
			dropped := b.publish(42)
			require.Equal(t, 0, dropped)
		})

		t.Run("close closes all subscriber channels", func(t *testing.T) {
			b := newBroadcaster[int]()
			ch1 := b.subscribe(1)
			ch2 := b.subscribe(1)
			b.close()
			_, open1 := <-ch1
			_, open2 := <-ch2
			require.False(t, open1)
			require.False(t, open2)
		})

		t.Run("close is idempotent", func(t *testing.T) {
			b := newBroadcaster[int]()
			_ = b.subscribe(1)
			require.NotPanics(t, func() {
				b.close()
				b.close()
			})
		})
	})
}
