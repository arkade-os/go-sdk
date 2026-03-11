package arksdk

import (
	"errors"
	"testing"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestSyncListeners(t *testing.T) {
	// All operations on syncListeners are unconditionally valid — there are no
	// invalid cases to exercise.
	t.Run("valid", func(t *testing.T) {
		t.Run("broadcast", func(t *testing.T) {
			fixtures := []struct {
				name       string
				err        error
				wantSynced bool
			}{
				{
					name:       "nil error signals success",
					err:        nil,
					wantSynced: true,
				},
				{
					name:       "non-nil error signals failure",
					err:        errors.New("something failed"),
					wantSynced: false,
				},
			}

			for _, f := range fixtures {
				t.Run(f.name, func(t *testing.T) {
					l := newReadyListeners()
					ch := make(chan types.SyncEvent, 1)
					l.add(ch)
					l.broadcast(f.err)
					got := <-ch
					require.Equal(t, f.wantSynced, got.Synced)
					require.Equal(t, f.err, got.Err)
				})
			}
		})

		t.Run("broadcast with no listeners does not block", func(t *testing.T) {
			l := newReadyListeners()
			l.broadcast(nil)
		})

		t.Run("broadcast reaches all listeners", func(t *testing.T) {
			l := newReadyListeners()
			ch1 := make(chan types.SyncEvent, 1)
			ch2 := make(chan types.SyncEvent, 1)
			ch3 := make(chan types.SyncEvent, 1)
			l.add(ch1)
			l.add(ch2)
			l.add(ch3)
			l.broadcast(nil)
			require.Len(t, ch1, 1)
			require.Len(t, ch2, 1)
			require.Len(t, ch3, 1)
		})

		t.Run("add same channel twice is idempotent", func(t *testing.T) {
			l := newReadyListeners()
			ch := make(chan types.SyncEvent, 2)
			l.add(ch)
			l.add(ch)
			l.broadcast(nil)
			require.Len(t, ch, 1)
		})

		t.Run("clear closes all channels", func(t *testing.T) {
			l := newReadyListeners()
			ch1 := make(chan types.SyncEvent, 1)
			ch2 := make(chan types.SyncEvent, 1)
			l.add(ch1)
			l.add(ch2)
			l.clear()
			_, open1 := <-ch1
			_, open2 := <-ch2
			require.False(t, open1)
			require.False(t, open2)
		})

		t.Run("clear on empty listeners does not panic", func(t *testing.T) {
			l := newReadyListeners()
			require.NotPanics(t, func() { l.clear() })
		})

		t.Run("clear resets state for new listeners", func(t *testing.T) {
			l := newReadyListeners()
			old := make(chan types.SyncEvent, 1)
			l.add(old)
			l.clear()

			fresh := make(chan types.SyncEvent, 1)
			l.add(fresh)
			l.broadcast(nil)
			require.Len(t, fresh, 1)
			require.Empty(t, old) // cleared channel was not re-sent to
		})
	})
}
