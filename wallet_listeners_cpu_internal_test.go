//go:build unix

package arksdk

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/types"
)

// stubUtxoStore, stubVtxoStore and stubTxStore each expose one test-owned event
// channel. Every other store method is nil and panics if called.
type stubUtxoStore struct {
	types.UtxoStore
	ch <-chan types.UtxoEvent
}

func (s *stubUtxoStore) GetEventChannel() <-chan types.UtxoEvent { return s.ch }

type stubVtxoStore struct {
	types.VtxoStore
	ch <-chan types.VtxoEvent
}

func (s *stubVtxoStore) GetEventChannel() <-chan types.VtxoEvent { return s.ch }

type stubTxStore struct {
	types.TransactionStore
	ch <-chan types.TransactionEvent
}

func (s *stubTxStore) GetEventChannel() <-chan types.TransactionEvent { return s.ch }

type stubEventStore struct {
	types.Store
	utxo *stubUtxoStore
	vtxo *stubVtxoStore
	tx   *stubTxStore
}

func (s *stubEventStore) UtxoStore() types.UtxoStore               { return s.utxo }
func (s *stubEventStore) VtxoStore() types.VtxoStore               { return s.vtxo }
func (s *stubEventStore) TransactionStore() types.TransactionStore { return s.tx }

// processCPU reports CPU time consumed by this process so far. A parked
// goroutine adds essentially none; a busy-spinning one adds roughly wall-clock.
func processCPU(t *testing.T) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

const (
	// cpuSampleWindow is how long the listener is observed while idle.
	cpuSampleWindow = 300 * time.Millisecond
	// cpuSpinThreshold is the budget for that window. A parked listener uses
	// microseconds and a spinning one uses the full window, so anything in
	// between is a comfortable margin either way.
	cpuSpinThreshold = 100 * time.Millisecond
)

// TestListenDbEventsDoesNotSpinOnClosedChannels pins the fix for a busy-spin in
// the db event loop. It selects over three store channels at once, so a closed
// channel cannot simply end the loop; the closed arm has to be dropped from the
// select instead, or receiving from it returns immediately and forever.
func TestListenDbEventsDoesNotSpinOnClosedChannels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	utxoCh := make(chan types.UtxoEvent)
	vtxoCh := make(chan types.VtxoEvent)
	txCh := make(chan types.TransactionEvent)

	w := &wallet{
		store: &stubEventStore{
			utxo: &stubUtxoStore{ch: utxoCh},
			vtxo: &stubVtxoStore{ch: vtxoCh},
			tx:   &stubTxStore{ch: txCh},
		},
		utxoBroadcaster: newBroadcaster[types.UtxoEvent](),
		vtxoBroadcaster: newBroadcaster[types.VtxoEvent](),
		txBroadcaster:   newBroadcaster[types.TransactionEvent](),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.listenDbEvents(ctx)
	}()

	// Every source is gone, so the listener has nothing left to do but wait for
	// cancelation. It must park, not spin.
	close(utxoCh)
	close(vtxoCh)
	close(txCh)

	before := processCPU(t)
	time.Sleep(cpuSampleWindow)
	used := processCPU(t) - before

	if used > cpuSpinThreshold {
		t.Fatalf(
			"listenDbEvents burned %v of CPU in %v with all store channels closed: it is busy-spinning",
			used,
			cpuSampleWindow,
		)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(listenerReturnTimeout):
		t.Fatal("listenDbEvents did not return after its context was canceled")
	}
}
