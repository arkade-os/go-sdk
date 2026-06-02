package arksdk

import (
	"sync"
)

const (
	settleType = iota
	collabExitType
	sendType
)

// batchEntry represents the single batch tx (settle or collab-exit) that is
// active or pending at any given time. Its result is published (res/err set
// before done is closed) so a settle deduplicating against it can return it.
type batchEntry struct {
	res     string
	err     error
	started bool          // whether it has been dispatched to run
	turn    chan struct{} // closed when it is this batch's turn to run
	done    chan struct{} // closed when it has completed
}

// txHandler serializes spend operations (send/issue/reissue/burn) and batch
// operations (settle/collab-exit) so they never overlap and double-spend the
// same VTXOs. Only one operation runs at a time. Ordering is a priority queue:
// a pending batch tx always runs before any waiting spend tx (because settles
// race expiring VTXOs that would otherwise fail the queued spends), while
// within each class operations run first-in-first-out.
//
// At most one batch tx is ever active or pending: a second settle deduplicates
// against it (returns its result), and a collab-exit is rejected with
// ErrSettleInProgress.
type txHandler struct {
	mu     sync.Mutex
	busy   bool            // an operation's fn() is currently running
	lead   *batchEntry     // the active-or-pending batch tx, nil if none
	spends []chan struct{} // FIFO queue of waiting spend txs, each its own turn signal
}

func newTxHandler() *txHandler {
	return &txHandler{}
}

// dispatch hands the free slot to the next operation: a pending batch tx takes
// precedence, otherwise the oldest waiting spend tx runs. Caller must hold h.mu.
func (h *txHandler) dispatch() {
	if h.busy {
		return
	}
	if h.lead != nil && !h.lead.started {
		h.lead.started = true
		h.busy = true
		close(h.lead.turn)
		return
	}
	if len(h.spends) > 0 {
		turn := h.spends[0]
		h.spends = h.spends[1:]
		h.busy = true
		close(turn)
	}
}

// handleBatchTx runs a batch tx (settle or collab-exit) with precedence over
// waiting spend txs and without overlapping any in-flight operation. If a batch
// tx is already active or pending, a settle deduplicates against it (waits for
// it and returns its result) and a collab-exit is rejected.
func (h *txHandler) handleBatchTx(
	txType int, fn func() (string, error),
) (string, error) {
	h.mu.Lock()
	if h.lead != nil {
		lead := h.lead
		h.mu.Unlock()
		if txType == collabExitType {
			return "", ErrSettleInProgress
		}
		// settle: dedup against the active-or-pending batch tx.
		<-lead.done
		return lead.res, lead.err
	}

	entry := &batchEntry{turn: make(chan struct{}), done: make(chan struct{})}
	h.lead = entry
	h.dispatch()
	h.mu.Unlock()

	<-entry.turn
	res, err := fn()

	h.mu.Lock()
	entry.res = res
	entry.err = err
	h.lead = nil
	h.busy = false
	h.dispatch()
	h.mu.Unlock()

	close(entry.done)
	return res, err
}

// handleTx runs a spend tx (send/issue/reissue/burn). It waits its turn behind
// any in-flight operation and any pending batch tx, preserving FIFO order among
// spend txs, then runs without overlapping anything else.
func (h *txHandler) handleTx(fn func() (any, error)) (any, error) {
	h.mu.Lock()
	turn := make(chan struct{})
	h.spends = append(h.spends, turn)
	h.dispatch()
	h.mu.Unlock()

	<-turn
	res, err := fn()

	h.mu.Lock()
	h.busy = false
	h.dispatch()
	h.mu.Unlock()

	return res, err
}
