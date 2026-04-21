package contract

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
)

const (
	watcherBackoffBase  = 1 * time.Second
	watcherBackoffCap   = 30 * time.Second
	watcherPollInterval = 60 * time.Second
)

// Watcher subscribes to the indexer for all active contract scripts and
// surfaces vtxo_received / vtxo_spent events through the Manager's event bus.
// A failsafe poll fires every 60 s to catch vtxos that may be missed by the stream.
type Watcher struct {
	idx     indexer.Indexer
	manager Manager

	mu      sync.Mutex
	subId   string
	scripts map[string]struct{} // currently watched scripts

	cancel context.CancelFunc
}

// NewWatcher creates a Watcher. Call Start to begin watching.
func NewWatcher(idx indexer.Indexer, mgr Manager) *Watcher {
	return &Watcher{
		idx:     idx,
		manager: mgr,
		scripts: make(map[string]struct{}),
	}
}

// Start collects all current contract scripts, creates an indexer subscription,
// and launches the listener and failsafe-poll goroutines.
// Newly created contracts are automatically added to the live subscription via
// the manager's OnContractEvent callback.
func (w *Watcher) Start(ctx context.Context) error {
	contracts, err := w.manager.GetContracts(ctx, Filter{})
	if err != nil {
		return fmt.Errorf("watcher: load initial contracts: %w", err)
	}

	initialScripts := make([]string, 0, len(contracts))
	for _, c := range contracts {
		if c.Script != "" {
			initialScripts = append(initialScripts, c.Script)
			w.scripts[c.Script] = struct{}{}
		}
	}

	watchCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel

	// When a new contract is created, add its script to the live subscription.
	unsub := w.manager.OnContractEvent(func(e Event) {
		if e.Type != "contract_created" || e.Contract.Script == "" {
			return
		}
		w.mu.Lock()
		_, already := w.scripts[e.Contract.Script]
		if !already {
			w.scripts[e.Contract.Script] = struct{}{}
		}
		subId := w.subId
		w.mu.Unlock()

		if already || subId == "" {
			return
		}
		if _, err := w.idx.SubscribeForScripts(
			watchCtx,
			subId,
			[]string{e.Contract.Script},
		); err != nil {
			log.WithError(err).Warn("watcher: failed to add new contract script to subscription")
		}
	})

	go func() {
		defer unsub()
		w.listen(watchCtx, initialScripts)
	}()

	go w.poll(watchCtx)

	return nil
}

// Stop cancels the watcher's context, shutting down all goroutines.
func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
}

// listen maintains the indexer subscription with exponential-backoff reconnects.
func (w *Watcher) listen(ctx context.Context, initialScripts []string) {
	scripts := initialScripts
	backoff := watcherBackoffBase

	for {
		if ctx.Err() != nil {
			return
		}

		// Create (or re-create) the subscription.
		subId, err := w.idx.SubscribeForScripts(ctx, "", scripts)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.WithError(err).Warnf("watcher: subscription failed, retrying in %s", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, watcherBackoffCap)
			scripts = w.currentScripts()
			continue
		}

		w.mu.Lock()
		w.subId = subId
		w.mu.Unlock()

		log.Debugf("watcher: subscribed to %d contract scripts (sub=%s)", len(scripts), subId)

		// Open the event channel for this subscription.
		events, closeFn, err := w.idx.GetSubscription(ctx, subId)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.WithError(err).Warnf("watcher: GetSubscription failed, retrying in %s", backoff)
			w.mu.Lock()
			w.subId = ""
			w.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, watcherBackoffCap)
			scripts = w.currentScripts()
			continue
		}

		backoff = watcherBackoffBase // reset after successful connect

		disconnected := w.processEvents(ctx, events)
		closeFn()

		w.mu.Lock()
		w.subId = ""
		w.mu.Unlock()

		if !disconnected || ctx.Err() != nil {
			return
		}

		log.Warnf("watcher: stream disconnected, retrying in %s", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, watcherBackoffCap)
		scripts = w.currentScripts()
	}
}

// processEvents drains the event channel until it closes or context is done.
// Returns true when the stream dropped and the caller should reconnect.
func (w *Watcher) processEvents(ctx context.Context, events <-chan indexer.ScriptEvent) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case ev, ok := <-events:
			if !ok {
				return true // channel closed → reconnect
			}
			if ev.Err != nil {
				log.WithError(ev.Err).Warn("watcher: stream error")
				return true
			}
			if ev.Connection != nil {
				log.Debugf("watcher: connection %s", ev.Connection.State)
				continue
			}
			if ev.Data != nil {
				w.handleData(ctx, ev.Data)
			}
		}
	}
}

func (w *Watcher) handleData(ctx context.Context, data *indexer.ScriptEventData) {
	// Build script → Contract map for the scripts involved in this event.
	scriptToContract := make(map[string]Contract, len(data.Scripts))
	for _, s := range data.Scripts {
		script := s
		cs, err := w.manager.GetContracts(ctx, Filter{Script: &script})
		if err != nil || len(cs) == 0 {
			continue
		}
		scriptToContract[s] = cs[0]
	}

	for _, vtxo := range data.NewVtxos {
		c, ok := scriptToContract[vtxo.Script]
		if !ok {
			continue
		}
		v := vtxo
		w.manager.EmitEvent(Event{
			Type:     "vtxo_received",
			Contract: c,
			Vtxos:    []clientTypes.Vtxo{v},
		})
	}

	for _, vtxo := range data.SpentVtxos {
		c, ok := scriptToContract[vtxo.Script]
		if !ok {
			continue
		}
		v := vtxo
		w.manager.EmitEvent(Event{
			Type:     "vtxo_spent",
			Contract: c,
			Vtxos:    []clientTypes.Vtxo{v},
		})
	}
}

// poll is the failsafe goroutine; it calls GetVtxos every 60 s for all
// watched scripts so vtxos missed by the stream surface eventually.
func (w *Watcher) poll(ctx context.Context) {
	ticker := time.NewTicker(watcherPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pollOnce(ctx)
		}
	}
}

func (w *Watcher) pollOnce(ctx context.Context) {
	scripts := w.currentScripts()
	if len(scripts) == 0 {
		return
	}
	resp, err := w.idx.GetVtxos(ctx, indexer.WithScripts(scripts))
	if err != nil {
		log.WithError(err).Warn("watcher: failsafe poll failed")
		return
	}
	data := &indexer.ScriptEventData{Scripts: scripts}
	for _, vtxo := range resp.Vtxos {
		v := vtxo
		if v.Spent {
			data.SpentVtxos = append(data.SpentVtxos, v)
		} else {
			data.NewVtxos = append(data.NewVtxos, v)
		}
	}
	if len(data.NewVtxos) > 0 || len(data.SpentVtxos) > 0 {
		w.handleData(ctx, data)
	}
}

func (w *Watcher) currentScripts() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.scripts))
	for s := range w.scripts {
		out = append(out, s)
	}
	return out
}
