package arksdk

import (
	"sync"

	"github.com/arkade-os/go-sdk/types"
)

type syncListeners struct {
	lock      *sync.RWMutex
	listeners map[chan types.SyncEvent]struct{}
}

func newReadyListeners() *syncListeners {
	return &syncListeners{
		lock:      &sync.RWMutex{},
		listeners: make(map[chan types.SyncEvent]struct{}),
	}
}

func (l *syncListeners) add(ch chan types.SyncEvent) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.listeners[ch] = struct{}{}
}

func (l *syncListeners) broadcast(err error) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	event := types.SyncEvent{Synced: err == nil, Err: err}
	for ch := range l.listeners {
		select {
		case ch <- event:
		default:
		}
	}
}

func (l *syncListeners) clear() {
	l.lock.Lock()
	defer l.lock.Unlock()
	for ch := range l.listeners {
		close(ch)
	}
	l.listeners = make(map[chan types.SyncEvent]struct{})
}
