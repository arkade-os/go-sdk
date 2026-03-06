package arksdk

import (
	"sync"
)

type broadcaster[T any] struct {
	mu        *sync.RWMutex
	listeners map[chan T]struct{}
	closed    bool
}

func newBroadcaster[T any]() *broadcaster[T] {
	return &broadcaster[T]{
		mu:        &sync.RWMutex{},
		listeners: make(map[chan T]struct{}),
	}
}

func (l *broadcaster[T]) subscribe(buf int) <-chan T {
	if buf == 0 {
		buf = 64
	}
	ch := make(chan T, buf)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		close(ch)
		return ch
	}
	l.listeners[ch] = struct{}{}
	return ch
}

func (l *broadcaster[T]) unsubscribe(ch <-chan T) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.listeners {
		if (<-chan T)(c) == ch {
			delete(l.listeners, c)
			close(c)
			break
		}
	}
}

func (l *broadcaster[T]) publish(v T) int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	listenersToRemove := make([]chan T, 0)
	for ch := range l.listeners {
		select {
		case ch <- v:
		default:
			listenersToRemove = append(listenersToRemove, ch)
		}
	}

	if len(listenersToRemove) > 0 {
		go func() {
			l.remove(listenersToRemove)
		}()
	}
	return len(listenersToRemove)
}

func (l *broadcaster[T]) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	for ch := range l.listeners {
		close(ch)
	}
	l.listeners = nil
	l.closed = true
}

func (l *broadcaster[T]) remove(chs []chan T) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ch := range chs {
		if _, ok := l.listeners[ch]; !ok {
			continue
		}
		close(ch)
		delete(l.listeners, ch)
	}
}
