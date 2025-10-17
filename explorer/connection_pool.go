package explorer

import (
	"crypto/sha256"
	"sync"

	"github.com/gorilla/websocket"
)

// websocketConnection represents a single WebSocket connection with its subscribed addresses.
type websocketConnection struct {
	conn          *websocket.Conn
	addressBucket map[string]bool // Track subscribed addresses for this connection
	mu            sync.RWMutex
}

// connectionPool manages multiple WebSocket connections for load distribution.
// Addresses are distributed across connections using consistent hash-based routing.
type connectionPool struct {
	connections    []*websocketConnection
	maxConnections int
	currentIndex   int // For round-robin distribution
	mu             sync.RWMutex
}

func newConnectionPool(maxConnections int) *connectionPool {
	return &connectionPool{
		connections:    make([]*websocketConnection, 0, maxConnections),
		maxConnections: maxConnections,
		currentIndex:   0,
	}
}

func (cp *connectionPool) getConnectionCount() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.connections)
}

func (cp *connectionPool) addConnection(conn *websocket.Conn) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	wsConn := &websocketConnection{
		conn:          conn,
		addressBucket: make(map[string]bool),
	}

	cp.connections = append(cp.connections, wsConn)
}

func (cp *connectionPool) getConnectionForAddress(address string) (*websocketConnection, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	// Guard against empty connection pool
	n := len(cp.connections)
	if n == 0 {
		return nil, false
	}

	// Use hash-based distribution to consistently assign addresses to connections
	// Use actual number of live connections instead of maxConnections
	hash := sha256.Sum256([]byte(address))
	connectionIndex := int(hash[0]) % n

	return cp.connections[connectionIndex], true
}
