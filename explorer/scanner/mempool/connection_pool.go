package mempool_scanner

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// websocketConnection represents a single WebSocket connection with its subscribed addresses.
type websocketConnection struct {
	id      int
	conn    *websocket.Conn
	address *addressStore
	mu      *sync.RWMutex
}

// connectionPool manages multiple WebSocket connections for load distribution.
// Addresses are distributed across connections using consistent hash-based routing.
type connectionPool struct {
	connectionsByAddress map[string]int               // map address => connection index
	connections          map[int]*websocketConnection // pool of connections
	newConnectionCh      chan *websocketConnection
	mu                   *sync.RWMutex
	wsURL                string
	ctx                  context.Context
	noMoreConnections    bool
}

func newConnectionPool(ctx context.Context, wsURL string) (*connectionPool, error) {
	pool := &connectionPool{
		connectionsByAddress: make(map[string]int),
		connections:          make(map[int]*websocketConnection, 0),
		newConnectionCh:      make(chan *websocketConnection),
		mu:                   &sync.RWMutex{},
		wsURL:                wsURL,
		ctx:                  ctx,
	}

	if err := pool.addConnection(); err != nil {
		return nil, err
	}

	return pool, nil
}

func (cp *connectionPool) getNewConnections() <-chan *websocketConnection {
	return cp.newConnectionCh
}

func (cp *connectionPool) getConnectionCount() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.connections)
}

func (cp *connectionPool) addConnection() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.noMoreConnections {
		return fmt.Errorf("no more connections available")
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}
	conn, _, err := dialer.DialContext(cp.ctx, cp.wsURL, nil)
	if err != nil {
		cp.noMoreConnections = true
		return err
	}

	connId := len(cp.connections)
	wsConn := &websocketConnection{
		id:      connId,
		conn:    conn,
		address: newAddressStore(),
		mu:      &sync.RWMutex{},
	}

	cp.connections[connId] = wsConn
	go func() { cp.newConnectionCh <- wsConn }()

	return nil
}

func (cp *connectionPool) resetConnection(wsConn *websocketConnection) {
	cp.mu.Lock()
	// nolint
	wsConn.conn.Close()
	delete(cp.connections, wsConn.id)
	delete(cp.connectionsByAddress, wsConn.address.get())
	cp.noMoreConnections = false
	cp.mu.Unlock()

	// nolint
	cp.addConnection()
}

func (cp *connectionPool) pushAddress(address string) (*websocketConnection, bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if len(cp.connections) == 0 {
		return nil, false
	}

	conns := slices.Collect(maps.Values(cp.connections))
	idx := slices.IndexFunc(conns, func(c *websocketConnection) bool {
		return c.address.get() == ""
	})
	// If connections are all taken for an address, reject the request
	if idx < 0 {
		return nil, false
	}

	connId := conns[idx].id
	cp.connectionsByAddress[address] = connId
	cp.connections[connId].address.set(address)
	conn := cp.connections[connId]

	return conn, true
}

func (cp *connectionPool) popAddress(address string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	connId, ok := cp.connectionsByAddress[address]
	if !ok {
		return
	}
	delete(cp.connectionsByAddress, address)
	cp.connections[connId].address.remove(address)
}

func (cp *connectionPool) getConnectionForAddress(address string) (*websocketConnection, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	connId, ok := cp.connectionsByAddress[address]
	if !ok {
		return nil, false
	}
	return cp.connections[connId], true
}

type addressStore struct {
	mu      *sync.RWMutex
	address string
}

func newAddressStore() *addressStore {
	return &addressStore{
		mu: &sync.RWMutex{},
	}
}

func (l *addressStore) set(address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.address = address
}

func (l *addressStore) remove(_ string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.address = ""
}

func (l *addressStore) get() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.address
}
