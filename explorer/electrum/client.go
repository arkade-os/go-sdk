package electrum_explorer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	requestTimeout     = 15 * time.Second
	keepAliveInterval  = 60 * time.Second
	reconnectBaseDelay = 5 * time.Second
	reconnectMaxDelay  = 60 * time.Second
	maxScannerBytes    = 1 << 20 // 1 MB — large enough for verbose txs
)

type electrumClient struct {
	serverURL string
	tlsConfig *tls.Config // nil = default TLS config (system roots, TLS 1.2+)

	conn   net.Conn
	connMu sync.RWMutex // protects c.conn pointer only

	writeMu sync.Mutex // serializes all conn.Write calls so frames don't interleave

	reqID   atomic.Uint64
	pending map[uint64]chan *jsonRPCResponse
	pendMu  sync.Mutex

	// subs maps scripthash → channel that receives new status hash strings
	// whenever ElectrumX pushes a blockchain.scripthash.subscribe notification.
	subs   map[string]chan string
	subsMu sync.RWMutex

	// storedSubs is replayed in full on every reconnect.
	// storedSubsMu is kept separate from subsMu because subscribe() must not
	// hold either lock while doing the blocking RPC call, so the two maps are
	// updated independently under their own locks.
	storedSubs   []string
	storedSubsMu sync.Mutex

	reconnectMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc

	// cycleMu/cycleCancel track the current listen+keepAlive goroutine pair.
	// Cancelling the cycle context signals both goroutines to stop before a new
	// pair is started, preventing accumulation across reconnects.
	cycleMu     sync.Mutex
	cycleCancel context.CancelFunc
}

func newElectrumClient(serverURL string) *electrumClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &electrumClient{
		serverURL: serverURL,
		pending:   make(map[uint64]chan *jsonRPCResponse),
		subs:      make(map[string]chan string),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// connect dials the server and starts the listen + keepAlive goroutines.
// listen() must start before handshake() so that the server's response is read.
func (c *electrumClient) connect() error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	c.setConn(conn)

	// listen must start before handshake so responses can be dispatched.
	cycleCtx, _ := c.newCycleCtx()
	go c.listen(cycleCtx)
	go c.keepAlive(cycleCtx)

	if err := c.handshake(); err != nil {
		c.close() // cancels cycleCtx → listen exits without reconnecting
		return err
	}
	return nil
}

func (c *electrumClient) dial() (net.Conn, error) {
	addr := strings.TrimPrefix(strings.TrimPrefix(c.serverURL, "tcp://"), "ssl://")
	if strings.HasPrefix(c.serverURL, "ssl://") {
		tlsCfg := c.tlsConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp", addr, tlsCfg,
		)
	}
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

func (c *electrumClient) handshake() error {
	_, err := c.request("server.version", []any{"go-sdk", "1.4"})
	return err
}

func (c *electrumClient) setConn(conn net.Conn) {
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
}

func (c *electrumClient) getConn() net.Conn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.conn
}

// newCycleCtx cancels the previous keepAlive goroutine and returns a fresh
// child context (and its cancel) for the new listen+keepAlive cycle.
func (c *electrumClient) newCycleCtx() (context.Context, context.CancelFunc) {
	c.cycleMu.Lock()
	defer c.cycleMu.Unlock()
	if c.cycleCancel != nil {
		c.cycleCancel()
	}
	ctx, cancel := context.WithCancel(c.ctx)
	c.cycleCancel = cancel
	return ctx, cancel
}

// close cancels the current connection cycle and drains pending requests, but
// does NOT cancel the root context. Use shutdown() for a terminal teardown.
func (c *electrumClient) close() {
	c.cycleMu.Lock()
	if c.cycleCancel != nil {
		c.cycleCancel()
		c.cycleCancel = nil
	}
	c.cycleMu.Unlock()

	if conn := c.getConn(); conn != nil {
		conn.Close() // nolint
	}
	c.pendMu.Lock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.pendMu.Unlock()
}

// shutdown permanently tears down the client by cancelling the root context
// and then closing the current connection cycle.
func (c *electrumClient) shutdown() {
	c.cancel()
	c.close()
}

// listen reads newline-delimited JSON frames and dispatches them.
// Responses (have "id") go to the pending map; notifications (have "method") go to subs.
// On any scanner exit — including a clean EOF from a server restart — it calls
// reconnect unless ctx is cancelled (which signals that reconnect() already owns
// the recovery, e.g. after a failed handshake) or the client context is done.
func (c *electrumClient) listen(ctx context.Context) {
	conn := c.getConn()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, maxScannerBytes), maxScannerBytes)
	for scanner.Scan() {
		line := scanner.Bytes()

		// Peek at the "id" field to distinguish response from notification.
		var peek struct {
			ID     *uint64 `json:"id"`
			Method string  `json:"method"`
		}
		if err := json.Unmarshal(line, &peek); err != nil {
			log.WithError(err).Debug("electrum: failed to parse frame")
			continue
		}

		if peek.ID != nil {
			var resp jsonRPCResponse
			if err := json.Unmarshal(line, &resp); err != nil {
				log.WithError(err).Debug("electrum: failed to parse response")
				continue
			}
			c.pendMu.Lock()
			ch, ok := c.pending[resp.ID]
			if ok {
				delete(c.pending, resp.ID)
			}
			c.pendMu.Unlock()
			if ok {
				ch <- &resp
			}
			continue
		}

		if peek.Method == "blockchain.scripthash.subscribe" {
			var notif jsonRPCNotification
			if err := json.Unmarshal(line, &notif); err != nil {
				log.WithError(err).Debug("electrum: failed to parse notification")
				continue
			}
			if len(notif.Params) < 2 {
				continue
			}
			var scripthash, status string
			// nolint
			json.Unmarshal(notif.Params[0], &scripthash)
			// nolint
			json.Unmarshal(notif.Params[1], &status)
			c.subsMu.RLock()
			ch, ok := c.subs[scripthash]
			if ok {
				select {
				case ch <- status:
				default:
				}
			}
			c.subsMu.RUnlock()
		}
	}

	// If our cycle context was cancelled, reconnect() already owns recovery
	// (e.g., it cancelled us after a failed handshake). Don't double-reconnect.
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Scanner exited — reconnect unless the client is shutting down.
	// A nil error means clean EOF (e.g. server restarted and sent FIN);
	// we must reconnect in that case too, not just on I/O errors.
	if !c.contextDone() {
		if err := scanner.Err(); err != nil {
			log.WithError(err).Debug("electrum: connection error, reconnecting")
		} else {
			log.Debug("electrum: server closed connection, reconnecting")
		}
		if err := c.reconnect(); err != nil {
			log.WithError(err).Error("electrum: reconnect failed")
		}
	}
}

func (c *electrumClient) contextDone() bool {
	select {
	case <-c.ctx.Done():
		return true
	default:
		return false
	}
}

// keepAlive sends periodic server.ping RPCs to keep the connection alive.
// It exits when ctx is cancelled (i.e. when a new connection cycle starts).
func (c *electrumClient) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := c.request("server.ping", []any{}); err != nil {
				if !c.contextDone() {
					log.WithError(err).Debug("electrum: ping failed")
				}
				return
			}
		}
	}
}

// reconnect re-dials with exponential backoff and replays all subscriptions.
// Only one goroutine runs the reconnect body at a time.
// listen() is started before handshake() so that responses can be dispatched.
// If handshake fails the new cycle is cancelled so the freshly-started listen
// goroutine exits without triggering yet another reconnect.
func (c *electrumClient) reconnect() error {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	delay := reconnectBaseDelay
	for {
		if c.contextDone() {
			return errors.New("context cancelled")
		}
		conn, err := c.dial()
		if err != nil {
			log.WithError(err).Debugf("electrum: reconnect failed, retrying in %s", delay)
			select {
			case <-c.ctx.Done():
				return errors.New("context cancelled")
			case <-time.After(delay):
			}
			if delay < reconnectMaxDelay {
				delay *= 2
				if delay > reconnectMaxDelay {
					delay = reconnectMaxDelay
				}
			}
			continue
		}

		c.setConn(conn)

		// Start listen before handshake so the handshake response can be read.
		cycleCtx, cancelCycle := c.newCycleCtx()
		go c.listen(cycleCtx)
		go c.keepAlive(cycleCtx)

		if err := c.handshake(); err != nil {
			// Cancel the cycle first so listen() won't trigger another reconnect
			// when we close the connection below.
			cancelCycle()
			conn.Close() // nolint
			continue
		}

		// Replay subscriptions.
		c.storedSubsMu.Lock()
		subs := make([]string, len(c.storedSubs))
		copy(subs, c.storedSubs)
		c.storedSubsMu.Unlock()

		for _, sh := range subs {
			if _, err := c.request("blockchain.scripthash.subscribe", []any{sh}); err != nil {
				log.WithError(err).Warnf("electrum: failed to resubscribe %s", sh)
			}
		}

		log.Debug("electrum: reconnected and replayed subscriptions")
		return nil
	}
}

// request sends a single JSON-RPC call and waits up to requestTimeout for the response.
func (c *electrumClient) request(method string, params []any) (json.RawMessage, error) {
	id := c.reqID.Add(1)
	req := jsonRPCRequest{ID: id, Method: method, Params: params}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')

	ch := make(chan *jsonRPCResponse, 1)
	c.pendMu.Lock()
	c.pending[id] = ch
	c.pendMu.Unlock()
	defer func() {
		c.pendMu.Lock()
		delete(c.pending, id)
		c.pendMu.Unlock()
	}()

	conn := c.getConn()
	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	c.writeMu.Lock()
	_, err = conn.Write(data)
	c.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, requestTimeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("request timed out: %s", method)
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("connection closed waiting for %s", method)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("electrum error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
}

// subscribe sends blockchain.scripthash.subscribe and returns a channel that
// receives status-hash strings whenever the scripthash state changes.
func (c *electrumClient) subscribe(scripthash string) (<-chan string, error) {
	ch := make(chan string, 8)
	c.subsMu.Lock()
	c.subs[scripthash] = ch
	c.subsMu.Unlock()

	c.storedSubsMu.Lock()
	c.storedSubs = append(c.storedSubs, scripthash)
	c.storedSubsMu.Unlock()

	result, err := c.request("blockchain.scripthash.subscribe", []any{scripthash})
	if err != nil {
		c.subsMu.Lock()
		delete(c.subs, scripthash)
		c.subsMu.Unlock()

		c.storedSubsMu.Lock()
		filtered := c.storedSubs[:0]
		for _, sh := range c.storedSubs {
			if sh != scripthash {
				filtered = append(filtered, sh)
			}
		}
		c.storedSubs = filtered
		c.storedSubsMu.Unlock()

		return nil, err
	}

	// If the initial status is non-null, emit it so the caller sees the current state.
	var initialStatus string
	if err := json.Unmarshal(result, &initialStatus); err == nil && initialStatus != "" {
		select {
		case ch <- initialStatus:
		default:
		}
	}

	return ch, nil
}

// unsubscribeLocal removes a scripthash from the local subs map.
// ElectrumX has no unsubscribe wire message.
func (c *electrumClient) unsubscribeLocal(scripthash string) {
	c.subsMu.Lock()
	if ch, ok := c.subs[scripthash]; ok {
		close(ch)
		delete(c.subs, scripthash)
	}
	c.subsMu.Unlock()

	c.storedSubsMu.Lock()
	filtered := c.storedSubs[:0]
	for _, sh := range c.storedSubs {
		if sh != scripthash {
			filtered = append(filtered, sh)
		}
	}
	c.storedSubs = filtered
	c.storedSubsMu.Unlock()
}

func (c *electrumClient) isConnected() bool {
	return c.getConn() != nil
}
