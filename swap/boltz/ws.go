package boltz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

const reconnectInterval = 15 * time.Second
const pingInterval = 30 * time.Second
const pongWait = 5 * time.Second

type SwapStatusResponse struct {
	Status           string `json:"status"`
	ZeroConfRejected bool   `json:"zeroConfRejected"`
	Transaction      struct {
		Id  string `json:"id"`
		Hex string `json:"hex"`
	} `json:"transaction"`

	Error string `json:"error"`
}

type SwapUpdate struct {
	SwapStatusResponse `       mapstructure:",squash"`
	Id                 string `                       json:"id"`
}

type Websocket struct {
	Updates chan SwapUpdate

	apiUrl        string
	subscriptions chan bool
	mu            sync.RWMutex
	conn          *websocket.Conn
	closed        bool
	reconnect     bool
	dialer        *websocket.Dialer
	swapIds       []string
}

type wsResponse struct {
	Event   string `json:"event"`
	Error   string `json:"error"`
	Channel string `json:"channel"`
	Args    []any  `json:"args"`
}

func (boltz *Api) NewWebsocket() *Websocket {
	httpTransport, ok := boltz.Client.Transport.(*http.Transport)

	dialer := *websocket.DefaultDialer
	if ok {
		dialer.Proxy = httpTransport.Proxy
	}

	return &Websocket{
		apiUrl:        boltz.WSURL,
		subscriptions: make(chan bool),
		dialer:        &dialer,
		Updates:       make(chan SwapUpdate),
	}
}

func (boltz *Websocket) Connect() error {
	wsUrl, err := url.Parse(boltz.apiUrl)
	if err != nil {
		return err
	}
	wsUrl.Path += "/v2/ws"

	switch wsUrl.Scheme {
	case "https":
		wsUrl.Scheme = "wss"
	case "http":
		wsUrl.Scheme = "ws"
	}

	conn, _, err := boltz.dialer.Dial(wsUrl.String(), nil)
	if err != nil {
		return fmt.Errorf("could not connect to boltz ws at %s: %w", wsUrl, err)
	}
	boltz.mu.Lock()
	boltz.conn = conn
	boltz.mu.Unlock()

	setDeadline := func() error {
		return conn.SetReadDeadline(time.Now().Add(pingInterval + pongWait))
	}
	_ = setDeadline()
	conn.SetPongHandler(func(string) error {
		return setDeadline()
	})
	pingTicker := time.NewTicker(pingInterval)

	go func() {
		defer pingTicker.Stop()
		for range pingTicker.C {
			// Will not wait longer with writing than for the response
			err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(pongWait))
			if err != nil {
				boltz.mu.RLock()
				closed := boltz.closed
				boltz.mu.RUnlock()
				if closed {
					return
				}
				return
			}
		}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic in boltz ws connection: %v", r)
			}
		}()

		for {
			msgType, message, err := conn.ReadMessage()
			if err != nil {
				boltz.mu.RLock()
				closed := boltz.closed
				boltz.mu.RUnlock()
				if closed {
					close(boltz.Updates)
					return
				}
				break
			}

			switch msgType {
			case websocket.TextMessage:
				var response wsResponse
				if err := json.Unmarshal(message, &response); err != nil {
					continue
				}
				if response.Error != "" {
					continue
				}

				switch response.Event {
				case "update":
					switch response.Channel {
					case "swap.update":
						for _, arg := range response.Args {
							var update SwapUpdate
							if err := mapstructure.Decode(arg, &update); err != nil {
								continue
							}
							boltz.Updates <- update
						}
					default:
					}
				case "subscribe":
					boltz.subscriptions <- true
					continue
				default:
				}
			}
		}
		for {
			pingTicker.Stop()
			boltz.mu.Lock()
			reconnect := boltz.reconnect
			if reconnect {
				boltz.reconnect = false
			}
			boltz.mu.Unlock()
			if reconnect {
				return
			} else {
				time.Sleep(reconnectInterval)
			}
			err := boltz.Connect()
			if err == nil {
				return
			}
		}
	}()

	boltz.mu.RLock()
	swapIDs := append([]string(nil), boltz.swapIds...)
	boltz.mu.RUnlock()
	if len(swapIDs) > 0 {
		return boltz.subscribe(swapIDs)
	}

	return nil
}

func (boltz *Websocket) subscribe(swapIds []string) error {
	boltz.mu.RLock()
	closed := boltz.closed
	boltz.mu.RUnlock()
	if closed {
		return errors.New("websocket is closed")
	}
	if len(swapIds) == 0 {
		return nil
	}
	boltz.mu.RLock()
	conn := boltz.conn
	boltz.mu.RUnlock()
	if conn == nil {
		return errors.New("websocket is not connected")
	}
	if err := conn.WriteJSON(map[string]any{
		"op":      "subscribe",
		"channel": "swap.update",
		"args":    swapIds,
	}); err != nil {
		return err
	}
	select {
	case <-boltz.subscriptions:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("no answer from boltz")
	}
}

func (boltz *Websocket) Subscribe(swapIds []string) error {
	if err := boltz.subscribe(swapIds); err != nil {
		// the connection might be dead, so forcefully reconnect
		if err := boltz.Reconnect(); err != nil {
			return fmt.Errorf("could not reconnect boltz ws: %w", err)
		}
		if err := boltz.subscribe(swapIds); err != nil {
			return err
		}
	}
	boltz.mu.Lock()
	boltz.swapIds = append(boltz.swapIds, swapIds...)
	boltz.mu.Unlock()
	return nil
}

func (boltz *Websocket) Unsubscribe(swapId string) {
	boltz.mu.Lock()
	boltz.swapIds = slices.DeleteFunc(boltz.swapIds, func(id string) bool {
		return id == swapId
	})
	boltz.mu.Unlock()
}

func (boltz *Websocket) Close() error {
	boltz.mu.Lock()
	boltz.closed = true
	conn := boltz.conn
	boltz.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (boltz *Websocket) Reconnect() error {
	boltz.mu.Lock()
	if boltz.closed {
		boltz.mu.Unlock()
		return errors.New("websocket is closed")
	}
	boltz.reconnect = true
	conn := boltz.conn
	boltz.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	return boltz.Connect()
}

func (boltz *Websocket) ConnectAndSubscribe(
	ctx context.Context,
	swapIds []string,
	retryInterval time.Duration,
) error {
	err := Retry(ctx, retryInterval, func(ctx context.Context) (bool, error) {
		err := boltz.Connect()
		if err != nil {
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("could not connect to boltz websocket: %w", err)
	}

	err = Retry(ctx, retryInterval, func(ctx context.Context) (bool, error) {
		err = boltz.Subscribe(swapIds)
		if err != nil {
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("could not subscribe to boltz websocket: %w", err)
	}

	return nil
}
