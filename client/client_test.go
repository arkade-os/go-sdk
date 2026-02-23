package client_test

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetInfo(t *testing.T) {
	client, err := grpcclient.NewClient("http://localhost:7070")
	require.NoError(t, err)
	defer client.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Println("done")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			info, err := client.GetInfo(ctx)
			cancel()

			if err != nil {
				st, ok := status.FromError(err)
				if ok && (st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded) {
					fmt.Printf("temporary error (arkd down/reconnecting): %v\n", err)
					continue
				}
				fmt.Printf("GetInfo error: %v\n", err)
				continue
			}

			fmt.Println(info)
		}
	}
}

func TestGetInfo1(t *testing.T) {
	newClient := func() client.TransportClient {
		c, err := grpcclient.NewClient("http://127.0.0.1:7070") // avoid localhost v4/v6 ambiguity
		require.NoError(t, err)
		return c
	}

	c := newClient()
	defer c.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Println("done")
			return

		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			info, err := c.GetInfo(ctx)
			cancel()

			if err == nil {
				fmt.Println(info)
				continue
			}

			st, ok := status.FromError(err)
			if !ok {
				fmt.Printf("GetInfo error: %v\n", err)
				continue
			}

			switch st.Code() {
			case codes.Unavailable, codes.DeadlineExceeded:
				fmt.Printf("temporary error: %v\n", err)

			case codes.Unimplemented:
				// Server is up but ArkService not ready/exposed yet; recreate client.
				fmt.Printf("server not ready yet (%v), recreating client\n", err)
				c.Close()
				c = newClient()

			default:
				fmt.Printf("GetInfo error: %v\n", err)
			}
		}
	}
}

func TestManualTransactionsStreamRestart(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	client, err := grpcclient.NewClient("http://127.0.0.1:7070")
	require.NoError(t, err)
	defer client.Close()

	txCh, closeFn, err := client.GetTransactionsStream(context.Background())
	require.NoError(t, err)
	defer closeFn()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	fmt.Println("manual stream test started")
	fmt.Println("restart arkd now and trigger transactions; stream should resume automatically")
	fmt.Println("press Ctrl+C to stop")

	for {
		select {
		case <-sigCh:
			fmt.Println("done")
			return
		case ev, ok := <-txCh:
			if !ok {
				fmt.Println("transactions stream channel closed")
				return
			}
			if ev.Err != nil {
				fmt.Printf("stream error (reconnect may be in progress): %v\n", ev.Err)
				continue
			}
			fmt.Printf("stream event: %+v\n", ev)
		}
	}
}
