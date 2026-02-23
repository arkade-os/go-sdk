package client_test

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/stretchr/testify/require"
)

func TestStream(t *testing.T) {
	client, err := grpcclient.NewClient("http://localhost:7070")
	require.NoError(t, err)
	defer client.Close()

	info, err := client.GetInfo(context.Background())
	require.NoError(t, err)
	fmt.Println(info)

	txChan, closeFn, err := client.GetTransactionsStream(context.Background())
	require.NoError(t, err)
	defer closeFn()

	go func() {
		for tx := range txChan {
			fmt.Println(tx)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh

	fmt.Println("done")
}

func TestGetInfo(t *testing.T) {
	client, err := grpcclient.NewClient("http://localhost:7070")
	require.NoError(t, err)

	for {
		info, _ := client.GetInfo(context.Background())

		fmt.Println(info)
		time.Sleep(2 * time.Second)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	client.Close()
	fmt.Println("done")
}
