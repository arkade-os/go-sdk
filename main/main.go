package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	restclient "github.com/arkade-os/go-sdk/client/rest"
)

func main() {
	client, err := restclient.NewClient("http://127.0.0.1:7070")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("GetInfo")
	fmt.Println(client.GetInfo(context.Background()))

	fmt.Println("connecting to server...")
	ch, cancel, err := client.GetTransactionsStream(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer cancel()

	go func() {
		for ev := range ch {
			fmt.Printf("RECEIVED EVENT: %+v\n", ev)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, os.Interrupt)
	<-sigChan
}
