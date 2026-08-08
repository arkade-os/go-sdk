package arksdk

import (
	"context"
	"testing"
	"time"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
)

// listenerReturnTimeout bounds how long a listener may take to notice that its
// source channel is gone. A busy-spinning listener never returns, so it trips
// this instead of hanging the suite forever.
const listenerReturnTimeout = 2 * time.Second

// stubIdentity satisfies identity.Identity by embedding it. The listener only
// checks the value for nil, so no method is ever called.
type stubIdentity struct{ identity.Identity }

// stubStreamWallet stubs the two clientwallet.Wallet methods listenForArkTxs
// reads. Every other method is nil and panics if called.
type stubStreamWallet struct {
	clientwallet.Wallet
	client client.Client
}

func (s *stubStreamWallet) Identity() identity.Identity { return &stubIdentity{} }
func (s *stubStreamWallet) Client() client.Client       { return s.client }

// stubStreamClient hands out a transaction stream the test owns, so the test
// can close it and observe how the listener reacts.
type stubStreamClient struct {
	client.Client
	ch <-chan client.TransactionEvent
}

func (s *stubStreamClient) GetTransactionsStream(
	_ context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	return s.ch, func() {}, nil
}

// TestListenForArkTxsStopsWhenStreamCloses pins the fix for a busy-spin that
// pegged a full CPU core: receiving from a closed channel returns immediately
// and forever, so a `continue` on !ok re-enters the select with nothing left to
// block on. The transport reconnects internally and only closes the channel on
// a terminal error, so the listener must stop rather than loop.
func TestListenForArkTxsStopsWhenStreamCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan client.TransactionEvent)
	w := &wallet{
		client: &stubStreamWallet{client: &stubStreamClient{ch: ch}},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.listenForArkTxs(ctx)
	}()

	close(ch)

	select {
	case <-done:
	case <-time.After(listenerReturnTimeout):
		t.Fatal("listenForArkTxs did not return after its stream closed: it is busy-spinning")
	}
}
