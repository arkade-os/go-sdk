package mempool_explorer

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/gorilla/websocket"
)

func TestShouldExitReadLoop(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantExit bool
	}{
		{
			name:     "normal closure should exit",
			err:      &websocket.CloseError{Code: websocket.CloseNormalClosure},
			wantExit: true,
		},
		{
			name:     "going away should exit",
			err:      &websocket.CloseError{Code: websocket.CloseGoingAway},
			wantExit: true,
		},
		{
			name:     "abnormal closure should exit",
			err:      &websocket.CloseError{Code: websocket.CloseAbnormalClosure},
			wantExit: true,
		},
		{
			name:     "net.ErrClosed should exit",
			err:      net.ErrClosed,
			wantExit: true,
		},
		{
			name:     "os timeout error should exit",
			err:      &timeoutError{},
			wantExit: true,
		},
		{
			name:     "os.ErrDeadlineExceeded should exit",
			err:      os.ErrDeadlineExceeded,
			wantExit: true,
		},
		{
			name:     "context.DeadlineExceeded should exit",
			err:      context.DeadlineExceeded,
			wantExit: true,
		},
		{
			name:     "context.Canceled should exit",
			err:      context.Canceled,
			wantExit: true,
		},
		{
			name:     "generic error should not exit (should retry)",
			err:      errors.New("temporary read error"),
			wantExit: false,
		},
		{
			name:     "wrapped timeout error should exit",
			err:      wrapError(&timeoutError{}),
			wantExit: true,
		},
		{
			name:     "wrapped context.Canceled should exit",
			err:      wrapError(context.Canceled),
			wantExit: true,
		},
		{
			name:     "wrapped net.ErrClosed should exit",
			err:      wrapError(net.ErrClosed),
			wantExit: true,
		},
		{
			name:     "internal server error should not exit (should retry)",
			err:      &websocket.CloseError{Code: websocket.CloseInternalServerErr},
			wantExit: false,
		},
		{
			name:     "service restart error should not exit (should retry)",
			err:      &websocket.CloseError{Code: websocket.CloseServiceRestart},
			wantExit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldExitReadLoop(tt.err)
			if got != tt.wantExit {
				t.Errorf("shouldExitReadLoop() = %v, want %v for error: %v", got, tt.wantExit, tt.err)
			}
		})
	}
}

// timeoutError is a test helper that implements the timeout interface
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout error" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return false }

// wrapError wraps an error to test error unwrapping
func wrapError(err error) error {
	return &wrappedError{err: err}
}

type wrappedError struct {
	err error
}

func (e *wrappedError) Error() string {
	return "wrapped: " + e.err.Error()
}

func (e *wrappedError) Unwrap() error {
	return e.err
}
