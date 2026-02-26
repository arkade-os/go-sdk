package utils

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestShouldReconnect(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
		delay    time.Duration
	}{
		{
			name:     "unavailable reconnects",
			err:      status.Error(codes.Unavailable, "server unavailable"),
			expected: true,
			delay:    time.Second,
		},
		{
			name:     "resource exhausted reconnects with longer backoff",
			err:      status.Error(codes.ResourceExhausted, "rate limited"),
			expected: true,
			delay:    5 * time.Second,
		},
		{
			name:     "deadline exceeded reconnects",
			err:      status.Error(codes.DeadlineExceeded, "timeout"),
			expected: true,
			delay:    time.Second,
		},
		{
			name: "failed precondition reconnects (wallet not ready)",
			err: status.Error(
				codes.FailedPrecondition,
				"ark service not ready: wallet is locked or syncing",
			),
			expected: true,
			delay:    2 * time.Second,
		},
		{
			name:     "canceled does not reconnect",
			err:      status.Error(codes.Canceled, "client canceled"),
			expected: false,
			delay:    0,
		},
		{
			name:     "invalid argument does not reconnect",
			err:      status.Error(codes.InvalidArgument, "bad request"),
			expected: false,
			delay:    0,
		},
		{
			name:     "unimplemented does not reconnect",
			err:      status.Error(codes.Unimplemented, "unknown service"),
			expected: false,
			delay:    0,
		},
		{
			name:     "cloudflare 524 reconnects",
			err:      status.Error(codes.Unknown, "upstream timeout 524"),
			expected: true,
			delay:    5 * time.Second,
		},
		{
			name: "grpc briefly hits http gateway during restart",
			err: status.Error(
				codes.Unknown,
				"unexpected HTTP status code received from server: 200 (OK); malformed header: missing HTTP content-type",
			),
			expected: true,
			delay:    time.Second,
		},
		{
			name:     "plain error reconnects",
			err:      errors.New("connection dropped"),
			expected: true,
			delay:    time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, delay := ShouldReconnect(tt.err)
			if got != tt.expected {
				t.Fatalf("expected shouldReconnect=%v, got %v", tt.expected, got)
			}
			if delay != tt.delay {
				t.Fatalf("expected delay=%v, got %v", tt.delay, delay)
			}
		})
	}
}
