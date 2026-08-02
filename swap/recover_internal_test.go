package swap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arkade-os/go-sdk/swap/boltz"
	swaptypes "github.com/arkade-os/go-sdk/swap/types"
	"github.com/stretchr/testify/require"
)

// TestRenegotiateChainSwapQuoteFailures pins that a failed quote fetch or acceptance surfaces
// an error to the recovery switch — which then falls through to the refund path — instead of
// leaving the swap stranded in a half-renegotiated state.
func TestRenegotiateChainSwapQuoteFailures(t *testing.T) {
	tests := []struct {
		name         string
		quoteStatus  int
		acceptStatus int
	}{
		{
			name:        "quote not offered",
			quoteStatus: http.StatusBadRequest,
		},
		{
			name:         "acceptance rejected",
			quoteStatus:  http.StatusOK,
			acceptStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					status := tt.quoteStatus
					if r.Method == http.MethodPost {
						status = tt.acceptStatus
					}
					w.WriteHeader(status)
					if status == http.StatusOK {
						// nolint
						w.Write([]byte(`{"amount": 45000}`))
						return
					}
					// nolint
					w.Write([]byte(`{"error": "quote not available"}`))
				},
			))
			t.Cleanup(srv.Close)

			manager := &SwapManager{boltzSvc: &boltz.Api{URL: srv.URL}}
			err := manager.renegotiateChainSwap(
				t.Context(), &swaptypes.Swap{Id: "swapid"},
			)
			require.Error(t, err)
		})
	}
}
