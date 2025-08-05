package utils

import (
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	retryWaitDuration = 2 * time.Second
	maxRetryCount     = 5
)

type RetryGrpcHandler struct {
	retryCount    int
	retryDuration time.Duration
	reconnectFn   func() error
}

func NewRetryGrpcHandler(reconnectFn func() error) *RetryGrpcHandler {
	return &RetryGrpcHandler{
		reconnectFn:   reconnectFn,
		retryDuration: retryWaitDuration,
		retryCount:    0,
	}
}

func (h *RetryGrpcHandler) ShouldRetry(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	if st.Code() == codes.Unimplemented || st.Code() == codes.Canceled ||
		st.Code() == codes.DataLoss {
		if h.retryCount >= maxRetryCount {
			return false
		}
		if err := h.reconnectFn(); err != nil {
			logrus.WithError(err).Error("failed to reconnect to grpc server")
		}
		time.Sleep(h.retryDuration)
		h.retryCount++
		h.retryDuration *= 2 // double
		return true
	}
	return false
}

func (h *RetryGrpcHandler) Reset() {
	h.retryCount = 0
	h.retryDuration = retryWaitDuration
}
