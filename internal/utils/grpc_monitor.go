package utils

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func MonitorSubscription(
	ctx context.Context,
	conn *grpc.ClientConn,
	onReconnect func(ctx context.Context) error,
) {
	firstReadySeen := false

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if conn.WaitForStateChange(ctx, conn.GetState()) {
				if conn.GetState() == connectivity.Ready {
					// first time we see the connection is ready, we don't want to reconnect
					if !firstReadySeen {
						firstReadySeen = true
						continue
					}
				} else {
					if firstReadySeen {
						if err := onReconnect(ctx); err != nil {
							logrus.WithError(err).Error("failed to reconnect to grpc server")
						}
					}
				}
			}
		}
	}
}
