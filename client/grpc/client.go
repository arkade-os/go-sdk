package grpcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	arkv1 "github.com/arkade-os/go-sdk/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const cloudflare524Error = "524"

type service struct {
	arkv1.ArkServiceClient
}

type grpcClient struct {
	mu     sync.Mutex
	target string
	opts   []grpc.DialOption
	conn   *grpc.ClientConn
	svc    service
	cancel context.CancelFunc
}

func (c *grpcClient) ensureConnection(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		state := c.conn.GetState()
		if state == connectivity.Ready {
			return nil
		}

		if state == connectivity.Shutdown || state == connectivity.TransientFailure {
			if err := c.conn.Close(); err != nil {
				logrus.Warnf("failed to close grpc connection: %v", err)
			}
			conn, err := grpc.NewClient(c.target, c.opts...)
			if err != nil {
				return err
			}
			c.conn = conn
			c.svc = service{arkv1.NewArkServiceClient(conn)}
			state = c.conn.GetState()
			if state == connectivity.Ready {
				return nil
			}
		}

		if !c.conn.WaitForStateChange(ctx, state) {
			return ctx.Err()
		}
	}
}

func NewClient(serverUrl string) (client.TransportClient, error) {
	if len(serverUrl) <= 0 {
		return nil, fmt.Errorf("missing server url")
	}

	port := 80
	creds := insecure.NewCredentials()
	serverUrl = strings.TrimPrefix(serverUrl, "http://")
	if strings.HasPrefix(serverUrl, "https://") {
		serverUrl = strings.TrimPrefix(serverUrl, "https://")
		creds = credentials.NewTLS(nil)
		port = 443
	}
	if !strings.Contains(serverUrl, ":") {
		serverUrl = fmt.Sprintf("%s:%d", serverUrl, port)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	conn, err := grpc.NewClient(serverUrl, opts...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &grpcClient{
		target: serverUrl,
		opts:   opts,
		conn:   conn,
		svc:    service{arkv1.NewArkServiceClient(conn)},
		cancel: cancel,
	}
	go c.monitorConnection(ctx)
	return c, nil
}

func (c *grpcClient) monitorConnection(ctx context.Context) {
	for {
		if err := c.ensureConnection(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			logrus.Warnf("failed to ensure grpc connection: %v", err)
			time.Sleep(time.Second)
			continue
		}

		if !c.conn.WaitForStateChange(ctx, connectivity.Ready) {
			return
		}
	}
}

func (a *grpcClient) GetInfo(ctx context.Context) (*client.Info, error) {
	if err := a.ensureConnection(ctx); err != nil {
		return nil, err
	}
	req := &arkv1.GetInfoRequest{}
	resp, err := a.svc.GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	var marketHourStartTime, marketHourEndTime, marketHourPeriod, marketHourRoundInterval int64
	if mktHour := resp.GetMarketHour(); mktHour != nil {
		marketHourStartTime = mktHour.GetNextStartTime()
		marketHourEndTime = mktHour.GetNextEndTime()
		marketHourPeriod = mktHour.GetPeriod()
		marketHourRoundInterval = mktHour.GetRoundInterval()
	}
	return &client.Info{
		SignerPubKey:            resp.GetSignerPubkey(),
		VtxoTreeExpiry:          resp.GetVtxoTreeExpiry(),
		UnilateralExitDelay:     resp.GetUnilateralExitDelay(),
		RoundInterval:           resp.GetRoundInterval(),
		Network:                 resp.GetNetwork(),
		Dust:                    uint64(resp.GetDust()),
		BoardingExitDelay:       resp.GetBoardingExitDelay(),
		ForfeitAddress:          resp.GetForfeitAddress(),
		Version:                 resp.GetVersion(),
		MarketHourStartTime:     marketHourStartTime,
		MarketHourEndTime:       marketHourEndTime,
		MarketHourPeriod:        marketHourPeriod,
		MarketHourRoundInterval: marketHourRoundInterval,
		UtxoMinAmount:           resp.GetUtxoMinAmount(),
		UtxoMaxAmount:           resp.GetUtxoMaxAmount(),
		VtxoMinAmount:           resp.GetVtxoMinAmount(),
		VtxoMaxAmount:           resp.GetVtxoMaxAmount(),
	}, nil
}

func (a *grpcClient) RegisterIntent(
	ctx context.Context,
	signature, message string,
) (string, error) {
	if err := a.ensureConnection(ctx); err != nil {
		return "", err
	}
	req := &arkv1.RegisterIntentRequest{
		Intent: &arkv1.Bip322Signature{
			Message:   message,
			Signature: signature,
		},
	}

	resp, err := a.svc.RegisterIntent(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetIntentId(), nil
}

func (a *grpcClient) DeleteIntent(ctx context.Context, signature, message string) error {
	if err := a.ensureConnection(ctx); err != nil {
		return err
	}
	req := &arkv1.DeleteIntentRequest{
		Proof: &arkv1.Bip322Signature{
			Message:   message,
			Signature: signature,
		},
	}
	_, err := a.svc.DeleteIntent(ctx, req)
	return err
}

func (a *grpcClient) ConfirmRegistration(ctx context.Context, intentID string) error {
	if err := a.ensureConnection(ctx); err != nil {
		return err
	}
	req := &arkv1.ConfirmRegistrationRequest{
		IntentId: intentID,
	}
	_, err := a.svc.ConfirmRegistration(ctx, req)
	return err
}

func (a *grpcClient) SubmitTreeNonces(
	ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces,
) error {
	if err := a.ensureConnection(ctx); err != nil {
		return err
	}
	sigsJSON, err := json.Marshal(nonces)
	if err != nil {
		return err
	}

	req := &arkv1.SubmitTreeNoncesRequest{
		BatchId:    batchId,
		Pubkey:     cosignerPubkey,
		TreeNonces: string(sigsJSON),
	}

	if _, err := a.svc.SubmitTreeNonces(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitTreeSignatures(
	ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs,
) error {
	if err := a.ensureConnection(ctx); err != nil {
		return err
	}
	sigsJSON, err := json.Marshal(signatures)
	if err != nil {
		return err
	}

	req := &arkv1.SubmitTreeSignaturesRequest{
		BatchId:        batchId,
		Pubkey:         cosignerPubkey,
		TreeSignatures: string(sigsJSON),
	}

	if _, err := a.svc.SubmitTreeSignatures(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
) error {
	if err := a.ensureConnection(ctx); err != nil {
		return err
	}
	req := &arkv1.SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs:   signedForfeitTxs,
		SignedCommitmentTx: signedCommitmentTx,
	}

	_, err := a.svc.SubmitSignedForfeitTxs(ctx, req)
	return err
}

func (a *grpcClient) GetEventStream(
	ctx context.Context,
	topics []string,
) (<-chan client.BatchEventChannel, func(), error) {
	if err := a.ensureConnection(ctx); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)

	req := &arkv1.GetEventStreamRequest{Topics: topics}

	stream, err := a.svc.GetEventStream(ctx, req)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	eventsCh := make(chan client.BatchEventChannel)

	go func() {
		defer close(eventsCh)

		for {
			resp, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				st, ok := status.FromError(err)
				if ok {
					switch st.Code() {
					case codes.Canceled:
						return
					case codes.Unknown:
						errMsg := st.Message()
						if strings.Contains(errMsg, cloudflare524Error) {
							stream, err = a.svc.GetEventStream(ctx, req)
							if err != nil {
								eventsCh <- client.BatchEventChannel{Err: err}
								return
							}
							continue
						}
					}
				}

				if err := a.ensureConnection(ctx); err != nil {
					eventsCh <- client.BatchEventChannel{Err: err}
					return
				}
				stream, err = a.svc.GetEventStream(ctx, req)
				if err != nil {
					eventsCh <- client.BatchEventChannel{Err: err}
					return
				}
				continue
			}

			ev, err := event{resp}.toBatchEvent()
			if err != nil {
				eventsCh <- client.BatchEventChannel{Err: err}
				return
			}

			eventsCh <- client.BatchEventChannel{Event: ev}
		}
	}()

	closeFn := func() {
		if err := stream.CloseSend(); err != nil {
			logrus.Warnf("failed to close event stream: %s", err)
		}
		cancel()
	}

	return eventsCh, closeFn, nil
}

func (a *grpcClient) SubmitTx(
	ctx context.Context, signedArkTx string, checkpointTxs []string,
) (string, string, []string, error) {
	if err := a.ensureConnection(ctx); err != nil {
		return "", "", nil, err
	}
	req := &arkv1.SubmitTxRequest{
		SignedArkTx:   signedArkTx,
		CheckpointTxs: checkpointTxs,
	}

	resp, err := a.svc.SubmitTx(ctx, req)
	if err != nil {
		return "", "", nil, err
	}

	return resp.GetArkTxid(), resp.GetFinalArkTx(), resp.GetSignedCheckpointTxs(), nil
}

func (a *grpcClient) FinalizeTx(
	ctx context.Context, arkTxid string, finalCheckpointTxs []string,
) error {
	if err := a.ensureConnection(ctx); err != nil {
		return err
	}
	req := &arkv1.FinalizeTxRequest{
		ArkTxid:            arkTxid,
		FinalCheckpointTxs: finalCheckpointTxs,
	}

	_, err := a.svc.FinalizeTx(ctx, req)
	return err
}

func (c *grpcClient) GetTransactionsStream(
	ctx context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	if err := c.ensureConnection(ctx); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)

	req := &arkv1.GetTransactionsStreamRequest{}

	stream, err := c.svc.GetTransactionsStream(ctx, req)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	eventsCh := make(chan client.TransactionEvent)

	go func() {
		defer close(eventsCh)

		for {
			resp, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				st, ok := status.FromError(err)
				if ok {
					switch st.Code() {
					case codes.Canceled:
						return
					case codes.Unknown:
						errMsg := st.Message()
						if strings.Contains(errMsg, cloudflare524Error) {
							stream, err = c.svc.GetTransactionsStream(ctx, req)
							if err != nil {
								eventsCh <- client.TransactionEvent{Err: err}
								return
							}
							continue
						}
					}
				}

				if err := c.ensureConnection(ctx); err != nil {
					eventsCh <- client.TransactionEvent{Err: err}
					return
				}
				stream, err = c.svc.GetTransactionsStream(ctx, req)
				if err != nil {
					eventsCh <- client.TransactionEvent{Err: err}
					return
				}
				continue
			}

			switch tx := resp.Tx.(type) {
			case *arkv1.GetTransactionsStreamResponse_CommitmentTx:
				eventsCh <- client.TransactionEvent{
					CommitmentTx: &client.TxNotification{
						TxData: client.TxData{
							Txid: tx.CommitmentTx.GetTxid(),
							Tx:   tx.CommitmentTx.GetTx(),
						},
						SpentVtxos:     vtxos(tx.CommitmentTx.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.CommitmentTx.SpendableVtxos).toVtxos(),
					},
				}
			case *arkv1.GetTransactionsStreamResponse_ArkTx:
				checkpointTxs := make(map[types.Outpoint]client.TxData)
				for k, v := range tx.ArkTx.CheckpointTxs {
					// nolint
					out, _ := wire.NewOutPointFromString(k)
					checkpointTxs[types.Outpoint{
						Txid: out.Hash.String(),
						VOut: out.Index,
					}] = client.TxData{
						Txid: v.GetTxid(),
						Tx:   v.GetTx(),
					}
				}
				eventsCh <- client.TransactionEvent{
					ArkTx: &client.TxNotification{
						TxData: client.TxData{
							Txid: tx.ArkTx.GetTxid(),
							Tx:   tx.ArkTx.GetTx(),
						},
						SpentVtxos:     vtxos(tx.ArkTx.SpentVtxos).toVtxos(),
						SpendableVtxos: vtxos(tx.ArkTx.SpendableVtxos).toVtxos(),
						CheckpointTxs:  checkpointTxs,
					},
				}
			}
		}
	}()

	closeFn := func() {
		if err := stream.CloseSend(); err != nil {
			logrus.Warnf("failed to close transaction stream: %v", err)
		}
		cancel()
	}

	return eventsCh, closeFn, nil
}

func (c *grpcClient) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	//nolint:all
	c.conn.Close()
}
