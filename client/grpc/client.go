package grpcclient

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	arkv1 "github.com/arkade-os/go-sdk/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const cloudflare524Error = "524"

type grpcClient struct {
	conn             *grpc.ClientConn
	connMu           sync.RWMutex
	monitoringCancel context.CancelFunc
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

	option := grpc.WithTransportCredentials(creds)

	conn, err := grpc.NewClient(serverUrl, option)
	if err != nil {
		return nil, err
	}

	monitoringCtx, monitoringCancel := context.WithCancel(context.Background())
	client := &grpcClient{conn, sync.RWMutex{}, monitoringCancel}

	go utils.MonitorGrpcConn(monitoringCtx, conn, func(ctx context.Context) error {
		client.connMu.Lock()
		// nolint:errcheck
		client.conn.Close()
		client.connMu.Unlock()

		// wait for the arkd server to be ready by pinging it every 5 seconds
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		isUnlocked := false
		for !isUnlocked {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				pingConn, err := grpc.NewClient(serverUrl, option)
				if err != nil {
					continue
				}
				// we use GetInfo to check if the server is ready
				// we know that if this RPC returns an error, the server is not unlocked yet
				_, err = arkv1.NewArkServiceClient(pingConn).GetInfo(ctx, &arkv1.GetInfoRequest{})
				if err != nil {
					// nolint:errcheck
					pingConn.Close()
					continue
				}

				// nolint:errcheck
				pingConn.Close()
				isUnlocked = true
			}
		}

		client.connMu.Lock()
		defer client.connMu.Unlock()
		client.conn, err = grpc.NewClient(serverUrl, option)
		if err != nil {
			return err
		}
		return nil
	})

	return client, nil
}

func (a *grpcClient) svc() arkv1.ArkServiceClient {
	a.connMu.RLock()
	defer a.connMu.RUnlock()

	return arkv1.NewArkServiceClient(a.conn)
}

func (a *grpcClient) GetInfo(ctx context.Context) (*client.Info, error) {
	req := &arkv1.GetInfoRequest{}
	resp, err := a.svc().GetInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	fees, err := parseFees(resp.GetFees())
	if err != nil {
		return nil, err
	}
	var (
		ssStartTime, ssEndTime, ssPeriod, ssDuration int64
		ssFees                                       types.FeeInfo
	)
	if ss := resp.GetScheduledSession(); ss != nil {
		ssStartTime = ss.GetNextStartTime()
		ssEndTime = ss.GetNextEndTime()
		ssPeriod = ss.GetPeriod()
		ssDuration = ss.GetDuration()
		ssFees, err = parseFees(ss.GetFees())
		if err != nil {
			return nil, err
		}
	}
	var deprecatedSigners []client.DeprecatedSigner
	for _, s := range resp.GetDeprecatedSigners() {
		if s == nil {
			continue
		}
		deprecatedSigners = append(deprecatedSigners, client.DeprecatedSigner{
			PubKey:     s.GetPubkey(),
			CutoffDate: s.GetCutoffDate(),
		})
	}
	return &client.Info{
		SignerPubKey:              resp.GetSignerPubkey(),
		ForfeitPubKey:             resp.GetForfeitPubkey(),
		UnilateralExitDelay:       resp.GetUnilateralExitDelay(),
		SessionDuration:           resp.GetSessionDuration(),
		Network:                   resp.GetNetwork(),
		Dust:                      uint64(resp.GetDust()),
		BoardingExitDelay:         resp.GetBoardingExitDelay(),
		ForfeitAddress:            resp.GetForfeitAddress(),
		Version:                   resp.GetVersion(),
		ScheduledSessionStartTime: ssStartTime,
		ScheduledSessionEndTime:   ssEndTime,
		ScheduledSessionPeriod:    ssPeriod,
		ScheduledSessionDuration:  ssDuration,
		ScheduledSessionFees:      ssFees,
		UtxoMinAmount:             resp.GetUtxoMinAmount(),
		UtxoMaxAmount:             resp.GetUtxoMaxAmount(),
		VtxoMinAmount:             resp.GetVtxoMinAmount(),
		VtxoMaxAmount:             resp.GetVtxoMaxAmount(),
		CheckpointTapscript:       resp.GetCheckpointTapscript(),
		DeprecatedSignerPubKeys:   deprecatedSigners,
		Fees:                      fees,
		ServiceStatus:             resp.GetServiceStatus(),
		Digest:                    resp.GetDigest(),
	}, nil
}

func (a *grpcClient) RegisterIntent(
	ctx context.Context,
	proof, message string,
) (string, error) {
	req := &arkv1.RegisterIntentRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}

	resp, err := a.svc().RegisterIntent(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.GetIntentId(), nil
}

func (a *grpcClient) DeleteIntent(ctx context.Context, proof, message string) error {
	req := &arkv1.DeleteIntentRequest{
		Intent: &arkv1.Intent{
			Message: message,
			Proof:   proof,
		},
	}
	_, err := a.svc().DeleteIntent(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (a *grpcClient) ConfirmRegistration(ctx context.Context, intentID string) error {
	req := &arkv1.ConfirmRegistrationRequest{
		IntentId: intentID,
	}
	_, err := a.svc().ConfirmRegistration(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (a *grpcClient) SubmitTreeNonces(
	ctx context.Context, batchId, cosignerPubkey string, nonces tree.TreeNonces,
) error {
	req := &arkv1.SubmitTreeNoncesRequest{
		BatchId:    batchId,
		Pubkey:     cosignerPubkey,
		TreeNonces: nonces.ToMap(),
	}

	if _, err := a.svc().SubmitTreeNonces(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitTreeSignatures(
	ctx context.Context, batchId, cosignerPubkey string, signatures tree.TreePartialSigs,
) error {
	sigs, err := signatures.ToMap()
	if err != nil {
		return err
	}

	req := &arkv1.SubmitTreeSignaturesRequest{
		BatchId:        batchId,
		Pubkey:         cosignerPubkey,
		TreeSignatures: sigs,
	}

	if _, err := a.svc().SubmitTreeSignatures(ctx, req); err != nil {
		return err
	}

	return nil
}

func (a *grpcClient) SubmitSignedForfeitTxs(
	ctx context.Context, signedForfeitTxs []string, signedCommitmentTx string,
) error {
	req := &arkv1.SubmitSignedForfeitTxsRequest{
		SignedForfeitTxs:   signedForfeitTxs,
		SignedCommitmentTx: signedCommitmentTx,
	}

	_, err := a.svc().SubmitSignedForfeitTxs(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (a *grpcClient) GetEventStream(
	ctx context.Context,
	topics []string,
) (<-chan client.BatchEventChannel, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	req := &arkv1.GetEventStreamRequest{Topics: topics}

	stream, err := a.svc().GetEventStream(ctx, req)
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
				if err == io.EOF {
					eventsCh <- client.BatchEventChannel{Err: client.ErrConnectionClosedByServer}
					return
				}
				st, ok := status.FromError(err)
				if ok {
					switch st.Code() {
					case codes.Canceled:
						return
					case codes.Unknown:
						errMsg := st.Message()
						// Check if it's a 524 error during stream reading
						if strings.Contains(errMsg, cloudflare524Error) {
							stream, err = a.svc().GetEventStream(ctx, req)
							if err != nil {
								eventsCh <- client.BatchEventChannel{Err: err}
								return
							}

							continue
						}
					}
				}

				eventsCh <- client.BatchEventChannel{Err: err}
				return
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
	req := &arkv1.SubmitTxRequest{
		SignedArkTx:   signedArkTx,
		CheckpointTxs: checkpointTxs,
	}

	resp, err := a.svc().SubmitTx(ctx, req)
	if err != nil {
		return "", "", nil, err
	}

	return resp.GetArkTxid(), resp.GetFinalArkTx(), resp.GetSignedCheckpointTxs(), nil
}

func (a *grpcClient) FinalizeTx(
	ctx context.Context, arkTxid string, finalCheckpointTxs []string,
) error {
	req := &arkv1.FinalizeTxRequest{
		ArkTxid:            arkTxid,
		FinalCheckpointTxs: finalCheckpointTxs,
	}

	_, err := a.svc().FinalizeTx(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (c *grpcClient) GetTransactionsStream(
	ctx context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	req := &arkv1.GetTransactionsStreamRequest{}

	stream, err := c.svc().GetTransactionsStream(ctx, req)
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
				if err == io.EOF {
					eventsCh <- client.TransactionEvent{Err: client.ErrConnectionClosedByServer}
					return
				}
				st, ok := status.FromError(err)
				if ok {
					switch st.Code() {
					case codes.Canceled:
						return
					case codes.Unknown:
						errMsg := st.Message()
						// Check if it's a 524 error during stream reading
						if strings.Contains(errMsg, cloudflare524Error) {
							stream, err = c.svc().GetTransactionsStream(ctx, req)
							if err != nil {
								eventsCh <- client.TransactionEvent{Err: err}
								return
							}

							continue
						}
					}
				}
				eventsCh <- client.TransactionEvent{Err: err}
				return
			}

			switch tx := resp.GetData().(type) {
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
	c.monitoringCancel()
	c.connMu.Lock()
	defer c.connMu.Unlock()
	// nolint:errcheck
	c.conn.Close()
}

func parseFees(fees *arkv1.FeeInfo) (types.FeeInfo, error) {
	var (
		err                               error
		txFeeRate                         float64
		onchainInputFee, onchainOutputFee uint64
	)
	if fees.GetTxFeeRate() != "" {
		txFeeRate, err = strconv.ParseFloat(fees.GetTxFeeRate(), 64)
		if err != nil {
			return types.FeeInfo{}, err
		}
	}
	intentFees := fees.GetIntentFee()
	if intentFees.GetOnchainInput() != "" {
		onchainInputFee, err = strconv.ParseUint(intentFees.GetOnchainInput(), 10, 64)
		if err != nil {
			return types.FeeInfo{}, err
		}
	}
	if intentFees.GetOnchainOutput() != "" {
		onchainOutputFee, err = strconv.ParseUint(intentFees.GetOnchainOutput(), 10, 64)
		if err != nil {
			return types.FeeInfo{}, err
		}
	}
	return types.FeeInfo{
		TxFeeRate: txFeeRate,
		IntentFees: types.IntentFeeInfo{
			OffchainInput:  fees.GetIntentFee().GetOffchainInput(),
			OffchainOutput: fees.GetIntentFee().GetOffchainOutput(),
			OnchainInput:   onchainInputFee,
			OnchainOutput:  onchainOutputFee,
		},
	}, nil
}
