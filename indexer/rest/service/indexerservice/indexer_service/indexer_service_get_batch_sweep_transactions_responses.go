// Code generated by go-swagger; DO NOT EDIT.

package indexer_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/arkade-os/go-sdk/indexer/rest/service/models"
)

// IndexerServiceGetBatchSweepTransactionsReader is a Reader for the IndexerServiceGetBatchSweepTransactions structure.
type IndexerServiceGetBatchSweepTransactionsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IndexerServiceGetBatchSweepTransactionsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIndexerServiceGetBatchSweepTransactionsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewIndexerServiceGetBatchSweepTransactionsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewIndexerServiceGetBatchSweepTransactionsOK creates a IndexerServiceGetBatchSweepTransactionsOK with default headers values
func NewIndexerServiceGetBatchSweepTransactionsOK() *IndexerServiceGetBatchSweepTransactionsOK {
	return &IndexerServiceGetBatchSweepTransactionsOK{}
}

/*
IndexerServiceGetBatchSweepTransactionsOK describes a response with status code 200, with default header values.

A successful response.
*/
type IndexerServiceGetBatchSweepTransactionsOK struct {
	Payload *models.V1GetBatchSweepTransactionsResponse
}

// IsSuccess returns true when this indexer service get batch sweep transactions o k response has a 2xx status code
func (o *IndexerServiceGetBatchSweepTransactionsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this indexer service get batch sweep transactions o k response has a 3xx status code
func (o *IndexerServiceGetBatchSweepTransactionsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indexer service get batch sweep transactions o k response has a 4xx status code
func (o *IndexerServiceGetBatchSweepTransactionsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this indexer service get batch sweep transactions o k response has a 5xx status code
func (o *IndexerServiceGetBatchSweepTransactionsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this indexer service get batch sweep transactions o k response a status code equal to that given
func (o *IndexerServiceGetBatchSweepTransactionsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the indexer service get batch sweep transactions o k response
func (o *IndexerServiceGetBatchSweepTransactionsOK) Code() int {
	return 200
}

func (o *IndexerServiceGetBatchSweepTransactionsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/batch/{batchOutpoint.txid}/{batchOutpoint.vout}/sweepTxs][%d] indexerServiceGetBatchSweepTransactionsOK %s", 200, payload)
}

func (o *IndexerServiceGetBatchSweepTransactionsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/batch/{batchOutpoint.txid}/{batchOutpoint.vout}/sweepTxs][%d] indexerServiceGetBatchSweepTransactionsOK %s", 200, payload)
}

func (o *IndexerServiceGetBatchSweepTransactionsOK) GetPayload() *models.V1GetBatchSweepTransactionsResponse {
	return o.Payload
}

func (o *IndexerServiceGetBatchSweepTransactionsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1GetBatchSweepTransactionsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIndexerServiceGetBatchSweepTransactionsDefault creates a IndexerServiceGetBatchSweepTransactionsDefault with default headers values
func NewIndexerServiceGetBatchSweepTransactionsDefault(code int) *IndexerServiceGetBatchSweepTransactionsDefault {
	return &IndexerServiceGetBatchSweepTransactionsDefault{
		_statusCode: code,
	}
}

/*
IndexerServiceGetBatchSweepTransactionsDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type IndexerServiceGetBatchSweepTransactionsDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this indexer service get batch sweep transactions default response has a 2xx status code
func (o *IndexerServiceGetBatchSweepTransactionsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this indexer service get batch sweep transactions default response has a 3xx status code
func (o *IndexerServiceGetBatchSweepTransactionsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this indexer service get batch sweep transactions default response has a 4xx status code
func (o *IndexerServiceGetBatchSweepTransactionsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this indexer service get batch sweep transactions default response has a 5xx status code
func (o *IndexerServiceGetBatchSweepTransactionsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this indexer service get batch sweep transactions default response a status code equal to that given
func (o *IndexerServiceGetBatchSweepTransactionsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the indexer service get batch sweep transactions default response
func (o *IndexerServiceGetBatchSweepTransactionsDefault) Code() int {
	return o._statusCode
}

func (o *IndexerServiceGetBatchSweepTransactionsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/batch/{batchOutpoint.txid}/{batchOutpoint.vout}/sweepTxs][%d] IndexerService_GetBatchSweepTransactions default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetBatchSweepTransactionsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/batch/{batchOutpoint.txid}/{batchOutpoint.vout}/sweepTxs][%d] IndexerService_GetBatchSweepTransactions default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetBatchSweepTransactionsDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *IndexerServiceGetBatchSweepTransactionsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
