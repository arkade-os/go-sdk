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

// IndexerServiceGetForfeitTxsReader is a Reader for the IndexerServiceGetForfeitTxs structure.
type IndexerServiceGetForfeitTxsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IndexerServiceGetForfeitTxsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIndexerServiceGetForfeitTxsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewIndexerServiceGetForfeitTxsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewIndexerServiceGetForfeitTxsOK creates a IndexerServiceGetForfeitTxsOK with default headers values
func NewIndexerServiceGetForfeitTxsOK() *IndexerServiceGetForfeitTxsOK {
	return &IndexerServiceGetForfeitTxsOK{}
}

/*
IndexerServiceGetForfeitTxsOK describes a response with status code 200, with default header values.

A successful response.
*/
type IndexerServiceGetForfeitTxsOK struct {
	Payload *models.V1GetForfeitTxsResponse
}

// IsSuccess returns true when this indexer service get forfeit txs o k response has a 2xx status code
func (o *IndexerServiceGetForfeitTxsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this indexer service get forfeit txs o k response has a 3xx status code
func (o *IndexerServiceGetForfeitTxsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indexer service get forfeit txs o k response has a 4xx status code
func (o *IndexerServiceGetForfeitTxsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this indexer service get forfeit txs o k response has a 5xx status code
func (o *IndexerServiceGetForfeitTxsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this indexer service get forfeit txs o k response a status code equal to that given
func (o *IndexerServiceGetForfeitTxsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the indexer service get forfeit txs o k response
func (o *IndexerServiceGetForfeitTxsOK) Code() int {
	return 200
}

func (o *IndexerServiceGetForfeitTxsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/forfeitTxs][%d] indexerServiceGetForfeitTxsOK %s", 200, payload)
}

func (o *IndexerServiceGetForfeitTxsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/forfeitTxs][%d] indexerServiceGetForfeitTxsOK %s", 200, payload)
}

func (o *IndexerServiceGetForfeitTxsOK) GetPayload() *models.V1GetForfeitTxsResponse {
	return o.Payload
}

func (o *IndexerServiceGetForfeitTxsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1GetForfeitTxsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIndexerServiceGetForfeitTxsDefault creates a IndexerServiceGetForfeitTxsDefault with default headers values
func NewIndexerServiceGetForfeitTxsDefault(code int) *IndexerServiceGetForfeitTxsDefault {
	return &IndexerServiceGetForfeitTxsDefault{
		_statusCode: code,
	}
}

/*
IndexerServiceGetForfeitTxsDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type IndexerServiceGetForfeitTxsDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this indexer service get forfeit txs default response has a 2xx status code
func (o *IndexerServiceGetForfeitTxsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this indexer service get forfeit txs default response has a 3xx status code
func (o *IndexerServiceGetForfeitTxsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this indexer service get forfeit txs default response has a 4xx status code
func (o *IndexerServiceGetForfeitTxsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this indexer service get forfeit txs default response has a 5xx status code
func (o *IndexerServiceGetForfeitTxsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this indexer service get forfeit txs default response a status code equal to that given
func (o *IndexerServiceGetForfeitTxsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the indexer service get forfeit txs default response
func (o *IndexerServiceGetForfeitTxsDefault) Code() int {
	return o._statusCode
}

func (o *IndexerServiceGetForfeitTxsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/forfeitTxs][%d] IndexerService_GetForfeitTxs default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetForfeitTxsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/commitmentTx/{txid}/forfeitTxs][%d] IndexerService_GetForfeitTxs default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetForfeitTxsDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *IndexerServiceGetForfeitTxsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
