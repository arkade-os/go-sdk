// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/arkade-os/go-sdk/client/rest/service/models"
)

// ArkServiceSubmitSignedForfeitTxsReader is a Reader for the ArkServiceSubmitSignedForfeitTxs structure.
type ArkServiceSubmitSignedForfeitTxsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceSubmitSignedForfeitTxsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceSubmitSignedForfeitTxsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceSubmitSignedForfeitTxsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceSubmitSignedForfeitTxsOK creates a ArkServiceSubmitSignedForfeitTxsOK with default headers values
func NewArkServiceSubmitSignedForfeitTxsOK() *ArkServiceSubmitSignedForfeitTxsOK {
	return &ArkServiceSubmitSignedForfeitTxsOK{}
}

/*
ArkServiceSubmitSignedForfeitTxsOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceSubmitSignedForfeitTxsOK struct {
	Payload models.V1SubmitSignedForfeitTxsResponse
}

// IsSuccess returns true when this ark service submit signed forfeit txs o k response has a 2xx status code
func (o *ArkServiceSubmitSignedForfeitTxsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service submit signed forfeit txs o k response has a 3xx status code
func (o *ArkServiceSubmitSignedForfeitTxsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service submit signed forfeit txs o k response has a 4xx status code
func (o *ArkServiceSubmitSignedForfeitTxsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service submit signed forfeit txs o k response has a 5xx status code
func (o *ArkServiceSubmitSignedForfeitTxsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service submit signed forfeit txs o k response a status code equal to that given
func (o *ArkServiceSubmitSignedForfeitTxsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service submit signed forfeit txs o k response
func (o *ArkServiceSubmitSignedForfeitTxsOK) Code() int {
	return 200
}

func (o *ArkServiceSubmitSignedForfeitTxsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/submitForfeitTxs][%d] arkServiceSubmitSignedForfeitTxsOK %s", 200, payload)
}

func (o *ArkServiceSubmitSignedForfeitTxsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/submitForfeitTxs][%d] arkServiceSubmitSignedForfeitTxsOK %s", 200, payload)
}

func (o *ArkServiceSubmitSignedForfeitTxsOK) GetPayload() models.V1SubmitSignedForfeitTxsResponse {
	return o.Payload
}

func (o *ArkServiceSubmitSignedForfeitTxsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceSubmitSignedForfeitTxsDefault creates a ArkServiceSubmitSignedForfeitTxsDefault with default headers values
func NewArkServiceSubmitSignedForfeitTxsDefault(code int) *ArkServiceSubmitSignedForfeitTxsDefault {
	return &ArkServiceSubmitSignedForfeitTxsDefault{
		_statusCode: code,
	}
}

/*
ArkServiceSubmitSignedForfeitTxsDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceSubmitSignedForfeitTxsDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service submit signed forfeit txs default response has a 2xx status code
func (o *ArkServiceSubmitSignedForfeitTxsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service submit signed forfeit txs default response has a 3xx status code
func (o *ArkServiceSubmitSignedForfeitTxsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service submit signed forfeit txs default response has a 4xx status code
func (o *ArkServiceSubmitSignedForfeitTxsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service submit signed forfeit txs default response has a 5xx status code
func (o *ArkServiceSubmitSignedForfeitTxsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service submit signed forfeit txs default response a status code equal to that given
func (o *ArkServiceSubmitSignedForfeitTxsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service submit signed forfeit txs default response
func (o *ArkServiceSubmitSignedForfeitTxsDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceSubmitSignedForfeitTxsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/submitForfeitTxs][%d] ArkService_SubmitSignedForfeitTxs default %s", o._statusCode, payload)
}

func (o *ArkServiceSubmitSignedForfeitTxsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/submitForfeitTxs][%d] ArkService_SubmitSignedForfeitTxs default %s", o._statusCode, payload)
}

func (o *ArkServiceSubmitSignedForfeitTxsDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceSubmitSignedForfeitTxsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
