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

// ArkServiceSubmitTreeNoncesReader is a Reader for the ArkServiceSubmitTreeNonces structure.
type ArkServiceSubmitTreeNoncesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceSubmitTreeNoncesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceSubmitTreeNoncesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceSubmitTreeNoncesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceSubmitTreeNoncesOK creates a ArkServiceSubmitTreeNoncesOK with default headers values
func NewArkServiceSubmitTreeNoncesOK() *ArkServiceSubmitTreeNoncesOK {
	return &ArkServiceSubmitTreeNoncesOK{}
}

/*
ArkServiceSubmitTreeNoncesOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceSubmitTreeNoncesOK struct {
	Payload models.V1SubmitTreeNoncesResponse
}

// IsSuccess returns true when this ark service submit tree nonces o k response has a 2xx status code
func (o *ArkServiceSubmitTreeNoncesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service submit tree nonces o k response has a 3xx status code
func (o *ArkServiceSubmitTreeNoncesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service submit tree nonces o k response has a 4xx status code
func (o *ArkServiceSubmitTreeNoncesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service submit tree nonces o k response has a 5xx status code
func (o *ArkServiceSubmitTreeNoncesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service submit tree nonces o k response a status code equal to that given
func (o *ArkServiceSubmitTreeNoncesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service submit tree nonces o k response
func (o *ArkServiceSubmitTreeNoncesOK) Code() int {
	return 200
}

func (o *ArkServiceSubmitTreeNoncesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/tree/submitNonces][%d] arkServiceSubmitTreeNoncesOK %s", 200, payload)
}

func (o *ArkServiceSubmitTreeNoncesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/tree/submitNonces][%d] arkServiceSubmitTreeNoncesOK %s", 200, payload)
}

func (o *ArkServiceSubmitTreeNoncesOK) GetPayload() models.V1SubmitTreeNoncesResponse {
	return o.Payload
}

func (o *ArkServiceSubmitTreeNoncesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceSubmitTreeNoncesDefault creates a ArkServiceSubmitTreeNoncesDefault with default headers values
func NewArkServiceSubmitTreeNoncesDefault(code int) *ArkServiceSubmitTreeNoncesDefault {
	return &ArkServiceSubmitTreeNoncesDefault{
		_statusCode: code,
	}
}

/*
ArkServiceSubmitTreeNoncesDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceSubmitTreeNoncesDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service submit tree nonces default response has a 2xx status code
func (o *ArkServiceSubmitTreeNoncesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service submit tree nonces default response has a 3xx status code
func (o *ArkServiceSubmitTreeNoncesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service submit tree nonces default response has a 4xx status code
func (o *ArkServiceSubmitTreeNoncesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service submit tree nonces default response has a 5xx status code
func (o *ArkServiceSubmitTreeNoncesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service submit tree nonces default response a status code equal to that given
func (o *ArkServiceSubmitTreeNoncesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service submit tree nonces default response
func (o *ArkServiceSubmitTreeNoncesDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceSubmitTreeNoncesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/tree/submitNonces][%d] ArkService_SubmitTreeNonces default %s", o._statusCode, payload)
}

func (o *ArkServiceSubmitTreeNoncesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1/batch/tree/submitNonces][%d] ArkService_SubmitTreeNonces default %s", o._statusCode, payload)
}

func (o *ArkServiceSubmitTreeNoncesDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceSubmitTreeNoncesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
