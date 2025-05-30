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

	"github.com/arkade-os/sdk/client/rest/service/models"
)

// ArkServicePingReader is a Reader for the ArkServicePing structure.
type ArkServicePingReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServicePingReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServicePingOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServicePingDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServicePingOK creates a ArkServicePingOK with default headers values
func NewArkServicePingOK() *ArkServicePingOK {
	return &ArkServicePingOK{}
}

/*
ArkServicePingOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServicePingOK struct {
	Payload models.V1PingResponse
}

// IsSuccess returns true when this ark service ping o k response has a 2xx status code
func (o *ArkServicePingOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service ping o k response has a 3xx status code
func (o *ArkServicePingOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service ping o k response has a 4xx status code
func (o *ArkServicePingOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service ping o k response has a 5xx status code
func (o *ArkServicePingOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service ping o k response a status code equal to that given
func (o *ArkServicePingOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service ping o k response
func (o *ArkServicePingOK) Code() int {
	return 200
}

func (o *ArkServicePingOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/ping/{requestId}][%d] arkServicePingOK %s", 200, payload)
}

func (o *ArkServicePingOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/ping/{requestId}][%d] arkServicePingOK %s", 200, payload)
}

func (o *ArkServicePingOK) GetPayload() models.V1PingResponse {
	return o.Payload
}

func (o *ArkServicePingOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServicePingDefault creates a ArkServicePingDefault with default headers values
func NewArkServicePingDefault(code int) *ArkServicePingDefault {
	return &ArkServicePingDefault{
		_statusCode: code,
	}
}

/*
ArkServicePingDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServicePingDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service ping default response has a 2xx status code
func (o *ArkServicePingDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service ping default response has a 3xx status code
func (o *ArkServicePingDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service ping default response has a 4xx status code
func (o *ArkServicePingDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service ping default response has a 5xx status code
func (o *ArkServicePingDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service ping default response a status code equal to that given
func (o *ArkServicePingDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service ping default response
func (o *ArkServicePingDefault) Code() int {
	return o._statusCode
}

func (o *ArkServicePingDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/ping/{requestId}][%d] ArkService_Ping default %s", o._statusCode, payload)
}

func (o *ArkServicePingDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/round/ping/{requestId}][%d] ArkService_Ping default %s", o._statusCode, payload)
}

func (o *ArkServicePingDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServicePingDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
