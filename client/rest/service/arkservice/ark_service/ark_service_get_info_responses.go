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

// ArkServiceGetInfoReader is a Reader for the ArkServiceGetInfo structure.
type ArkServiceGetInfoReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ArkServiceGetInfoReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewArkServiceGetInfoOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewArkServiceGetInfoDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewArkServiceGetInfoOK creates a ArkServiceGetInfoOK with default headers values
func NewArkServiceGetInfoOK() *ArkServiceGetInfoOK {
	return &ArkServiceGetInfoOK{}
}

/*
ArkServiceGetInfoOK describes a response with status code 200, with default header values.

A successful response.
*/
type ArkServiceGetInfoOK struct {
	Payload *models.V1GetInfoResponse
}

// IsSuccess returns true when this ark service get info o k response has a 2xx status code
func (o *ArkServiceGetInfoOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this ark service get info o k response has a 3xx status code
func (o *ArkServiceGetInfoOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this ark service get info o k response has a 4xx status code
func (o *ArkServiceGetInfoOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this ark service get info o k response has a 5xx status code
func (o *ArkServiceGetInfoOK) IsServerError() bool {
	return false
}

// IsCode returns true when this ark service get info o k response a status code equal to that given
func (o *ArkServiceGetInfoOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the ark service get info o k response
func (o *ArkServiceGetInfoOK) Code() int {
	return 200
}

func (o *ArkServiceGetInfoOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/info][%d] arkServiceGetInfoOK %s", 200, payload)
}

func (o *ArkServiceGetInfoOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/info][%d] arkServiceGetInfoOK %s", 200, payload)
}

func (o *ArkServiceGetInfoOK) GetPayload() *models.V1GetInfoResponse {
	return o.Payload
}

func (o *ArkServiceGetInfoOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1GetInfoResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewArkServiceGetInfoDefault creates a ArkServiceGetInfoDefault with default headers values
func NewArkServiceGetInfoDefault(code int) *ArkServiceGetInfoDefault {
	return &ArkServiceGetInfoDefault{
		_statusCode: code,
	}
}

/*
ArkServiceGetInfoDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ArkServiceGetInfoDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this ark service get info default response has a 2xx status code
func (o *ArkServiceGetInfoDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this ark service get info default response has a 3xx status code
func (o *ArkServiceGetInfoDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this ark service get info default response has a 4xx status code
func (o *ArkServiceGetInfoDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this ark service get info default response has a 5xx status code
func (o *ArkServiceGetInfoDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this ark service get info default response a status code equal to that given
func (o *ArkServiceGetInfoDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the ark service get info default response
func (o *ArkServiceGetInfoDefault) Code() int {
	return o._statusCode
}

func (o *ArkServiceGetInfoDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/info][%d] ArkService_GetInfo default %s", o._statusCode, payload)
}

func (o *ArkServiceGetInfoDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/info][%d] ArkService_GetInfo default %s", o._statusCode, payload)
}

func (o *ArkServiceGetInfoDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ArkServiceGetInfoDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
