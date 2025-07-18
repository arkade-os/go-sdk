// Code generated by go-swagger; DO NOT EDIT.

package indexer_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/arkade-os/go-sdk/indexer/rest/service/models"
)

// IndexerServiceGetSubscriptionReader is a Reader for the IndexerServiceGetSubscription structure.
type IndexerServiceGetSubscriptionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IndexerServiceGetSubscriptionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIndexerServiceGetSubscriptionOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewIndexerServiceGetSubscriptionDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewIndexerServiceGetSubscriptionOK creates a IndexerServiceGetSubscriptionOK with default headers values
func NewIndexerServiceGetSubscriptionOK() *IndexerServiceGetSubscriptionOK {
	return &IndexerServiceGetSubscriptionOK{}
}

/*
IndexerServiceGetSubscriptionOK describes a response with status code 200, with default header values.

A successful response.(streaming responses)
*/
type IndexerServiceGetSubscriptionOK struct {
	Payload *IndexerServiceGetSubscriptionOKBody
}

// IsSuccess returns true when this indexer service get subscription o k response has a 2xx status code
func (o *IndexerServiceGetSubscriptionOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this indexer service get subscription o k response has a 3xx status code
func (o *IndexerServiceGetSubscriptionOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this indexer service get subscription o k response has a 4xx status code
func (o *IndexerServiceGetSubscriptionOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this indexer service get subscription o k response has a 5xx status code
func (o *IndexerServiceGetSubscriptionOK) IsServerError() bool {
	return false
}

// IsCode returns true when this indexer service get subscription o k response a status code equal to that given
func (o *IndexerServiceGetSubscriptionOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the indexer service get subscription o k response
func (o *IndexerServiceGetSubscriptionOK) Code() int {
	return 200
}

func (o *IndexerServiceGetSubscriptionOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/script/subscription/{subscriptionId}][%d] indexerServiceGetSubscriptionOK %s", 200, payload)
}

func (o *IndexerServiceGetSubscriptionOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/script/subscription/{subscriptionId}][%d] indexerServiceGetSubscriptionOK %s", 200, payload)
}

func (o *IndexerServiceGetSubscriptionOK) GetPayload() *IndexerServiceGetSubscriptionOKBody {
	return o.Payload
}

func (o *IndexerServiceGetSubscriptionOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(IndexerServiceGetSubscriptionOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIndexerServiceGetSubscriptionDefault creates a IndexerServiceGetSubscriptionDefault with default headers values
func NewIndexerServiceGetSubscriptionDefault(code int) *IndexerServiceGetSubscriptionDefault {
	return &IndexerServiceGetSubscriptionDefault{
		_statusCode: code,
	}
}

/*
IndexerServiceGetSubscriptionDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type IndexerServiceGetSubscriptionDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this indexer service get subscription default response has a 2xx status code
func (o *IndexerServiceGetSubscriptionDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this indexer service get subscription default response has a 3xx status code
func (o *IndexerServiceGetSubscriptionDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this indexer service get subscription default response has a 4xx status code
func (o *IndexerServiceGetSubscriptionDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this indexer service get subscription default response has a 5xx status code
func (o *IndexerServiceGetSubscriptionDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this indexer service get subscription default response a status code equal to that given
func (o *IndexerServiceGetSubscriptionDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the indexer service get subscription default response
func (o *IndexerServiceGetSubscriptionDefault) Code() int {
	return o._statusCode
}

func (o *IndexerServiceGetSubscriptionDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/script/subscription/{subscriptionId}][%d] IndexerService_GetSubscription default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetSubscriptionDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1/script/subscription/{subscriptionId}][%d] IndexerService_GetSubscription default %s", o._statusCode, payload)
}

func (o *IndexerServiceGetSubscriptionDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *IndexerServiceGetSubscriptionDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
IndexerServiceGetSubscriptionOKBody Stream result of v1GetSubscriptionResponse
swagger:model IndexerServiceGetSubscriptionOKBody
*/
type IndexerServiceGetSubscriptionOKBody struct {

	// error
	Error *models.RPCStatus `json:"error,omitempty"`

	// result
	Result *models.V1GetSubscriptionResponse `json:"result,omitempty"`
}

// Validate validates this indexer service get subscription o k body
func (o *IndexerServiceGetSubscriptionOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateError(formats); err != nil {
		res = append(res, err)
	}

	if err := o.validateResult(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *IndexerServiceGetSubscriptionOKBody) validateError(formats strfmt.Registry) error {
	if swag.IsZero(o.Error) { // not required
		return nil
	}

	if o.Error != nil {
		if err := o.Error.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("indexerServiceGetSubscriptionOK" + "." + "error")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("indexerServiceGetSubscriptionOK" + "." + "error")
			}
			return err
		}
	}

	return nil
}

func (o *IndexerServiceGetSubscriptionOKBody) validateResult(formats strfmt.Registry) error {
	if swag.IsZero(o.Result) { // not required
		return nil
	}

	if o.Result != nil {
		if err := o.Result.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("indexerServiceGetSubscriptionOK" + "." + "result")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("indexerServiceGetSubscriptionOK" + "." + "result")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this indexer service get subscription o k body based on the context it is used
func (o *IndexerServiceGetSubscriptionOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := o.contextValidateError(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := o.contextValidateResult(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *IndexerServiceGetSubscriptionOKBody) contextValidateError(ctx context.Context, formats strfmt.Registry) error {

	if o.Error != nil {

		if swag.IsZero(o.Error) { // not required
			return nil
		}

		if err := o.Error.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("indexerServiceGetSubscriptionOK" + "." + "error")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("indexerServiceGetSubscriptionOK" + "." + "error")
			}
			return err
		}
	}

	return nil
}

func (o *IndexerServiceGetSubscriptionOKBody) contextValidateResult(ctx context.Context, formats strfmt.Registry) error {

	if o.Result != nil {

		if swag.IsZero(o.Result) { // not required
			return nil
		}

		if err := o.Result.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("indexerServiceGetSubscriptionOK" + "." + "result")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("indexerServiceGetSubscriptionOK" + "." + "result")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *IndexerServiceGetSubscriptionOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *IndexerServiceGetSubscriptionOKBody) UnmarshalBinary(b []byte) error {
	var res IndexerServiceGetSubscriptionOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
