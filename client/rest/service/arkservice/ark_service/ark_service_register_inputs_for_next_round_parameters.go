// Code generated by go-swagger; DO NOT EDIT.

package ark_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/arkade-os/sdk/client/rest/service/models"
)

// NewArkServiceRegisterInputsForNextRoundParams creates a new ArkServiceRegisterInputsForNextRoundParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArkServiceRegisterInputsForNextRoundParams() *ArkServiceRegisterInputsForNextRoundParams {
	return &ArkServiceRegisterInputsForNextRoundParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceRegisterInputsForNextRoundParamsWithTimeout creates a new ArkServiceRegisterInputsForNextRoundParams object
// with the ability to set a timeout on a request.
func NewArkServiceRegisterInputsForNextRoundParamsWithTimeout(timeout time.Duration) *ArkServiceRegisterInputsForNextRoundParams {
	return &ArkServiceRegisterInputsForNextRoundParams{
		timeout: timeout,
	}
}

// NewArkServiceRegisterInputsForNextRoundParamsWithContext creates a new ArkServiceRegisterInputsForNextRoundParams object
// with the ability to set a context for a request.
func NewArkServiceRegisterInputsForNextRoundParamsWithContext(ctx context.Context) *ArkServiceRegisterInputsForNextRoundParams {
	return &ArkServiceRegisterInputsForNextRoundParams{
		Context: ctx,
	}
}

// NewArkServiceRegisterInputsForNextRoundParamsWithHTTPClient creates a new ArkServiceRegisterInputsForNextRoundParams object
// with the ability to set a custom HTTPClient for a request.
func NewArkServiceRegisterInputsForNextRoundParamsWithHTTPClient(client *http.Client) *ArkServiceRegisterInputsForNextRoundParams {
	return &ArkServiceRegisterInputsForNextRoundParams{
		HTTPClient: client,
	}
}

/*
ArkServiceRegisterInputsForNextRoundParams contains all the parameters to send to the API endpoint

	for the ark service register inputs for next round operation.

	Typically these are written to a http.Request.
*/
type ArkServiceRegisterInputsForNextRoundParams struct {

	// Body.
	Body *models.V1RegisterInputsForNextRoundRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ark service register inputs for next round params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceRegisterInputsForNextRoundParams) WithDefaults() *ArkServiceRegisterInputsForNextRoundParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ark service register inputs for next round params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceRegisterInputsForNextRoundParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) WithTimeout(timeout time.Duration) *ArkServiceRegisterInputsForNextRoundParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) WithContext(ctx context.Context) *ArkServiceRegisterInputsForNextRoundParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) WithHTTPClient(client *http.Client) *ArkServiceRegisterInputsForNextRoundParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) WithBody(body *models.V1RegisterInputsForNextRoundRequest) *ArkServiceRegisterInputsForNextRoundParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the ark service register inputs for next round params
func (o *ArkServiceRegisterInputsForNextRoundParams) SetBody(body *models.V1RegisterInputsForNextRoundRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceRegisterInputsForNextRoundParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
