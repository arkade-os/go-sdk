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

	"github.com/arkade-os/go-sdk/client/rest/service/models"
)

// NewArkServiceFinalizeTxParams creates a new ArkServiceFinalizeTxParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArkServiceFinalizeTxParams() *ArkServiceFinalizeTxParams {
	return &ArkServiceFinalizeTxParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceFinalizeTxParamsWithTimeout creates a new ArkServiceFinalizeTxParams object
// with the ability to set a timeout on a request.
func NewArkServiceFinalizeTxParamsWithTimeout(timeout time.Duration) *ArkServiceFinalizeTxParams {
	return &ArkServiceFinalizeTxParams{
		timeout: timeout,
	}
}

// NewArkServiceFinalizeTxParamsWithContext creates a new ArkServiceFinalizeTxParams object
// with the ability to set a context for a request.
func NewArkServiceFinalizeTxParamsWithContext(ctx context.Context) *ArkServiceFinalizeTxParams {
	return &ArkServiceFinalizeTxParams{
		Context: ctx,
	}
}

// NewArkServiceFinalizeTxParamsWithHTTPClient creates a new ArkServiceFinalizeTxParams object
// with the ability to set a custom HTTPClient for a request.
func NewArkServiceFinalizeTxParamsWithHTTPClient(client *http.Client) *ArkServiceFinalizeTxParams {
	return &ArkServiceFinalizeTxParams{
		HTTPClient: client,
	}
}

/*
ArkServiceFinalizeTxParams contains all the parameters to send to the API endpoint

	for the ark service finalize tx operation.

	Typically these are written to a http.Request.
*/
type ArkServiceFinalizeTxParams struct {

	// Body.
	Body *models.V1FinalizeTxRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ark service finalize tx params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceFinalizeTxParams) WithDefaults() *ArkServiceFinalizeTxParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ark service finalize tx params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceFinalizeTxParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) WithTimeout(timeout time.Duration) *ArkServiceFinalizeTxParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) WithContext(ctx context.Context) *ArkServiceFinalizeTxParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) WithHTTPClient(client *http.Client) *ArkServiceFinalizeTxParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) WithBody(body *models.V1FinalizeTxRequest) *ArkServiceFinalizeTxParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the ark service finalize tx params
func (o *ArkServiceFinalizeTxParams) SetBody(body *models.V1FinalizeTxRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceFinalizeTxParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
