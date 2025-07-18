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

// NewArkServiceConfirmRegistrationParams creates a new ArkServiceConfirmRegistrationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewArkServiceConfirmRegistrationParams() *ArkServiceConfirmRegistrationParams {
	return &ArkServiceConfirmRegistrationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewArkServiceConfirmRegistrationParamsWithTimeout creates a new ArkServiceConfirmRegistrationParams object
// with the ability to set a timeout on a request.
func NewArkServiceConfirmRegistrationParamsWithTimeout(timeout time.Duration) *ArkServiceConfirmRegistrationParams {
	return &ArkServiceConfirmRegistrationParams{
		timeout: timeout,
	}
}

// NewArkServiceConfirmRegistrationParamsWithContext creates a new ArkServiceConfirmRegistrationParams object
// with the ability to set a context for a request.
func NewArkServiceConfirmRegistrationParamsWithContext(ctx context.Context) *ArkServiceConfirmRegistrationParams {
	return &ArkServiceConfirmRegistrationParams{
		Context: ctx,
	}
}

// NewArkServiceConfirmRegistrationParamsWithHTTPClient creates a new ArkServiceConfirmRegistrationParams object
// with the ability to set a custom HTTPClient for a request.
func NewArkServiceConfirmRegistrationParamsWithHTTPClient(client *http.Client) *ArkServiceConfirmRegistrationParams {
	return &ArkServiceConfirmRegistrationParams{
		HTTPClient: client,
	}
}

/*
ArkServiceConfirmRegistrationParams contains all the parameters to send to the API endpoint

	for the ark service confirm registration operation.

	Typically these are written to a http.Request.
*/
type ArkServiceConfirmRegistrationParams struct {

	// Body.
	Body *models.V1ConfirmRegistrationRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the ark service confirm registration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceConfirmRegistrationParams) WithDefaults() *ArkServiceConfirmRegistrationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the ark service confirm registration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ArkServiceConfirmRegistrationParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) WithTimeout(timeout time.Duration) *ArkServiceConfirmRegistrationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) WithContext(ctx context.Context) *ArkServiceConfirmRegistrationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) WithHTTPClient(client *http.Client) *ArkServiceConfirmRegistrationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) WithBody(body *models.V1ConfirmRegistrationRequest) *ArkServiceConfirmRegistrationParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the ark service confirm registration params
func (o *ArkServiceConfirmRegistrationParams) SetBody(body *models.V1ConfirmRegistrationRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ArkServiceConfirmRegistrationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
