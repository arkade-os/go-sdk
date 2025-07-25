// Code generated by go-swagger; DO NOT EDIT.

package indexer_service

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
	"github.com/go-openapi/swag"
)

// NewIndexerServiceGetBatchSweepTransactionsParams creates a new IndexerServiceGetBatchSweepTransactionsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIndexerServiceGetBatchSweepTransactionsParams() *IndexerServiceGetBatchSweepTransactionsParams {
	return &IndexerServiceGetBatchSweepTransactionsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewIndexerServiceGetBatchSweepTransactionsParamsWithTimeout creates a new IndexerServiceGetBatchSweepTransactionsParams object
// with the ability to set a timeout on a request.
func NewIndexerServiceGetBatchSweepTransactionsParamsWithTimeout(timeout time.Duration) *IndexerServiceGetBatchSweepTransactionsParams {
	return &IndexerServiceGetBatchSweepTransactionsParams{
		timeout: timeout,
	}
}

// NewIndexerServiceGetBatchSweepTransactionsParamsWithContext creates a new IndexerServiceGetBatchSweepTransactionsParams object
// with the ability to set a context for a request.
func NewIndexerServiceGetBatchSweepTransactionsParamsWithContext(ctx context.Context) *IndexerServiceGetBatchSweepTransactionsParams {
	return &IndexerServiceGetBatchSweepTransactionsParams{
		Context: ctx,
	}
}

// NewIndexerServiceGetBatchSweepTransactionsParamsWithHTTPClient creates a new IndexerServiceGetBatchSweepTransactionsParams object
// with the ability to set a custom HTTPClient for a request.
func NewIndexerServiceGetBatchSweepTransactionsParamsWithHTTPClient(client *http.Client) *IndexerServiceGetBatchSweepTransactionsParams {
	return &IndexerServiceGetBatchSweepTransactionsParams{
		HTTPClient: client,
	}
}

/*
IndexerServiceGetBatchSweepTransactionsParams contains all the parameters to send to the API endpoint

	for the indexer service get batch sweep transactions operation.

	Typically these are written to a http.Request.
*/
type IndexerServiceGetBatchSweepTransactionsParams struct {

	// BatchOutpointTxid.
	BatchOutpointTxid string

	// BatchOutpointVout.
	//
	// Format: int64
	BatchOutpointVout int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the indexer service get batch sweep transactions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndexerServiceGetBatchSweepTransactionsParams) WithDefaults() *IndexerServiceGetBatchSweepTransactionsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the indexer service get batch sweep transactions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IndexerServiceGetBatchSweepTransactionsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) WithTimeout(timeout time.Duration) *IndexerServiceGetBatchSweepTransactionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) WithContext(ctx context.Context) *IndexerServiceGetBatchSweepTransactionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) WithHTTPClient(client *http.Client) *IndexerServiceGetBatchSweepTransactionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBatchOutpointTxid adds the batchOutpointTxid to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) WithBatchOutpointTxid(batchOutpointTxid string) *IndexerServiceGetBatchSweepTransactionsParams {
	o.SetBatchOutpointTxid(batchOutpointTxid)
	return o
}

// SetBatchOutpointTxid adds the batchOutpointTxid to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) SetBatchOutpointTxid(batchOutpointTxid string) {
	o.BatchOutpointTxid = batchOutpointTxid
}

// WithBatchOutpointVout adds the batchOutpointVout to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) WithBatchOutpointVout(batchOutpointVout int64) *IndexerServiceGetBatchSweepTransactionsParams {
	o.SetBatchOutpointVout(batchOutpointVout)
	return o
}

// SetBatchOutpointVout adds the batchOutpointVout to the indexer service get batch sweep transactions params
func (o *IndexerServiceGetBatchSweepTransactionsParams) SetBatchOutpointVout(batchOutpointVout int64) {
	o.BatchOutpointVout = batchOutpointVout
}

// WriteToRequest writes these params to a swagger request
func (o *IndexerServiceGetBatchSweepTransactionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param batchOutpoint.txid
	if err := r.SetPathParam("batchOutpoint.txid", o.BatchOutpointTxid); err != nil {
		return err
	}

	// path param batchOutpoint.vout
	if err := r.SetPathParam("batchOutpoint.vout", swag.FormatInt64(o.BatchOutpointVout)); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
