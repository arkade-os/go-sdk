// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1IndexerVtxo v1 indexer vtxo
//
// swagger:model v1IndexerVtxo
type V1IndexerVtxo struct {

	// amount
	Amount string `json:"amount,omitempty"`

	// ark txid
	ArkTxid string `json:"arkTxid,omitempty"`

	// commitment txids
	CommitmentTxids []string `json:"commitmentTxids"`

	// created at
	CreatedAt string `json:"createdAt,omitempty"`

	// expires at
	ExpiresAt string `json:"expiresAt,omitempty"`

	// is preconfirmed
	IsPreconfirmed bool `json:"isPreconfirmed,omitempty"`

	// is spent
	IsSpent bool `json:"isSpent,omitempty"`

	// is swept
	IsSwept bool `json:"isSwept,omitempty"`

	// is unrolled
	IsUnrolled bool `json:"isUnrolled,omitempty"`

	// outpoint
	Outpoint *V1IndexerOutpoint `json:"outpoint,omitempty"`

	// script
	Script string `json:"script,omitempty"`

	// settled by
	SettledBy string `json:"settledBy,omitempty"`

	// spent by
	SpentBy string `json:"spentBy,omitempty"`
}

// Validate validates this v1 indexer vtxo
func (m *V1IndexerVtxo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOutpoint(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1IndexerVtxo) validateOutpoint(formats strfmt.Registry) error {
	if swag.IsZero(m.Outpoint) { // not required
		return nil
	}

	if m.Outpoint != nil {
		if err := m.Outpoint.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("outpoint")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("outpoint")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this v1 indexer vtxo based on the context it is used
func (m *V1IndexerVtxo) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOutpoint(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1IndexerVtxo) contextValidateOutpoint(ctx context.Context, formats strfmt.Registry) error {

	if m.Outpoint != nil {

		if swag.IsZero(m.Outpoint) { // not required
			return nil
		}

		if err := m.Outpoint.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("outpoint")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("outpoint")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1IndexerVtxo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1IndexerVtxo) UnmarshalBinary(b []byte) error {
	var res V1IndexerVtxo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
