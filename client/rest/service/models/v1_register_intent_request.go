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

// V1RegisterIntentRequest v1 register intent request
//
// swagger:model v1RegisterIntentRequest
type V1RegisterIntentRequest struct {

	// BIP322 signature embeds the outpoints and the proof of funds
	Bip322Signature *V1Bip322Signature `json:"bip322Signature,omitempty"`

	// notes
	Notes []string `json:"notes"`
}

// Validate validates this v1 register intent request
func (m *V1RegisterIntentRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBip322Signature(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1RegisterIntentRequest) validateBip322Signature(formats strfmt.Registry) error {
	if swag.IsZero(m.Bip322Signature) { // not required
		return nil
	}

	if m.Bip322Signature != nil {
		if err := m.Bip322Signature.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("bip322Signature")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("bip322Signature")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this v1 register intent request based on the context it is used
func (m *V1RegisterIntentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBip322Signature(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1RegisterIntentRequest) contextValidateBip322Signature(ctx context.Context, formats strfmt.Registry) error {

	if m.Bip322Signature != nil {

		if swag.IsZero(m.Bip322Signature) { // not required
			return nil
		}

		if err := m.Bip322Signature.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("bip322Signature")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("bip322Signature")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1RegisterIntentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1RegisterIntentRequest) UnmarshalBinary(b []byte) error {
	var res V1RegisterIntentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
