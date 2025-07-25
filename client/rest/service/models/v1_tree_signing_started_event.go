// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1TreeSigningStartedEvent v1 tree signing started event
//
// swagger:model v1TreeSigningStartedEvent
type V1TreeSigningStartedEvent struct {

	// cosigners pubkeys
	CosignersPubkeys []string `json:"cosignersPubkeys"`

	// id
	ID string `json:"id,omitempty"`

	// unsigned commitment tx
	UnsignedCommitmentTx string `json:"unsignedCommitmentTx,omitempty"`
}

// Validate validates this v1 tree signing started event
func (m *V1TreeSigningStartedEvent) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 tree signing started event based on context it is used
func (m *V1TreeSigningStartedEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1TreeSigningStartedEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1TreeSigningStartedEvent) UnmarshalBinary(b []byte) error {
	var res V1TreeSigningStartedEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
