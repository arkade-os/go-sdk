// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1BatchFinalizationEvent v1 batch finalization event
//
// swagger:model v1BatchFinalizationEvent
type V1BatchFinalizationEvent struct {

	// commitment tx
	CommitmentTx string `json:"commitmentTx,omitempty"`

	// id
	ID string `json:"id,omitempty"`
}

// Validate validates this v1 batch finalization event
func (m *V1BatchFinalizationEvent) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 batch finalization event based on context it is used
func (m *V1BatchFinalizationEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1BatchFinalizationEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1BatchFinalizationEvent) UnmarshalBinary(b []byte) error {
	var res V1BatchFinalizationEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
