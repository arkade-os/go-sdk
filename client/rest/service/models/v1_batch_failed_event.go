// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1BatchFailedEvent v1 batch failed event
//
// swagger:model v1BatchFailedEvent
type V1BatchFailedEvent struct {

	// id
	ID string `json:"id,omitempty"`

	// reason
	Reason string `json:"reason,omitempty"`
}

// Validate validates this v1 batch failed event
func (m *V1BatchFailedEvent) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 batch failed event based on context it is used
func (m *V1BatchFailedEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1BatchFailedEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1BatchFailedEvent) UnmarshalBinary(b []byte) error {
	var res V1BatchFailedEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
