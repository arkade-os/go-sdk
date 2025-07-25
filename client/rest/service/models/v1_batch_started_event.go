// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1BatchStartedEvent v1 batch started event
//
// swagger:model v1BatchStartedEvent
type V1BatchStartedEvent struct {

	// batch expiry
	BatchExpiry string `json:"batchExpiry,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// intent Id hashes
	IntentIDHashes []string `json:"intentIdHashes"`
}

// Validate validates this v1 batch started event
func (m *V1BatchStartedEvent) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 batch started event based on context it is used
func (m *V1BatchStartedEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1BatchStartedEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1BatchStartedEvent) UnmarshalBinary(b []byte) error {
	var res V1BatchStartedEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
