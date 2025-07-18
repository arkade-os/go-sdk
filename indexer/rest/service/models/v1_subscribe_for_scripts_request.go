// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1SubscribeForScriptsRequest v1 subscribe for scripts request
//
// swagger:model v1SubscribeForScriptsRequest
type V1SubscribeForScriptsRequest struct {

	// scripts
	Scripts []string `json:"scripts"`

	// If set, update an existing subscription
	SubscriptionID string `json:"subscriptionId,omitempty"`
}

// Validate validates this v1 subscribe for scripts request
func (m *V1SubscribeForScriptsRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 subscribe for scripts request based on context it is used
func (m *V1SubscribeForScriptsRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1SubscribeForScriptsRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1SubscribeForScriptsRequest) UnmarshalBinary(b []byte) error {
	var res V1SubscribeForScriptsRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
