// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1SubmitSignedForfeitTxsRequest v1 submit signed forfeit txs request
//
// swagger:model v1SubmitSignedForfeitTxsRequest
type V1SubmitSignedForfeitTxsRequest struct {

	// The user has to sign also the commitment tx if he registered a boarding UTXO.
	SignedCommitmentTx string `json:"signedCommitmentTx,omitempty"`

	// Forfeit txs signed by the user.
	SignedForfeitTxs []string `json:"signedForfeitTxs"`
}

// Validate validates this v1 submit signed forfeit txs request
func (m *V1SubmitSignedForfeitTxsRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 submit signed forfeit txs request based on context it is used
func (m *V1SubmitSignedForfeitTxsRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1SubmitSignedForfeitTxsRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1SubmitSignedForfeitTxsRequest) UnmarshalBinary(b []byte) error {
	var res V1SubmitSignedForfeitTxsRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
