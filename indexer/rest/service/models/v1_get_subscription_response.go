// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// V1GetSubscriptionResponse v1 get subscription response
//
// swagger:model v1GetSubscriptionResponse
type V1GetSubscriptionResponse struct {

	// checkpoint txs
	CheckpointTxs map[string]V1IndexerTxData `json:"checkpointTxs,omitempty"`

	// new vtxos
	NewVtxos []*V1IndexerVtxo `json:"newVtxos"`

	// scripts
	Scripts []string `json:"scripts"`

	// spent vtxos
	SpentVtxos []*V1IndexerVtxo `json:"spentVtxos"`

	// tx
	Tx string `json:"tx,omitempty"`

	// txid
	Txid string `json:"txid,omitempty"`
}

// Validate validates this v1 get subscription response
func (m *V1GetSubscriptionResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCheckpointTxs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNewVtxos(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSpentVtxos(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetSubscriptionResponse) validateCheckpointTxs(formats strfmt.Registry) error {
	if swag.IsZero(m.CheckpointTxs) { // not required
		return nil
	}

	for k := range m.CheckpointTxs {

		if err := validate.Required("checkpointTxs"+"."+k, "body", m.CheckpointTxs[k]); err != nil {
			return err
		}
		if val, ok := m.CheckpointTxs[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("checkpointTxs" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("checkpointTxs" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1GetSubscriptionResponse) validateNewVtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.NewVtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.NewVtxos); i++ {
		if swag.IsZero(m.NewVtxos[i]) { // not required
			continue
		}

		if m.NewVtxos[i] != nil {
			if err := m.NewVtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("newVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("newVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1GetSubscriptionResponse) validateSpentVtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.SpentVtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.SpentVtxos); i++ {
		if swag.IsZero(m.SpentVtxos[i]) { // not required
			continue
		}

		if m.SpentVtxos[i] != nil {
			if err := m.SpentVtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this v1 get subscription response based on the context it is used
func (m *V1GetSubscriptionResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCheckpointTxs(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNewVtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSpentVtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetSubscriptionResponse) contextValidateCheckpointTxs(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.CheckpointTxs {

		if val, ok := m.CheckpointTxs[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *V1GetSubscriptionResponse) contextValidateNewVtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NewVtxos); i++ {

		if m.NewVtxos[i] != nil {

			if swag.IsZero(m.NewVtxos[i]) { // not required
				return nil
			}

			if err := m.NewVtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("newVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("newVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1GetSubscriptionResponse) contextValidateSpentVtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SpentVtxos); i++ {

		if m.SpentVtxos[i] != nil {

			if swag.IsZero(m.SpentVtxos[i]) { // not required
				return nil
			}

			if err := m.SpentVtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1GetSubscriptionResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1GetSubscriptionResponse) UnmarshalBinary(b []byte) error {
	var res V1GetSubscriptionResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
