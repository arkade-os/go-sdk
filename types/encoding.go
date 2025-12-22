package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func (a *AssetOutput) EncodeTlv() ([]byte, error) {
	var buf bytes.Buffer

	// AssetId (Length + Bytes)
	idBytes := []byte(a.AssetId)
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(idBytes))); err != nil {
		return nil, err
	}
	if _, err := buf.Write(idBytes); err != nil {
		return nil, err
	}

	// Amount
	if err := binary.Write(&buf, binary.BigEndian, a.Amount); err != nil {
		return nil, err
	}

	// Vout
	if err := binary.Write(&buf, binary.BigEndian, a.Vout); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (a *AssetOutput) DecodeTlv(b []byte) error {
	r := bytes.NewReader(b)

	// AssetId
	var idLen uint32
	if err := binary.Read(r, binary.BigEndian, &idLen); err != nil {
		return err
	}

	// Check for reasonable length to prevent huge allocation
	if idLen > 1024 {
		return fmt.Errorf("asset id length too large: %d", idLen)
	}

	idBytes := make([]byte, idLen)
	if _, err := r.Read(idBytes); err != nil {
		return err
	}
	a.AssetId = string(idBytes)

	// Amount
	if err := binary.Read(r, binary.BigEndian, &a.Amount); err != nil {
		return err
	}

	// Vout
	if err := binary.Read(r, binary.BigEndian, &a.Vout); err != nil {
		return err
	}

	return nil
}
