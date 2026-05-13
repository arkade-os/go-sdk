package identityinmemorystore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/arkade-os/go-sdk/identity/store"
)

// store implements an in-memory Store for testing purposes.
type store struct {
	data *identitystore.IdentityData
	mu   sync.Mutex
}

// NewStore creates an in-memory Store for testing.
func NewStore() identitystore.IdentityStore {
	return &store{}
}

func (s *store) Save(_ context.Context, data identitystore.IdentityData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data == nil {
		if data.Type == "" {
			return fmt.Errorf("missing identity type")
		}
		if data.EncryptedExtendedKey == "" {
			return fmt.Errorf("missing encrypted extended key")
		}
		if data.EncryptedMnemonic == "" {
			return fmt.Errorf("missing encrypted mnemonic")
		}
		s.data = &identitystore.IdentityData{
			Type:                 data.Type,
			EncryptedExtendedKey: data.EncryptedExtendedKey,
			EncryptedMnemonic:    data.EncryptedMnemonic,
			NextIndex:            data.NextIndex,
		}
		return nil
	}

	newData := &identitystore.IdentityData{
		Type:                 s.data.Type,
		EncryptedExtendedKey: s.data.EncryptedExtendedKey,
		EncryptedMnemonic:    s.data.EncryptedMnemonic,
		NextIndex:            data.NextIndex,
	}

	s.data = newData
	return nil
}

func (s *store) Load(_ context.Context) (*identitystore.IdentityData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data == nil {
		return nil, nil
	}

	data, err := json.Marshal(s.data)
	if err != nil {
		return nil, err
	}
	var cp identitystore.IdentityData
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

func (s *store) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = nil
	return nil
}
