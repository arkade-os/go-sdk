package inmemorywalletstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	walletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store"
)

// store implements an in-memory Store for testing purposes.
type store struct {
	state *walletstore.State
	mu    sync.Mutex
}

// NewStore creates an in-memory Store for testing.
func NewStore() walletstore.Store {
	return &store{}
}

func (s *store) Save(_ context.Context, state walletstore.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		if state.WalletType == "" {
			return fmt.Errorf("missing wallet type")
		}
		if state.EncryptedExtendedKey == "" {
			return fmt.Errorf("missing encrypted extended key")
		}
		if state.EncryptedMnemonic == "" {
			return fmt.Errorf("missing encrypted mnemonic")
		}
		s.state = &walletstore.State{
			WalletType:           state.WalletType,
			EncryptedExtendedKey: state.EncryptedExtendedKey,
			EncryptedMnemonic:    state.EncryptedMnemonic,
			NextIndex:            state.NextIndex,
		}
		return nil
	}

	newState := &walletstore.State{
		WalletType:           s.state.WalletType,
		EncryptedExtendedKey: s.state.EncryptedExtendedKey,
		EncryptedMnemonic:    s.state.EncryptedMnemonic,
		NextIndex:            state.NextIndex,
	}

	s.state = newState
	return nil
}

func (s *store) Load(_ context.Context) (*walletstore.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		return nil, nil
	}

	data, err := json.Marshal(s.state)
	if err != nil {
		return nil, err
	}
	var cp walletstore.State
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

func (s *store) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = nil
	return nil
}
