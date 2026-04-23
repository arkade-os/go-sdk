package hdwallet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

// State holds the persisted state of an HD wallet.
type State struct {
	Version            uint32 `json:"version,omitempty"`
	WalletType         string `json:"wallet_type"`
	EncryptedMasterKey []byte `json:"encrypted_master_key"`
	PasswordVerifier   []byte `json:"password_verifier,omitempty"`
	PasswordSalt       []byte `json:"password_salt,omitempty"`
	EncryptedMnemonic  []byte `json:"encrypted_mnemonic,omitempty"`
	OffchainNextIndex  uint32 `json:"offchain_next_index"`
}

// Store is the persistence interface for HD wallet state.
type Store interface {
	Save(ctx context.Context, state *State) error
	Load(ctx context.Context) (*State, error)
}

const hdWalletStateFile = "hd_wallet_state.json"

// configStoreBackend implements Store using the client-lib ConfigStore's
// data directory for file-based persistence.
type configStoreBackend struct {
	configStore clientTypes.ConfigStore
	mu          sync.Mutex
}

// NewStore creates an Store backed by the client-lib ConfigStore.
func NewStore(store clientTypes.ConfigStore) Store {
	return &configStoreBackend{configStore: store}
}

func (s *configStoreBackend) Save(_ context.Context, state *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal hd wallet state: %w", err)
	}

	datadir := s.configStore.GetDatadir()
	if datadir == "" {
		return fmt.Errorf("config store datadir is empty")
	}

	filePath := filepath.Join(datadir, hdWalletStateFile)
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("failed to create datadir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(filePath), hdWalletStateFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(0600); err != nil {
		cleanupTempStateFile(tmp, tmpPath)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanupTempStateFile(tmp, tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanupTempStateFile(tmp, tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, filePath)
}

func cleanupTempStateFile(file *os.File, path string) {
	_ = file.Close()
	_ = os.Remove(path)
}

func (s *configStoreBackend) Load(_ context.Context) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	datadir := s.configStore.GetDatadir()
	if datadir == "" {
		return nil, nil
	}

	filePath := filepath.Join(datadir, hdWalletStateFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read hd wallet state: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hd wallet state: %w", err)
	}

	return &state, nil
}

// inMemoryStore implements Store for testing purposes.
type inMemoryStore struct {
	state *State
	mu    sync.Mutex
}

// NewInMemoryStore creates an in-memory Store for testing.
func NewInMemoryStore() Store {
	return &inMemoryStore{}
}

func (s *inMemoryStore) Save(_ context.Context, state *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	var cp State
	if err := json.Unmarshal(data, &cp); err != nil {
		return err
	}
	s.state = &cp
	return nil
}

func (s *inMemoryStore) Load(_ context.Context) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		return nil, nil
	}

	data, err := json.Marshal(s.state)
	if err != nil {
		return nil, err
	}
	var cp State
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}
