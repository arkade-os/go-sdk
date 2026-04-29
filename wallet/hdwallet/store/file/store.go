package filewalletstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	walletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store"
)

const hdWalletStateFile = "wallet.json"

// walletStore implements Store using the client-lib ConfigStore's
// data directory for file-based persistence.
type walletStore struct {
	datadir string
	mu      sync.Mutex
}

// NewStore creates an Store backed by the client-lib ConfigStore.
func NewStore(datadir string) (walletstore.Store, error) {
	if datadir == "" {
		return nil, fmt.Errorf("missing datadir")
	}
	return &walletStore{datadir: datadir}, nil
}

func (s *walletStore) Save(_ context.Context, state walletstore.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := filepath.Join(s.datadir, hdWalletStateFile)

	var newState *walletstore.State
	existing, err := os.ReadFile(filePath)
	switch {
	case err == nil:
		var current walletstore.State
		if err := json.Unmarshal(existing, &current); err != nil {
			return fmt.Errorf("failed to unmarshal hd wallet state: %w", err)
		}
		current.NextIndex = state.NextIndex
		newState = &current
	case os.IsNotExist(err):
		if state.WalletType == "" {
			return fmt.Errorf("missing wallet type")
		}
		if state.EncryptedExtendedKey == "" {
			return fmt.Errorf("missing encrypted extended key")
		}
		if state.EncryptedMnemonic == "" {
			return fmt.Errorf("missing encrypted mnemonic")
		}
		newState = &walletstore.State{
			WalletType:           state.WalletType,
			EncryptedExtendedKey: state.EncryptedExtendedKey,
			EncryptedMnemonic:    state.EncryptedMnemonic,
			NextIndex:            state.NextIndex,
		}
	default:
		return fmt.Errorf("failed to read data from wallet store: %w", err)
	}

	data, err := json.Marshal(newState)
	if err != nil {
		return fmt.Errorf("failed to marshal hd wallet state: %w", err)
	}

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

	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp state file: %w", err)
	}
	return nil
}

func (s *walletStore) Load(_ context.Context) (*walletstore.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	datadir := s.datadir
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

	var state walletstore.State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hd wallet state: %w", err)
	}

	return &state, nil
}

func (s *walletStore) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.datadir, hdWalletStateFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func cleanupTempStateFile(file *os.File, path string) {
	_ = file.Close()
	_ = os.Remove(path)
}
