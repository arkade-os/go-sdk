package identityfilestore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/arkade-os/go-sdk/identity/store"
)

const identityDataFile = "identity.json"

// store implements a JSON file version of the identitystore.Store interface.
type store struct {
	datadir string
	mu      sync.Mutex
}

// NewStore creates an Store backed by the client-lib ConfigStore.
func NewStore(datadir string) (identitystore.IdentityStore, error) {
	if datadir == "" {
		return nil, fmt.Errorf("missing datadir")
	}
	return &store{datadir: datadir}, nil
}

func (s *store) Save(_ context.Context, data identitystore.IdentityData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := filepath.Join(s.datadir, identityDataFile)

	var newState *identitystore.IdentityData
	existing, err := os.ReadFile(filePath)
	switch {
	case err == nil:
		var current identitystore.IdentityData
		if err := json.Unmarshal(existing, &current); err != nil {
			return fmt.Errorf("failed to unmarshal identity data: %w", err)
		}
		current.NextIndex = data.NextIndex
		newState = &current
	case os.IsNotExist(err):
		if data.Type == "" {
			return fmt.Errorf("missing identity type")
		}
		if data.EncryptedExtendedKey == "" {
			return fmt.Errorf("missing encrypted extended key")
		}
		if data.EncryptedMnemonic == "" {
			return fmt.Errorf("missing encrypted mnemonic")
		}
		newState = &identitystore.IdentityData{
			Type:                 data.Type,
			EncryptedExtendedKey: data.EncryptedExtendedKey,
			EncryptedMnemonic:    data.EncryptedMnemonic,
			NextIndex:            data.NextIndex,
		}
	default:
		return fmt.Errorf("failed to read identity data from store: %w", err)
	}

	buf, err := json.Marshal(newState)
	if err != nil {
		return fmt.Errorf("failed to marshal identity data: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("failed to create datadir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(filePath), identityDataFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp data file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(0600); err != nil {
		cleanupTempDataFile(tmp, tmpPath)
		return err
	}
	if _, err := tmp.Write(buf); err != nil {
		cleanupTempDataFile(tmp, tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanupTempDataFile(tmp, tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp data file: %w", err)
	}
	return nil
}

func (s *store) Load(_ context.Context) (*identitystore.IdentityData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	datadir := s.datadir
	if datadir == "" {
		return nil, nil
	}

	filePath := filepath.Join(datadir, identityDataFile)
	buf, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read identity data: %w", err)
	}

	var data identitystore.IdentityData
	if err := json.Unmarshal(buf, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity data: %w", err)
	}

	return &data, nil
}

func (s *store) Clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.datadir, identityDataFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func cleanupTempDataFile(file *os.File, path string) {
	_ = file.Close()
	_ = os.Remove(path)
}
