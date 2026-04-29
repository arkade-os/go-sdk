package walletstore

import "context"

// State holds the persisted state of an HD wallet.
type State struct {
	WalletType           string `json:"wallet_type"`
	EncryptedExtendedKey string `json:"encrypted_extended_key"`
	EncryptedMnemonic    string `json:"encrypted_mnemonic"`
	NextIndex            uint32 `json:"next_index"`
}

// Store is the persistence interface for HD wallet state.
type Store interface {
	// Save stores the given state if not yet persisted otherwise updates it to the given state
	Save(ctx context.Context, state State) error
	// Load loads the persisted state
	Load(ctx context.Context) (*State, error)
	// Delete deletes the persisted state
	Clear(ctx context.Context) error
}
