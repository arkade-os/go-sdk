package identitystore

import "context"

// IdentityData holds the persisted data of an HD identity.
type IdentityData struct {
	Type                 string `json:"type"`
	EncryptedExtendedKey string `json:"encrypted_extended_key"`
	EncryptedMnemonic    string `json:"encrypted_mnemonic"`
	NextIndex            uint32 `json:"next_index"`
}

// IdentityStore is the persistence interface for HD identity data.
type IdentityStore interface {
	// Save stores the given identity data if not yet persisted, otherwise updates only the
	// NextIndex of the persisted data. Requires Clear to be called to store a new identity data.
	Save(ctx context.Context, data IdentityData) error
	// Load loads the persisted identity data, if any.
	Load(ctx context.Context) (*IdentityData, error)
	// Delete deletes the persisted identity data, if any.
	Clear(ctx context.Context) error
}
