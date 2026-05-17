package identity

import (
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	identitystore "github.com/arkade-os/go-sdk/identity/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

const (
	defaultAccount = uint32(0)
)

// keyService handles BIP32 key derivation and caching for HD identity.
type keyService struct {
	// masterKey is the BIP32 root key restored from the user's mnemonic or xpriv.
	masterKey *hdkeychain.ExtendedKey

	// derivedKeyCache stores already derived keys by child index so we can reuse
	// them across address generation, signing, and discovery without deriving again.
	derivedKeyCache map[uint32]struct{}
	// nextKeyIndex is the next child index to allocate from keyBasePath.
	nextKeyIndex uint32
	mu           sync.RWMutex
}

// newHDKeyService creates a new key provider from a BIP32 master extended key.
func newHDKeyService(masterKey *hdkeychain.ExtendedKey) *keyService {
	return &keyService{
		masterKey:       masterKey,
		derivedKeyCache: make(map[uint32]struct{}),
	}
}

// GetNextKey derives and caches the next key pair based on the internal derivation index.
func (s *keyService) GetNextKey() (*btcec.PrivateKey, *btcec.PublicKey, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.nextKeyIndex
	privKey, err := s.deriveKeyAtIndex(idx)
	if err != nil {
		return nil, nil, "", err
	}
	s.derivedKeyCache[idx] = struct{}{}
	s.nextKeyIndex = idx + 1
	return privKey, privKey.PubKey(), toDerivationPath(idx), nil
}

// DeriveKeyAt derives the key pair with the given key id.
func (s *keyService) DeriveKeyAt(keyId string) (*btcec.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := parseDerivationIndex(keyId)
	if err != nil {
		return nil, err
	}
	index := path[1]

	privKey, err := s.deriveKeyAtIndex(index)
	if err != nil {
		return nil, err
	}
	s.derivedKeyCache[index] = struct{}{}
	return privKey, nil
}

// GetNextKeyIndex returns the internal derivation index for the next key pair.
func (s *keyService) GetNextKeyIndex() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.nextKeyIndex
}

// ClaimIndex marks index as allocated, advancing nextKeyIndex past it
func (s *keyService) ClaimIndex(index uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.derivedKeyCache[index] = struct{}{}
	if index >= s.nextKeyIndex {
		s.nextKeyIndex = index + 1
	}
}

// GetAllKeyRefs returns references for all keys derived with GetNextKey.
func (s *keyService) GetAllKeyRefs() []identity.KeyRef {
	s.mu.RLock()
	defer s.mu.RUnlock()

	refs := make([]identity.KeyRef, 0, s.nextKeyIndex)
	for index := uint32(0); index < s.nextKeyIndex; index++ {
		// nolint
		key, _ := s.deriveKeyAtIndex(index)
		if key != nil {
			refs = append(refs, identity.KeyRef{
				Id:     toDerivationPath(index),
				PubKey: key.PubKey(),
			})
		}
	}
	return refs
}

// LoadState restores the allocation state. Keys are derived lazily on demand.
func (s *keyService) LoadState(state identitystore.IdentityData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextKeyIndex = state.NextIndex
	s.derivedKeyCache = make(map[uint32]struct{})
	return nil
}

// deriveKeyAtIndex is pure: it derives the private key at the given index but
// does NOT mutate derivedKeyCache. Callers that want the index tracked must
// add it to the cache themselves while holding the write lock — otherwise
// concurrent read-locked callers (e.g. GetAllKeyRefs) would race on the map.
func (s *keyService) deriveKeyAtIndex(index uint32) (*btcec.PrivateKey, error) {
	child, err := s.deriveChildKey(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key at index %d: %w", index, err)
	}
	prvkey, err := child.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract EC privkey: %w", err)
	}
	return prvkey, nil
}

// deriveChildKey derives a child key at m/0/{index} from the master key.
func (s *keyService) deriveChildKey(index uint32) (*hdkeychain.ExtendedKey, error) {
	current := s.masterKey
	fullPath := []uint32{defaultAccount, index}
	for _, childIdx := range fullPath {
		child, err := current.Derive(childIdx)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child at index %d: %w", childIdx, err)
		}
		current = child
	}
	return current, nil
}
