package hdwallet

import (
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	walletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

const (
	defaultAccount = uint32(0)
)

// keyService handles BIP32 key derivation and caching for HD wallets.
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

// GetNextKey derives and tracks the next shared Ark wallet key pair.
func (p *keyService) GetNextKey() (*btcec.PrivateKey, *btcec.PublicKey, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	idx := p.nextKeyIndex
	privKey, err := p.deriveKeyAtIndex(idx)
	if err != nil {
		return nil, nil, "", err
	}
	p.derivedKeyCache[idx] = struct{}{}
	p.nextKeyIndex = idx + 1
	return privKey, privKey.PubKey(), p.derivationPath(idx), nil
}

// DeriveKeyAt derives the wallet keypair with the given key id.
func (p *keyService) DeriveKeyAt(keyID string) (*btcec.PrivateKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	path, err := parseDerivationIndex(keyID)
	if err != nil {
		return nil, err
	}
	index := path[1]

	privKey, err := p.deriveKeyAtIndex(index)
	if err != nil {
		return nil, err
	}
	p.derivedKeyCache[index] = struct{}{}
	return privKey, nil
}

// GetNextKeyIndex returns the exclusive upper bound of the known derived key range.
func (p *keyService) GetNextKeyIndex() uint32 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.nextKeyIndex
}

// GetAllKeyRefs returns references for all derived keys.
func (p *keyService) GetAllKeyRefs() []wallet.KeyRef {
	p.mu.RLock()
	defer p.mu.RUnlock()

	refs := make([]wallet.KeyRef, 0, len(p.derivedKeyCache))
	for index := range p.derivedKeyCache {
		// nolint
		key, _ := p.deriveKeyAtIndex(index)
		if key != nil {
			refs = append(refs, wallet.KeyRef{
				Id:     p.derivationPath(index),
				PubKey: key.PubKey(),
			})
		}
	}
	return refs
}

// LoadState restores the allocation state. Keys are derived lazily on demand.
func (p *keyService) LoadState(state walletstore.State) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nextKeyIndex = state.NextIndex
	p.derivedKeyCache = make(map[uint32]struct{})
	return nil
}

// deriveKeyAtIndex is pure: it derives the private key at the given index but
// does NOT mutate derivedKeyCache. Callers that want the index tracked must
// add it to the cache themselves while holding the write lock — otherwise
// concurrent read-locked callers (e.g. GetAllKeyRefs) would race on the map.
func (p *keyService) deriveKeyAtIndex(index uint32) (*btcec.PrivateKey, error) {
	child, err := p.deriveChildKey(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wallet key at index %d: %w", index, err)
	}
	prvkey, err := child.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract EC privkey: %w", err)
	}
	return prvkey, nil
}

// deriveChildKey derives a child key at m/0/{index} from the master key.
func (p *keyService) deriveChildKey(index uint32) (*hdkeychain.ExtendedKey, error) {
	current := p.masterKey
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

func (p *keyService) derivationPath(index uint32) string {
	return fmt.Sprintf("m/0/%d", index)
}
