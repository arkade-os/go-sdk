package hdwallet

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

const (
	// defaultKeyPathPrefix is the canonical Ark SDK derivation path shared with the Rust SDK.
	defaultKeyPathPrefix = "m/83696968'/11811'/0"
)

type cachedKey struct {
	privKey *btcec.PrivateKey
	pubKey  *btcec.PublicKey
}

// KeyService handles BIP32 key derivation and caching for HD wallets.
type KeyService struct {
	// masterKey is the BIP32 root key restored from the user's mnemonic or xpriv.
	masterKey *hdkeychain.ExtendedKey

	// keyBasePath is the parsed form of defaultKeyPathPrefix.
	//
	// The final non-hardened child index is appended per allocated key. Each derived
	// pubkey currently acts as the common wallet key for all Ark address families:
	// offchain, boarding, redemption, and direct onchain taproot addresses.
	//
	// TODO: If Ark adopts separate branches in the future, consider splitting this
	// shared base into purpose-specific paths for onchain/offchain/boarding flows,
	// and possibly contract-specific branches such as default VTXOs, vHTLCs,
	// delegator keys, or introspector-style contracts. Any change here must remain
	// coordinated across SDKs to preserve mnemonic compatibility.
	keyBasePath []uint32

	// derivedKeyCache stores already derived keys by child index so we can reuse
	// them across address generation, signing, and discovery without deriving again.
	derivedKeyCache map[uint32]*cachedKey
	// nextKeyIndex is the next child index to allocate from keyBasePath.
	nextKeyIndex uint32
	mu           sync.RWMutex
}

// DefaultKeyPath returns the full derivation path for the shared Ark wallet key
// at the given child index.
func (p *KeyService) DefaultKeyPath(index uint32) string {
	return fmt.Sprintf("%s/%d", defaultKeyPathPrefix, index)
}

// NewHDKeyProvider creates a new key provider from a BIP32 master extended key.
func NewHDKeyProvider(masterKey *hdkeychain.ExtendedKey) *KeyService {
	keyBasePath, err := parseKeyPathPrefix(defaultKeyPathPrefix)
	if err != nil {
		panic(fmt.Sprintf("invalid default HD key path prefix %q: %v", defaultKeyPathPrefix, err))
	}

	return &KeyService{
		masterKey:       masterKey,
		keyBasePath:     keyBasePath,
		derivedKeyCache: make(map[uint32]*cachedKey),
	}
}

// DeriveKeyAtIndex derives the shared Ark wallet private key at the given child
// index without mutating provider state. Callers that want the derived key to
// become part of the known in-memory key range must cache it separately.
func (p *KeyService) DeriveKeyAtIndex(index uint32) (*btcec.PrivateKey, error) {
	child, err := p.deriveChildKey(p.keyBasePath, index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wallet key at index %d: %w", index, err)
	}
	privKey, err := child.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract EC privkey: %w", err)
	}
	return privKey, nil
}

// GetNextKey derives and caches the next shared Ark wallet key pair.
func (p *KeyService) GetNextKey() (*btcec.PrivateKey, *btcec.PublicKey, uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	idx := p.nextKeyIndex
	privKey, err := p.DeriveKeyAtIndex(idx)
	if err != nil {
		return nil, nil, 0, err
	}

	p.derivedKeyCache[idx] = &cachedKey{
		privKey: privKey,
		pubKey:  privKey.PubKey(),
	}
	p.nextKeyIndex = idx + 1
	return privKey, privKey.PubKey(), idx, nil
}

// CacheDerivedKey records a previously derived key in the in-memory cache and
// expands nextKeyIndex when needed. This is intentionally separate from
// DeriveKeyAtIndex so callers like discovery can probe candidate indices
// without automatically mutating wallet state.
func (p *KeyService) CacheDerivedKey(index uint32, privKey *btcec.PrivateKey) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.derivedKeyCache[index] = &cachedKey{
		privKey: privKey,
		pubKey:  privKey.PubKey(),
	}
	if index >= p.nextKeyIndex {
		p.nextKeyIndex = index + 1
	}
}

// GetPrivKeyForPubKey searches the known derived key range for a private key matching the given pubkey.
func (p *KeyService) GetPrivKeyForPubKey(pubKey *btcec.PublicKey) (*btcec.PrivateKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	target := pubKey.SerializeCompressed()
	for i := uint32(0); i < p.nextKeyIndex; i++ {
		ck, err := p.getOrDeriveKeyLocked(i)
		if err != nil {
			return nil, err
		}
		if bytesEqual(ck.pubKey.SerializeCompressed(), target) {
			return ck.privKey, nil
		}
	}

	return nil, fmt.Errorf("no key for pubkey %x in HD wallet range", target)
}

// GetAllDerivedPubKeys returns all public keys in the known derived key range.
func (p *KeyService) GetAllDerivedPubKeys() []*btcec.PublicKey {
	p.mu.Lock()
	defer p.mu.Unlock()

	keys := make([]*btcec.PublicKey, 0, p.nextKeyIndex)
	for i := uint32(0); i < p.nextKeyIndex; i++ {
		ck, err := p.getOrDeriveKeyLocked(i)
		if err == nil {
			keys = append(keys, ck.pubKey)
		}
	}
	return keys
}

// GetDerivedPubKey returns the derived public key for the given child index if
// that index is already part of the known wallet key range.
func (p *KeyService) GetDerivedPubKey(index uint32) (*btcec.PublicKey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if index >= p.nextKeyIndex {
		return nil, false
	}

	ck, err := p.getOrDeriveKeyLocked(index)
	if err != nil {
		return nil, false
	}

	return ck.pubKey, true
}

// GetNextKeyIndex returns the exclusive upper bound of the known derived key range.
func (p *KeyService) GetNextKeyIndex() uint32 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.nextKeyIndex
}

// ExportState serializes the allocation state needed to reconstruct the wallet.
func (p *KeyService) ExportState() State {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return State{
		OffchainNextIndex: p.nextKeyIndex,
	}
}

// LoadState restores the allocation state. Keys are derived lazily on demand.
func (p *KeyService) LoadState(state State) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nextKeyIndex = state.OffchainNextIndex
	p.derivedKeyCache = make(map[uint32]*cachedKey)
	return nil
}

// getOrDeriveKeyLocked returns a cached key when present, or lazily re-derives
// it from the master key when the cache is empty for a known index. This
// happens after LoadState(), which restores nextKeyIndex but intentionally
// clears the in-memory derived key cache.
func (p *KeyService) getOrDeriveKeyLocked(index uint32) (*cachedKey, error) {
	if ck, ok := p.derivedKeyCache[index]; ok {
		return ck, nil
	}

	privKey, err := p.DeriveKeyAtIndex(index)
	if err != nil {
		return nil, err
	}

	ck := &cachedKey{
		privKey: privKey,
		pubKey:  privKey.PubKey(),
	}
	p.derivedKeyCache[index] = ck
	return ck, nil
}

// deriveChildKey derives a child key at basePath/{index} from the master key.
// The index is non-hardened.
func (p *KeyService) deriveChildKey(basePath []uint32, index uint32) (*hdkeychain.ExtendedKey, error) {
	current := p.masterKey
	fullPath := append(basePath, index)
	for _, childIdx := range fullPath {
		child, err := current.Derive(childIdx)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child at index %d: %w", childIdx, err)
		}
		current = child
	}
	return current, nil
}

func parseKeyPathPrefix(path string) ([]uint32, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("key path is required")
	}

	path = strings.TrimPrefix(path, "m/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid key path %q", path)
	}

	parsed := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("invalid empty path component")
		}

		hardened := strings.HasSuffix(part, "'")
		part = strings.TrimSuffix(part, "'")

		index, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path component %q: %w", part, err)
		}

		derivedIndex := uint32(index)
		if hardened {
			derivedIndex += hdkeychain.HardenedKeyStart
		}

		parsed = append(parsed, derivedIndex)
	}

	return parsed, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
