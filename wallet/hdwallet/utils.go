package hdwallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/pbkdf2"
)

func getBIP86RootPath(network chaincfg.Params) []uint32 {
	coinType := uint32(0)
	if network.Name != chaincfg.MainNetParams.Name {
		coinType = uint32(1)
	}
	// m/86'/0'/0' on mainnet
	// m/86'/1'/0' on any other network
	return []uint32{
		hdkeychain.HardenedKeyStart + 86,
		uint32(hdkeychain.HardenedKeyStart) + coinType,
		hdkeychain.HardenedKeyStart,
	}
}

func parseDerivationIndex(keyID string) ([]uint32, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key id is required")
	}
	if strings.Contains(keyID, "'") {
		return nil, fmt.Errorf("derivation path %s contains forbidden hardened index", keyID)
	}

	if idx, err := strconv.ParseUint(keyID, 10, 32); err == nil {
		return []uint32{defaultAccount, uint32(idx)}, nil
	}

	path := strings.TrimPrefix(keyID, "m/")
	parts := strings.Split(path, "/")

	idx, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse derivation index for path %s: %w", keyID, err)
	}

	return []uint32{defaultAccount, uint32(idx)}, nil
}

func encryptAES256(plaintext, password []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("missing plaintext")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing password")
	}

	key, salt, err := deriveEncryptionKey(password, nil)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func decryptAES256(encrypted, password []byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, fmt.Errorf("missing encrypted data")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing password")
	}
	if len(encrypted) < 32 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	salt := encrypted[len(encrypted)-32:]
	data := encrypted[:len(encrypted)-32]

	key, _, err := deriveEncryptionKey(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, text := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return plaintext, nil
}

func deriveEncryptionKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	// OWASP minimum for PBKDF2-HMAC-SHA256: 600,000
	iterations := 600000
	keySize := 32
	key := pbkdf2.Key(password, salt, iterations, keySize, sha256.New)
	return key, salt, nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
