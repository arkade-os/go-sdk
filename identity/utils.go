package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/pbkdf2"
)

func getBIP86RootPath(network *chaincfg.Params) []uint32 {
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

// parseDerivationIndex normalizes a key id to the {account, index} pair the key service
// derives at. Only the terminal index identifies a key: every key lives under the single
// unhardened account m/0, so any leading segments ("m/", an account number) are deliberately
// ignored and "5", "0/5", "m/5" and "m/0/5" all resolve to the same key. Key ids are produced
// internally by toDerivationPath and persisted in contract params — this normalization keeps
// them stable across the historical formats, it is not meant to validate user input.
func parseDerivationIndex(keyId string) ([]uint32, error) {
	if keyId == "" {
		return nil, fmt.Errorf("key id is required")
	}
	if strings.Contains(keyId, "'") {
		return nil, fmt.Errorf("derivation path %s contains forbidden hardened index", keyId)
	}

	if idx, err := strconv.ParseUint(keyId, 10, 32); err == nil {
		return []uint32{defaultAccount, uint32(idx)}, nil
	}

	path := strings.TrimPrefix(keyId, "m/")
	parts := strings.Split(path, "/")

	idx, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse derivation index for path %s: %w", keyId, err)
	}

	return []uint32{defaultAccount, uint32(idx)}, nil
}

func toDerivationPath(index uint32) string {
	return fmt.Sprintf("m/0/%d", index)
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
	// Layout: gcm nonce (12) || ciphertext || gcm tag (16) || pbkdf2 salt (32). Reject
	// anything that can't possibly decrypt before the key derivation below: it's
	// deliberately expensive (600k PBKDF2 rounds) and must not run on garbage input.
	const minEncryptedLen = 12 + 16 + 32
	if len(encrypted) < minEncryptedLen {
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

// zeroBytes overwrites every byte of b with zero. It's a best-effort
// memory-hygiene helper for sensitive material like the decrypted mnemonic.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func toBitcoinNetwork(net arklib.Network) *chaincfg.Params {
	switch net.Name {
	case arklib.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		return &chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return &arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}
