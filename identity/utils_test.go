package identity

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		plaintext := []byte("test secret data")
		password := []byte("mypassword")

		encrypted, err := encryptAES256(plaintext, password)
		require.NoError(t, err)

		decrypted, err := decryptAES256(encrypted, password)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)

		// Same plaintext+password must produce a different ciphertext (random salt).
		encryptedAgain, err := encryptAES256(plaintext, password)
		require.NoError(t, err)
		require.NotEqual(t, encrypted, encryptedAgain)
	})

	t.Run("invalid", func(t *testing.T) {
		rightCiphertext, err := encryptAES256([]byte("plaintext"), []byte("mypassword"))
		require.NoError(t, err)

		fixtures := []struct {
			name            string
			ciphertext      []byte
			password        []byte
			wantErrContains string
		}{
			{
				name:            "missing data",
				ciphertext:      nil,
				password:        []byte("mypassword"),
				wantErrContains: "missing encrypted data",
			},
			{
				name:            "missing password",
				ciphertext:      []byte("nonempty"),
				password:        nil,
				wantErrContains: "missing password",
			},
			{
				name:            "wrong data lenght",
				ciphertext:      []byte("short"),
				password:        []byte("mypassword"),
				wantErrContains: "encrypted data too short",
			},
			{
				name:            "wrong password",
				ciphertext:      rightCiphertext,
				password:        []byte("nottherightpassword"),
				wantErrContains: "invalid password",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				_, err := decryptAES256(f.ciphertext, f.password)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}
