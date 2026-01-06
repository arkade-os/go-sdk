package wallet_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestDefaultScriptBuilder(t *testing.T) {
	builder := wallet.NewDefaultScriptBuilder()
	require.NotNil(t, builder)

	// Generate test keys
	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	exitDelay := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeBlock,
		Value: 512,
	}

	t.Run("build offchain script", func(t *testing.T) {
		scripts, err := builder.BuildOffchainScript(userKey.PubKey(), signerKey.PubKey(), exitDelay)
		require.NoError(t, err)
		require.NotEmpty(t, scripts)

		// Validate scripts can be parsed
		_, err = script.ParseVtxoScript(scripts)
		require.NoError(t, err)

		// Validate using utility function
		err = wallet.ValidateScripts(scripts)
		require.NoError(t, err)
	})

	t.Run("build boarding script", func(t *testing.T) {
		boardingDelay := arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 1024,
		}

		scripts, err := builder.BuildBoardingScript(userKey.PubKey(), signerKey.PubKey(), boardingDelay)
		require.NoError(t, err)
		require.NotEmpty(t, scripts)

		// Validate scripts can be parsed
		_, err = script.ParseVtxoScript(scripts)
		require.NoError(t, err)

		// Validate using utility function
		err = wallet.ValidateScripts(scripts)
		require.NoError(t, err)
	})
}

func TestExtractTapKeyFromScripts(t *testing.T) {
	builder := wallet.NewDefaultScriptBuilder()

	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	exitDelay := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeBlock,
		Value: 512,
	}

	scripts, err := builder.BuildOffchainScript(userKey.PubKey(), signerKey.PubKey(), exitDelay)
	require.NoError(t, err)

	tapKey, err := wallet.ExtractTapKeyFromScripts(scripts)
	require.NoError(t, err)
	require.NotNil(t, tapKey)

	// Verify the tapKey is a valid schnorr public key
	require.Equal(t, 32, len(tapKey.SerializeCompressed()))
}

func TestValidateScripts(t *testing.T) {
	t.Run("valid scripts", func(t *testing.T) {
		builder := wallet.NewDefaultScriptBuilder()
		userKey, _ := btcec.NewPrivateKey()
		signerKey, _ := btcec.NewPrivateKey()
		exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 512}

		scripts, err := builder.BuildOffchainScript(userKey.PubKey(), signerKey.PubKey(), exitDelay)
		require.NoError(t, err)

		err = wallet.ValidateScripts(scripts)
		require.NoError(t, err)
	})

	t.Run("empty scripts array", func(t *testing.T) {
		err := wallet.ValidateScripts([]string{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no scripts generated")
	})

	t.Run("nil scripts", func(t *testing.T) {
		err := wallet.ValidateScripts(nil)
		require.Error(t, err)
	})

	t.Run("empty script in array", func(t *testing.T) {
		err := wallet.ValidateScripts([]string{""})
		require.Error(t, err)
		require.Contains(t, err.Error(), "script 0 is empty")
	})

	t.Run("invalid hex", func(t *testing.T) {
		err := wallet.ValidateScripts([]string{"not-valid-hex"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not valid hex")
	})
}

func TestExtractTapKeyFromScripts_Errors(t *testing.T) {
	t.Run("empty scripts", func(t *testing.T) {
		_, err := wallet.ExtractTapKeyFromScripts([]string{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no scripts provided")
	})

	t.Run("invalid scripts", func(t *testing.T) {
		_, err := wallet.ExtractTapKeyFromScripts([]string{"invalid"})
		require.Error(t, err)
	})
}

// CustomScriptBuilder is a test implementation of VtxoScriptBuilder
type CustomScriptBuilder struct {
	offchainScripts []string
	boardingScripts []string
	err             error
}

func (c *CustomScriptBuilder) BuildOffchainScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.offchainScripts != nil {
		return c.offchainScripts, nil
	}
	// Fall back to default behavior
	vtxoScript := script.NewDefaultVtxoScript(userPubKey, signerPubKey, exitDelay)
	return vtxoScript.Encode()
}

func (c *CustomScriptBuilder) BuildBoardingScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.boardingScripts != nil {
		return c.boardingScripts, nil
	}
	// Fall back to default behavior
	vtxoScript := script.NewDefaultVtxoScript(userPubKey, signerPubKey, exitDelay)
	return vtxoScript.Encode()
}

func TestCustomScriptBuilder(t *testing.T) {
	userKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	exitDelay := arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeBlock,
		Value: 512,
	}

	t.Run("custom builder with default fallback", func(t *testing.T) {
		builder := &CustomScriptBuilder{}

		scripts, err := builder.BuildOffchainScript(userKey.PubKey(), signerKey.PubKey(), exitDelay)
		require.NoError(t, err)
		require.NotEmpty(t, scripts)

		err = wallet.ValidateScripts(scripts)
		require.NoError(t, err)
	})

	t.Run("custom builder with error", func(t *testing.T) {
		builder := &CustomScriptBuilder{
			err: require.AnError,
		}

		_, err := builder.BuildOffchainScript(userKey.PubKey(), signerKey.PubKey(), exitDelay)
		require.Error(t, err)
	})
}
