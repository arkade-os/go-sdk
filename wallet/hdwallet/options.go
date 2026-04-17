package hdwallet

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

type keyArgs struct {
	id string
}

// WithKeyID resolves a previously allocated HD key by its stable key ID.
func WithKeyID(id string) wallet.KeyOption {
	return func(options any) error {
		args, ok := options.(*keyArgs)
		if !ok {
			return fmt.Errorf("invalid key options type %T", options)
		}
		args.id = id
		return nil
	}
}

// WithDerivationPath is an alias for WithKeyID when IDs are derivation paths.
func WithDerivationPath(path string) wallet.KeyOption {
	return WithKeyID(path)
}

func parseKeyID(opts ...wallet.KeyOption) (string, error) {
	args := &keyArgs{}
	for _, opt := range opts {
		if err := opt(args); err != nil {
			return "", err
		}
	}

	if args.id == "" {
		return "", fmt.Errorf("key id is required")
	}

	return args.id, nil
}

func parseOffchainIndex(keyID string) (uint32, error) {
	if keyID == "" {
		return 0, fmt.Errorf("key id is required")
	}

	if idx, err := strconv.ParseUint(keyID, 10, 32); err == nil {
		return uint32(idx), nil
	}

	path := strings.TrimPrefix(keyID, "m/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return 0, fmt.Errorf("invalid key id %q", keyID)
	}

	idx, err := strconv.ParseUint(strings.TrimSuffix(parts[len(parts)-1], "'"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid key id %q: %w", keyID, err)
	}

	return uint32(idx), nil
}
