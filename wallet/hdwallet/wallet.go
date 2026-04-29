package hdwallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	walletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/tyler-smith/go-bip39"
)

const (
	// Type is the wallet type identifier for HD wallets.
	Type = "hd"
	// DefaultGapLimit is the number of unused addresses to check during discovery.
	DefaultGapLimit = uint32(20)
)

// service implements wallet.WalletService using HD key derivation.
type service struct {
	keyProvider *keyService
	store       walletstore.Store
	// mnemonic holds the BIP39 mnemonic decrypted in memory only while the
	// wallet is unlocked. Stored as []byte (not string) so Lock can zero the
	// underlying memory.
	mnemonic []byte
	locked   bool
	mu       sync.RWMutex
}

// NewService creates a new HD wallet service with all known dependencies.
func NewService(store walletstore.Store) (wallet.WalletService, error) {
	if store == nil {
		return nil, fmt.Errorf("missing wallet store")
	}
	return &service{store: store}, nil
}

func (w *service) GetType() string {
	return Type
}

// Create initializes the HD wallet using one of three seed modes:
// - empty seed: generate and return a new BIP39 mnemonic
// - valid mnemonic: restore from that mnemonic and return it unchanged
func (w *service) Create(
	ctx context.Context, network chaincfg.Params, password, seed string,
) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	existing, err := w.store.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to check existing wallet state: %w", err)
	}
	if existing != nil {
		return "", fmt.Errorf("wallet already initialized")
	}

	var mnemonic string
	var masterSeed []byte
	if seed == "" {
		// Generate new BIP39 mnemonic (24 words = 256 bits entropy)
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return "", fmt.Errorf("failed to generate entropy: %w", err)
		}
		defer zeroBytes(entropy)

		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return "", fmt.Errorf("failed to generate mnemonic: %w", err)
		}
		masterSeed = bip39.NewSeed(mnemonic, "")
	} else {
		if !bip39.IsMnemonicValid(seed) {
			return "", fmt.Errorf("invalid mnemonic")
		}
		mnemonic = seed
		masterSeed = bip39.NewSeed(mnemonic, "")
	}
	defer zeroBytes(masterSeed)

	extendedKey, err := hdkeychain.NewMaster(masterSeed, &network)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	rootPath := getBIP86RootPath(network)
	for _, step := range rootPath {
		extendedKey, err = extendedKey.Derive(step)
		if err != nil {
			return "", fmt.Errorf("failed to derive key: %w", err)
		}
	}

	// Encrypt master key (xpriv string)
	pwd := []byte(password)

	xpriv := extendedKey.String()
	encryptedKey, err := encryptAES256([]byte(xpriv), pwd)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt xpriv: %w", err)
	}

	encryptedMnemonic, err := encryptAES256([]byte(mnemonic), pwd)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt mnemonic: %w", err)
	}

	// Store encrypted data
	state := walletstore.State{
		WalletType:           Type,
		EncryptedExtendedKey: hex.EncodeToString(encryptedKey),
		EncryptedMnemonic:    hex.EncodeToString(encryptedMnemonic),
	}

	if err := w.store.Save(ctx, state); err != nil {
		return "", fmt.Errorf("failed to save wallet state: %w", err)
	}

	w.mnemonic = []byte(mnemonic)
	w.locked = true

	return mnemonic, nil
}

func (w *service) Lock(_ context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.locked {
		return nil
	}
	if w.keyProvider == nil {
		return fmt.Errorf("wallet not initialized")
	}

	w.keyProvider = nil
	zeroBytes(w.mnemonic)
	w.mnemonic = nil
	w.locked = true
	return nil
}

func (w *service) Unlock(ctx context.Context, password string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	state, err := w.store.Load(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to load wallet state: %w", err)
	}
	if state == nil {
		return false, fmt.Errorf("wallet not initialized")
	}
	if state.WalletType != Type {
		return false, fmt.Errorf("store is not for HD wallet type")
	}

	// Already unlocked
	if !w.locked && w.keyProvider != nil {
		return w.keyProvider.GetNextKeyIndex() > 0, nil
	}

	pwd := []byte(password)

	// Password verification is performed implicitly by AES-GCM decryption: any
	// wrong password fails the AEAD tag check below and surfaces as an
	// "invalid password" error from decryptAES256.
	encryptedMnemonic, err := hex.DecodeString(state.EncryptedMnemonic)
	if err != nil {
		return false, fmt.Errorf("failed to decode mnemonic: %w", err)
	}

	mnemonic, err := decryptAES256(encryptedMnemonic, pwd)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt mnemonic: %w", err)
	}

	// Decrypt xpriv
	encryptedXpriv, err := hex.DecodeString(state.EncryptedExtendedKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode xpriv: %w", err)
	}

	xpriv, err := decryptAES256(encryptedXpriv, pwd)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt xpriv: %w", err)
	}

	extendedKey, err := hdkeychain.NewKeyFromString(string(xpriv))
	if err != nil {
		return false, fmt.Errorf("failed to parse xpriv: %w", err)
	}

	// Load and restore
	keyProvider := newHDKeyService(extendedKey)
	restored := state.NextIndex > 0
	if restored {
		if err := keyProvider.LoadState(*state); err != nil {
			return false, fmt.Errorf("failed to restore key state: %w", err)
		}
	}

	w.keyProvider = keyProvider
	w.mnemonic = mnemonic
	w.locked = false

	return restored, nil
}

func (w *service) IsLocked() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.locked
}

func (w *service) NextIndex(ctx context.Context) (uint32, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if err := w.safeCheck(); err != nil {
		return 0, err
	}

	return w.keyProvider.GetNextKeyIndex(), nil
}

func (w *service) Dump(_ context.Context) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if err := w.safeCheck(); err != nil {
		return "", err
	}
	return string(w.mnemonic), nil
}

func (w *service) NewKey(ctx context.Context) (*wallet.KeyRef, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	_, pubKey, keyID, err := w.keyProvider.GetNextKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	if err := w.persistState(ctx); err != nil {
		return nil, err
	}

	return &wallet.KeyRef{Id: keyID, PubKey: pubKey}, nil
}

func (w *service) GetKey(_ context.Context, keyID string) (*wallet.KeyRef, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	if len(keyID) <= 0 {
		return nil, fmt.Errorf("key id is required")
	}

	privKey, err := w.keyProvider.DeriveKeyAt(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key %q: %w", keyID, err)
	}

	return &wallet.KeyRef{Id: keyID, PubKey: privKey.PubKey()}, nil
}

func (w *service) ListKeys(_ context.Context) ([]wallet.KeyRef, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	keys := w.keyProvider.GetAllKeyRefs()

	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].Id < keys[j].Id
	})

	return keys, nil
}

func (w *service) SignTransaction(
	_ context.Context, tx string, keys map[string]string,
) (string, error) {
	if len(keys) <= 0 {
		return "", fmt.Errorf("missing key ids by script")
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	if err := w.safeCheck(); err != nil {
		return "", err
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse PSBT: %w", err)
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", fmt.Errorf("failed to create PSBT updater: %w", err)
	}

	// Every input must carry its own prevout info — the wallet does not fetch
	// missing data from the network. The PSBT must be fully populated by the
	// caller, otherwise signing fails loudly.
	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for i := range updater.Upsbt.Inputs {
		in := updater.Upsbt.Inputs[i]
		outpoint := updater.Upsbt.UnsignedTx.TxIn[i].PreviousOutPoint
		switch {
		case in.WitnessUtxo != nil:
			prevouts[outpoint] = in.WitnessUtxo
		case in.NonWitnessUtxo != nil && int(outpoint.Index) < len(in.NonWitnessUtxo.TxOut):
			prevouts[outpoint] = in.NonWitnessUtxo.TxOut[outpoint.Index]
		default:
			return "", fmt.Errorf(
				"input %d: missing prevout (WitnessUtxo or NonWitnessUtxo) for %s:%d",
				i, outpoint.Hash, outpoint.Index,
			)
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txsighashes := txscript.NewTxSigHashes(updater.Upsbt.UnsignedTx, prevoutFetcher)

	for i, input := range ptx.Inputs {
		if input.WitnessUtxo == nil {
			continue
		}

		script := hex.EncodeToString(input.WitnessUtxo.PkScript)
		inputKeyID, ok := keys[script]
		if !ok {
			continue
		}
		if len(inputKeyID) <= 0 {
			return "", fmt.Errorf("key id is empty for input %d with script %s", i, script)
		}

		switch {
		case len(input.TaprootLeafScript) > 0:
			if err := w.signTapscriptSpend(
				updater, input, i, txsighashes, prevoutFetcher, inputKeyID,
			); err != nil {
				return "", err
			}
		case len(input.TaprootInternalKey) > 0:
			if err := w.signTaprootKeySpend(
				updater, input, i, txsighashes, prevoutFetcher, inputKeyID,
			); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf(
				"input %d: cannot sign — neither TaprootLeafScript nor TaprootInternalKey set",
				i,
			)
		}
	}

	return ptx.B64Encode()
}

func (w *service) SignMessage(_ context.Context, message []byte) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if err := w.safeCheck(); err != nil {
		return "", err
	}

	privKey, err := w.keyProvider.DeriveKeyAt("m/0/0")
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	sig, err := schnorr.Sign(privKey, message)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	return hex.EncodeToString(sig.Serialize()), nil
}

func (w *service) NewVtxoTreeSigner(_ context.Context) (tree.SignerSession, error) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return tree.NewTreeSignerSession(key), nil
}

func (w *service) safeCheck() error {
	if w.locked {
		return fmt.Errorf("wallet is locked")
	}
	if w.keyProvider == nil {
		return fmt.Errorf("wallet not initialized")
	}
	return nil
}

func (w *service) signTapscriptSpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
	keyID string,
) error {
	prvkey, err := w.keyProvider.DeriveKeyAt(keyID)
	if err != nil {
		return err
	}
	xOnlyPub := schnorr.SerializePubKey(prvkey.PubKey())

	for _, leaf := range input.TaprootLeafScript {
		closure, err := script.DecodeClosure(leaf.Script)
		if err != nil {
			continue
		}

		checkKeys := func(keys []*btcec.PublicKey) bool {
			for _, key := range keys {
				if bytes.Equal(schnorr.SerializePubKey(key), xOnlyPub) {
					return true
				}
			}
			return false
		}

		var sign bool
		switch c := closure.(type) {
		case *script.CSVMultisigClosure:
			sign = checkKeys(c.PubKeys)
		case *script.MultisigClosure:
			sign = checkKeys(c.PubKeys)
		case *script.CLTVMultisigClosure:
			sign = checkKeys(c.PubKeys)
		case *script.ConditionMultisigClosure:
			sign = checkKeys(c.PubKeys)
		}

		if !sign {
			return fmt.Errorf(
				"cannot sign taproot input %d with script-path: pubkey %x not found in witness",
				inputIndex, xOnlyPub,
			)
		}

		hash := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script).TapHash()

		preimage, err := txscript.CalcTapscriptSignaturehash(
			txsighashes,
			input.SighashType,
			updater.Upsbt.UnsignedTx,
			inputIndex,
			prevoutFetcher,
			txscript.NewBaseTapLeaf(leaf.Script),
		)
		if err != nil {
			return fmt.Errorf("failed to calc tapscript sighash: %w", err)
		}

		sig, err := schnorr.Sign(prvkey, preimage)
		if err != nil {
			return fmt.Errorf("failed to sign tapscript: %w", err)
		}

		if updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig == nil {
			updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = make(
				[]*psbt.TaprootScriptSpendSig, 0,
			)
		}

		updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig = append(
			updater.Upsbt.Inputs[inputIndex].TaprootScriptSpendSig,
			&psbt.TaprootScriptSpendSig{
				XOnlyPubKey: xOnlyPub,
				LeafHash:    hash.CloneBytes(),
				Signature:   sig.Serialize(),
				SigHash:     input.SighashType,
			},
		)
	}

	return nil
}

func (w *service) signTaprootKeySpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
	keyID string,
) error {
	// Already signed, skip
	if len(input.TaprootKeySpendSig) > 0 {
		return nil
	}

	internalKey, err := schnorr.ParsePubKey(input.TaprootInternalKey)
	if err != nil {
		return fmt.Errorf("invalid taproot internal key on input %d: %w", inputIndex, err)
	}

	prvkey, err := w.keyProvider.DeriveKeyAt(keyID)
	if err != nil {
		return err
	}

	xOnlyPubkey := schnorr.SerializePubKey(prvkey.PubKey())
	xOnlyInternalKey := schnorr.SerializePubKey(internalKey)
	if !bytes.Equal(xOnlyInternalKey, xOnlyPubkey) {
		return fmt.Errorf(
			"cannot sign taproot input %d with key-path: got internal key %x, expected %x",
			inputIndex, xOnlyInternalKey, xOnlyPubkey,
		)
	}

	preimage, err := txscript.CalcTaprootSignatureHash(
		txsighashes,
		input.SighashType,
		updater.Upsbt.UnsignedTx,
		inputIndex,
		prevoutFetcher,
	)
	if err != nil {
		return fmt.Errorf("failed to calc taproot sighash: %w", err)
	}

	sig, err := schnorr.Sign(txscript.TweakTaprootPrivKey(*prvkey, nil), preimage)
	if err != nil {
		return fmt.Errorf("failed to sign taproot key spend: %w", err)
	}

	updater.Upsbt.Inputs[inputIndex].TaprootKeySpendSig = sig.Serialize()
	return nil
}

func (w *service) persistState(ctx context.Context) error {
	existing, err := w.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load existing state: %w", err)
	}

	if existing == nil {
		return fmt.Errorf("cannot persist state: wallet credentials missing from store")
	}

	return w.store.Save(ctx, walletstore.State{
		NextIndex: w.keyProvider.GetNextKeyIndex(),
	})
}
