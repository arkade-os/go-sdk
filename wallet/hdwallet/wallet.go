package hdwallet

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/tyler-smith/go-bip39"
	bip32 "github.com/vulpemventures/go-bip32"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// Type is the wallet type identifier for HD wallets.
	Type = "hd"
	// DefaultGapLimit is the number of unused addresses to check during discovery.
	DefaultGapLimit      = uint32(20)
	hdWalletStateVersion = uint32(2)
	passwordSaltSize     = 32
	pbkdf2Iterations     = 600_000
)

// Compile-time interface check.
var _ wallet.WalletService = (*Service)(nil)

// Service implements wallet.WalletService using HD key derivation.
type Service struct {
	keyProvider         *KeyService
	store               Store
	indexer             indexer.Indexer
	explorer            explorer.Explorer
	keyPathPrefix       string
	arkNetwork          arklib.Network
	signerPubKey        *btcec.PublicKey
	boardingExitDelay   arklib.RelativeLocktime
	unilateralExitDelay arklib.RelativeLocktime
	mnemonic            string
	locked              bool
	mu                  sync.RWMutex
}

// Args defines the dependencies needed to construct an HD wallet service.
type Args struct {
	Store               Store
	Indexer             indexer.Indexer
	Explorer            explorer.Explorer
	KeyPathPrefix       string
	ArkNetwork          arklib.Network
	SignerPubKey        *btcec.PublicKey
	BoardingExitDelay   arklib.RelativeLocktime
	UnilateralExitDelay arklib.RelativeLocktime
}

// NewService creates a new HD wallet service with all known dependencies.
func NewService(args Args) (*Service, error) {
	if args.Store == nil {
		return nil, fmt.Errorf("missing hd wallet store")
	}
	keyPathPrefix := normalizeKeyPathPrefix(args.KeyPathPrefix)
	if _, err := parseKeyPathPrefix(keyPathPrefix); err != nil {
		return nil, fmt.Errorf("invalid hd key path prefix %q: %w", keyPathPrefix, err)
	}

	return &Service{
		store:               args.Store,
		indexer:             args.Indexer,
		explorer:            args.Explorer,
		keyPathPrefix:       keyPathPrefix,
		arkNetwork:          args.ArkNetwork,
		signerPubKey:        args.SignerPubKey,
		boardingExitDelay:   args.BoardingExitDelay,
		unilateralExitDelay: args.UnilateralExitDelay,
		locked:              true,
	}, nil
}

func (w *Service) GetType() string {
	return Type
}

// Create initializes the HD wallet using one of three seed modes:
// - empty seed: generate and return a new BIP39 mnemonic
// - valid mnemonic: restore from that mnemonic and return it unchanged
// - hex string: treat it as raw master-seed bytes and return the same hex seed
func (w *Service) Create(
	ctx context.Context, password, seed string,
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
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return "", fmt.Errorf("failed to generate mnemonic: %w", err)
		}
		masterSeed = bip39.NewSeed(mnemonic, "")
	} else if bip39.IsMnemonicValid(seed) {
		mnemonic = seed
		masterSeed = bip39.NewSeed(mnemonic, "")
	} else {
		// Try hex-encoded seed
		seedBytes, err := hex.DecodeString(seed)
		if err != nil {
			return "", fmt.Errorf("invalid seed: not a valid mnemonic or hex string: %w", err)
		}
		masterSeed = seedBytes
		mnemonic = ""
	}

	netParams := toBitcoinNetwork(w.arkNetwork)

	masterKey, err := hdkeychain.NewMaster(masterSeed, &netParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	// Encrypt master key (xpriv string)
	pwd := []byte(password)
	xpriv := masterKey.String()
	encryptedKey, err := encryptAES256([]byte(xpriv), pwd)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Encrypt mnemonic if available
	var encryptedMnemonic []byte
	if mnemonic != "" {
		encryptedMnemonic, err = encryptAES256([]byte(mnemonic), pwd)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt mnemonic: %w", err)
		}
	}

	passwordSalt, err := randomBytes(passwordSaltSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate password salt: %w", err)
	}
	passwordVerifier := derivePasswordVerifier(pwd, passwordSalt)

	state := &State{
		Version:            hdWalletStateVersion,
		WalletType:         Type,
		EncryptedMasterKey: encryptedKey,
		PasswordVerifier:   passwordVerifier,
		PasswordSalt:       passwordSalt,
		EncryptedMnemonic:  encryptedMnemonic,
	}

	if err := w.store.Save(ctx, state); err != nil {
		return "", fmt.Errorf("failed to save wallet state: %w", err)
	}

	w.keyProvider, err = NewHDKeyProvider(masterKey, w.keyPathPrefix)
	if err != nil {
		return "", err
	}

	w.mnemonic = mnemonic
	w.locked = false

	returnSeed := mnemonic
	if returnSeed == "" {
		returnSeed = hex.EncodeToString(masterSeed)
	}

	return returnSeed, nil
}

func (w *Service) Lock(_ context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.keyProvider == nil {
		return nil
	}

	w.keyProvider = nil
	w.mnemonic = ""
	w.locked = true
	return nil
}

func (w *Service) Unlock(ctx context.Context, password string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.keyProvider != nil {
		return true, nil // already unlocked
	}

	state, err := w.store.Load(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to load wallet state: %w", err)
	}
	if state == nil {
		return false, fmt.Errorf("wallet not initialized")
	}

	pwd := []byte(password)
	if len(state.PasswordVerifier) == 0 || len(state.PasswordSalt) == 0 {
		return false, fmt.Errorf("wallet password verifier is missing")
	}
	currentVerifier := derivePasswordVerifier(pwd, state.PasswordSalt)
	if subtle.ConstantTimeCompare(currentVerifier, state.PasswordVerifier) != 1 {
		return false, fmt.Errorf("invalid password")
	}

	// Decrypt master key
	xprivBytes, err := decryptAES256(state.EncryptedMasterKey, pwd)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt master key: %w", err)
	}

	masterKey, err := hdkeychain.NewKeyFromString(string(xprivBytes))
	if err != nil {
		return false, fmt.Errorf("failed to parse master key: %w", err)
	}

	w.keyProvider, err = NewHDKeyProvider(masterKey, w.keyPathPrefix)
	if err != nil {
		return false, err
	}

	restored := state.OffchainNextIndex > 0
	if restored {
		if err := w.keyProvider.LoadState(*state); err != nil {
			return false, fmt.Errorf("failed to restore key state: %w", err)
		}
	}

	// Decrypt mnemonic if available
	if len(state.EncryptedMnemonic) > 0 {
		mnemonicBytes, err := decryptAES256(state.EncryptedMnemonic, pwd)
		if err == nil {
			w.mnemonic = string(mnemonicBytes)
		}
	}

	w.locked = false
	return restored, nil
}

func (w *Service) IsLocked() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.locked
}

func (w *Service) Dump(_ context.Context) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked {
		return "", fmt.Errorf("wallet is locked")
	}
	if w.mnemonic != "" {
		return w.mnemonic, nil
	}
	if w.keyProvider != nil && w.keyProvider.masterKey != nil {
		return w.keyProvider.masterKey.String(), nil
	}
	return "", fmt.Errorf("no seed available")
}

func (w *Service) NewKey(
	ctx context.Context, _ ...wallet.KeyOption,
) (*wallet.KeyRef, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.locked || w.keyProvider == nil {
		return nil, fmt.Errorf("wallet is locked")
	}

	_, pubKey, index, err := w.keyProvider.GetNextKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	if err := w.persistState(ctx); err != nil {
		return nil, err
	}

	return &wallet.KeyRef{
		Id:     w.keyProvider.DefaultKeyPath(index),
		PubKey: pubKey,
	}, nil
}

func (w *Service) GetKey(
	_ context.Context, opts ...wallet.KeyOption,
) (*wallet.KeyRef, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked || w.keyProvider == nil {
		return nil, fmt.Errorf("wallet is locked")
	}

	keyID, err := parseKeyID(opts...)
	if err != nil {
		return nil, err
	}

	index, err := parseOffchainIndex(keyID)
	if err != nil {
		return nil, err
	}

	pubKey, ok := w.keyProvider.GetDerivedPubKey(index)
	if !ok {
		if index >= w.keyProvider.GetNextKeyIndex() {
			return nil, fmt.Errorf("key %q has not been allocated", keyID)
		}

		privKey, err := w.keyProvider.DeriveKeyAtIndex(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key %q: %w", keyID, err)
		}
		w.keyProvider.CacheDerivedKey(index, privKey)
		pubKey = privKey.PubKey()
	}

	return &wallet.KeyRef{
		Id:     w.keyProvider.DefaultKeyPath(index),
		PubKey: pubKey,
	}, nil
}

func (w *Service) ListKeys(ctx context.Context) ([]wallet.KeyRef, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked || w.keyProvider == nil {
		return nil, fmt.Errorf("wallet is locked")
	}

	nextIndex := w.keyProvider.GetNextKeyIndex()
	keys := make([]wallet.KeyRef, 0, nextIndex)
	for index := uint32(0); index < nextIndex; index++ {
		pubKey, ok := w.keyProvider.GetDerivedPubKey(index)
		if !ok {
			continue
		}
		keys = append(keys, wallet.KeyRef{
			Id:     w.keyProvider.DefaultKeyPath(index),
			PubKey: pubKey,
		})
	}

	return keys, nil
}

func (w *Service) SignTransaction(
	ctx context.Context, explorerSvc explorer.Explorer, tx string, keys map[string]string,
) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked || w.keyProvider == nil {
		return "", fmt.Errorf("wallet is locked")
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse PSBT: %w", err)
	}

	updater, err := psbt.NewUpdater(ptx)
	if err != nil {
		return "", fmt.Errorf("failed to create PSBT updater: %w", err)
	}

	for i, input := range updater.Upsbt.UnsignedTx.TxIn {
		if updater.Upsbt.Inputs[i].WitnessUtxo != nil {
			continue
		}

		prevoutTxHex, err := explorerSvc.GetTxHex(input.PreviousOutPoint.Hash.String())
		if err != nil {
			return "", fmt.Errorf("failed to get prev tx: %w", err)
		}

		var prevoutTx wire.MsgTx
		prevoutReader := hex.NewDecoder(strings.NewReader(prevoutTxHex))
		if err := prevoutTx.Deserialize(prevoutReader); err != nil {
			return "", fmt.Errorf("failed to deserialize prev tx: %w", err)
		}

		if int(input.PreviousOutPoint.Index) >= len(prevoutTx.TxOut) {
			return "", fmt.Errorf(
				"prev tx output index %d out of range (have %d outputs)",
				input.PreviousOutPoint.Index, len(prevoutTx.TxOut),
			)
		}
		utxo := prevoutTx.TxOut[input.PreviousOutPoint.Index]
		if utxo == nil {
			return "", fmt.Errorf("witness utxo not found")
		}

		if err := updater.AddInWitnessUtxo(utxo, i); err != nil {
			return "", fmt.Errorf("failed to add witness utxo: %w", err)
		}
	}

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	for i, input := range updater.Upsbt.Inputs {
		outpoint := updater.Upsbt.UnsignedTx.TxIn[i].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txsighashes := txscript.NewTxSigHashes(updater.Upsbt.UnsignedTx, prevoutFetcher)

	for i, input := range ptx.Inputs {
		inputKeyID := ""
		if input.WitnessUtxo != nil {
			// We cannot skip early when this lookup misses: key-path spends may be
			// safely ignored, but tapscript spends still need to inspect their leaves
			// so we can fail if the caller omitted a required script -> key mapping.
			inputKeyID = keys[hex.EncodeToString(input.WitnessUtxo.PkScript)]
		}

		if len(input.TaprootLeafScript) > 0 {
			if err := w.signTapscriptSpend(
				updater, input, i, txsighashes, prevoutFetcher, inputKeyID, keys,
			); err != nil {
				return "", err
			}
			continue
		}

		if input.WitnessUtxo != nil && len(input.TaprootInternalKey) == 0 {
			if inputKeyID != "" {
				internalKey, err := w.internalKeyForKeyID(inputKeyID)
				if err != nil {
					return "", err
				}
				updater.Upsbt.Inputs[i].TaprootInternalKey = schnorr.SerializePubKey(internalKey)
				input = updater.Upsbt.Inputs[i]
			}
		}

		if len(input.TaprootInternalKey) > 0 {
			if err := w.signTaprootKeySpend(
				updater, input, i, txsighashes, prevoutFetcher, inputKeyID,
			); err != nil {
				return "", err
			}
			continue
		}
	}

	return ptx.B64Encode()
}

func (w *Service) signTapscriptSpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
	keyID string,
	signingKeys map[string]string,
) error {
	myPubkeys := make(map[string]*btcec.PrivateKey)

	if keyID != "" {
		priv, pub, err := w.derivedKeyForID(keyID)
		if err != nil {
			return err
		}
		myPubkeys[hex.EncodeToString(schnorr.SerializePubKey(pub))] = priv
	}

	needsWalletKey := false
	signed := false
	for _, leaf := range input.TaprootLeafScript {
		closure, err := script.DecodeClosure(leaf.Script)
		if err != nil {
			continue
		}

		var matchedPrivKey *btcec.PrivateKey
		var matchedPubKey []byte

		checkKeys := func(keys []*btcec.PublicKey) {
			for _, key := range keys {
				xonly := hex.EncodeToString(schnorr.SerializePubKey(key))
				if priv, ok := myPubkeys[xonly]; ok {
					matchedPrivKey = priv
					matchedPubKey = schnorr.SerializePubKey(key)
					return
				}
			}
		}

		switch c := closure.(type) {
		case *script.CSVMultisigClosure:
			needsWalletKey = true
			checkKeys(c.PubKeys)
		case *script.MultisigClosure:
			needsWalletKey = true
			checkKeys(c.PubKeys)
		case *script.CLTVMultisigClosure:
			needsWalletKey = true
			checkKeys(c.PubKeys)
		case *script.ConditionMultisigClosure:
			needsWalletKey = true
			checkKeys(c.PubKeys)
		}

		if matchedPrivKey != nil {
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

			sig, err := schnorr.Sign(matchedPrivKey, preimage)
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
					XOnlyPubKey: matchedPubKey,
					LeafHash:    hash.CloneBytes(),
					Signature:   sig.Serialize(),
					SigHash:     input.SighashType,
				},
			)
			signed = true
		}
	}

	// No leaf required one of our wallet keys, so this input is not ours to sign.
	if !needsWalletKey {
		return nil
	}
	// The input looks wallet-owned, but the caller did not provide script -> key ownership.
	if keyID == "" {
		scriptHex := ""
		if input.WitnessUtxo != nil {
			scriptHex = hex.EncodeToString(input.WitnessUtxo.PkScript)
		}

		return fmt.Errorf(
			"missing signing key for tapscript input %d script %s known %v",
			inputIndex,
			scriptHex,
			sampleSigningKeyScripts(signingKeys),
		)
	}
	// A key was provided, but it does not match any pubkey in the signable leaves.
	if !signed {
		return fmt.Errorf("signing key %q does not match tapscript input %d", keyID, inputIndex)
	}

	return nil
}

func sampleSigningKeyScripts(keys map[string]string) []string {
	scripts := make([]string, 0, 3)
	for script := range keys {
		scripts = append(scripts, script)
		if len(scripts) == cap(scripts) {
			break
		}
	}

	return scripts
}

func (w *Service) signTaprootKeySpend(
	updater *psbt.Updater,
	input psbt.PInput,
	inputIndex int,
	txsighashes *txscript.TxSigHashes,
	prevoutFetcher *txscript.MultiPrevOutFetcher,
	keyID string,
) error {
	if len(input.TaprootKeySpendSig) > 0 {
		return nil
	}
	if keyID == "" {
		return nil
	}

	internalKey, err := schnorr.ParsePubKey(input.TaprootInternalKey)
	if err != nil {
		return fmt.Errorf("invalid taproot internal key on input %d: %w", inputIndex, err)
	}

	var matchedPrivKey *btcec.PrivateKey

	priv, pub, err := w.derivedKeyForID(keyID)
	if err != nil {
		return err
	}

	if bytes.Equal(
		schnorr.SerializePubKey(pub),
		schnorr.SerializePubKey(internalKey),
	) {
		matchedPrivKey = priv
	}

	if matchedPrivKey == nil {
		return fmt.Errorf(
			"signing key %q does not match taproot key spend input %d",
			keyID,
			inputIndex,
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

	sig, err := schnorr.Sign(txscript.TweakTaprootPrivKey(*matchedPrivKey, nil), preimage)
	if err != nil {
		return fmt.Errorf("failed to sign taproot key spend: %w", err)
	}

	updater.Upsbt.Inputs[inputIndex].TaprootKeySpendSig = sig.Serialize()
	return nil
}

func (w *Service) derivedKeyForID(keyID string) (*btcec.PrivateKey, *btcec.PublicKey, error) {
	index, err := parseOffchainIndex(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid key id %q: %w", keyID, err)
	}

	privKey, err := w.keyProvider.DeriveKeyAtIndex(index)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key %q: %w", keyID, err)
	}

	return privKey, privKey.PubKey(), nil
}

func (w *Service) internalKeyForKeyID(keyID string) (*btcec.PublicKey, error) {
	_, pubKey, err := w.derivedKeyForID(keyID)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func (w *Service) SignMessage(_ context.Context, message []byte) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked || w.keyProvider == nil {
		return "", fmt.Errorf("wallet is locked")
	}

	privKey, err := w.keyProvider.DeriveKeyAtIndex(0)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	sig, err := schnorr.Sign(privKey, message)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	return hex.EncodeToString(sig.Serialize()), nil
}

func (w *Service) NewVtxoTreeSigner(
	_ context.Context, derivationPath string,
) (tree.SignerSession, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked || w.keyProvider == nil {
		return nil, fmt.Errorf("wallet is locked")
	}

	if len(derivationPath) == 0 {
		return nil, fmt.Errorf("derivation path is required")
	}

	masterKey := w.keyProvider.masterKey
	masterKeyPriv, err := masterKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to extract master privkey: %w", err)
	}

	bip32MasterKey, err := bip32.NewMasterKey(masterKeyPriv.Serialize())
	if err != nil {
		return nil, fmt.Errorf("failed to create bip32 master key: %w", err)
	}

	paths := strings.Split(strings.TrimPrefix(derivationPath, "m/"), "/")
	currentKey := bip32MasterKey

	for _, pathComponent := range paths {
		index := uint32(0)
		isHardened := strings.HasSuffix(pathComponent, "'")
		if isHardened {
			pathComponent = strings.TrimSuffix(pathComponent, "'")
		}

		if _, err := fmt.Sscanf(pathComponent, "%d", &index); err != nil {
			return nil, fmt.Errorf("invalid path component %s: %w", pathComponent, err)
		}

		if isHardened {
			index += bip32.FirstHardenedChild
		}

		currentKey, err = currentKey.NewChildKey(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key: %w", err)
		}
	}

	derivedPrivKey, _ := btcec.PrivKeyFromBytes(currentKey.Key)
	return tree.NewTreeSignerSession(derivedPrivKey), nil
}

// DiscoverKeys performs a full gap-limit key discovery from index 0.
func (w *Service) DiscoverKeys(ctx context.Context, gapLimit uint32) (bool, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.locked || w.keyProvider == nil {
		return false, fmt.Errorf("wallet is locked")
	}

	return w.discoverKeysFrom(ctx, gapLimit, 0)
}

func (w *Service) discoverKeysFrom(
	ctx context.Context, gapLimit, startIdx uint32,
) (bool, error) {
	if gapLimit == 0 {
		return false, fmt.Errorf("gap limit must be greater than zero")
	}

	if w.indexer == nil || w.signerPubKey == nil {
		return false, nil
	}

	type candidate struct {
		index          uint32
		boardingAddr   string
		redemptionAddr string
		onchainAddr    string
	}

	discovered := false
	for {
		candidates := make([]candidate, 0, gapLimit)
		scripts := make([]string, 0, gapLimit)
		scriptToIndex := make(map[string]uint32, gapLimit)

		for i := uint32(0); i < gapLimit; i++ {
			idx := startIdx + i
			privKey, err := w.keyProvider.DeriveKeyAtIndex(idx)
			if err != nil {
				return false, fmt.Errorf("failed to derive key at index %d: %w", idx, err)
			}

			pubKey := privKey.PubKey()
			scriptHex, err := w.computeVtxoScript(pubKey)
			if err != nil {
				return false, fmt.Errorf("failed to compute script for index %d: %w", idx, err)
			}

			boardingAddr, err := w.computeBoardingAddress(pubKey)
			if err != nil {
				return false, fmt.Errorf(
					"failed to compute boarding address for index %d: %w",
					idx,
					err,
				)
			}

			redemptionAddr, err := w.computeRedemptionAddress(pubKey)
			if err != nil {
				return false, fmt.Errorf(
					"failed to compute redemption address for index %d: %w",
					idx,
					err,
				)
			}

			onchainAddr, err := w.computeOnchainAddress(pubKey)
			if err != nil {
				return false, fmt.Errorf(
					"failed to compute onchain address for index %d: %w",
					idx,
					err,
				)
			}

			scripts = append(scripts, scriptHex)
			scriptToIndex[scriptHex] = idx
			candidates = append(candidates, candidate{
				index:          idx,
				boardingAddr:   boardingAddr,
				redemptionAddr: redemptionAddr,
				onchainAddr:    onchainAddr,
			})
		}

		matched := make(map[uint32]struct{}, gapLimit)

		// Offchain usage is discovered through the Ark indexer by matching VTXO output scripts.
		resp, err := w.indexer.GetVtxos(ctx, indexer.WithScripts(scripts))
		if err != nil {
			return false, fmt.Errorf("failed to query indexer: %w", err)
		}

		for _, vtxo := range resp.Vtxos {
			if idx, ok := scriptToIndex[vtxo.Script]; ok {
				matched[idx] = struct{}{}
			}
		}

		if w.explorer != nil {
			// Explorer-backed discovery covers Bitcoin addresses that may hold materialized
			// wallet outputs outside the indexer view, such as boarding deposits, direct
			// onchain funds, and redemption/unrolled outputs. We check transaction
			// history instead of only current UTXOs so fully spent addresses still count
			// as used and do not truncate gap-limit discovery prematurely.
			for _, candidate := range candidates {
				if _, ok := matched[candidate.index]; ok {
					continue
				}

				boardingUsed, err := w.addressHasHistory(candidate.boardingAddr)
				if err != nil {
					return false, fmt.Errorf(
						"failed to query boarding address for index %d: %w",
						candidate.index,
						err,
					)
				}
				if boardingUsed {
					matched[candidate.index] = struct{}{}
					continue
				}

				redemptionUsed, err := w.addressHasHistory(candidate.redemptionAddr)
				if err != nil {
					return false, fmt.Errorf(
						"failed to query redemption address for index %d: %w",
						candidate.index,
						err,
					)
				}
				if redemptionUsed {
					matched[candidate.index] = struct{}{}
					continue
				}

				onchainUsed, err := w.addressHasHistory(candidate.onchainAddr)
				if err != nil {
					return false, fmt.Errorf(
						"failed to query onchain address for index %d: %w",
						candidate.index,
						err,
					)
				}
				if onchainUsed {
					matched[candidate.index] = struct{}{}
				}
			}
		}

		if len(matched) == 0 {
			break
		}

		for idx := range matched {
			privKey, err := w.keyProvider.DeriveKeyAtIndex(idx)
			if err != nil {
				continue
			}
			// Discovery only caches keys once usage is confirmed so probing
			// ahead during the gap-limit scan does not mutate wallet state.
			w.keyProvider.CacheDerivedKey(idx, privKey)
			discovered = true
		}

		startIdx += gapLimit
	}

	if !discovered {
		return false, nil
	}

	return true, w.persistState(ctx)
}

func (w *Service) addressHasHistory(address string) (bool, error) {
	txs, err := w.explorer.GetTxs(address)
	if err != nil {
		return false, err
	}

	return len(txs) > 0, nil
}

func (w *Service) computeVtxoScript(
	pubKey *btcec.PublicKey,
) (string, error) {
	vtxoScript := script.NewDefaultVtxoScript(
		pubKey, w.signerPubKey, w.unilateralExitDelay,
	)

	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return "", fmt.Errorf("failed to compute vtxo tap tree: %w", err)
	}

	pkScript, err := script.P2TRScript(vtxoTapKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute P2TR script: %w", err)
	}

	return hex.EncodeToString(pkScript), nil
}

func (w *Service) computeBoardingAddress(pubKey *btcec.PublicKey) (string, error) {
	netParams := toBitcoinNetwork(w.arkNetwork)
	boardingScript := script.NewDefaultVtxoScript(
		pubKey, w.signerPubKey, w.boardingExitDelay,
	)

	boardingTapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return "", fmt.Errorf("failed to compute boarding tap tree: %w", err)
	}

	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(boardingTapKey), &netParams)
	if err != nil {
		return "", fmt.Errorf("failed to encode boarding address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

func (w *Service) computeRedemptionAddress(pubKey *btcec.PublicKey) (string, error) {
	netParams := toBitcoinNetwork(w.arkNetwork)
	vtxoScript := script.NewDefaultVtxoScript(
		pubKey, w.signerPubKey, w.unilateralExitDelay,
	)

	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return "", fmt.Errorf("failed to compute redemption tap tree: %w", err)
	}

	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(vtxoTapKey), &netParams)
	if err != nil {
		return "", fmt.Errorf("failed to encode redemption address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

func (w *Service) computeOnchainAddress(pubKey *btcec.PublicKey) (string, error) {
	netParams := toBitcoinNetwork(w.arkNetwork)
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pubKey)),
		&netParams,
	)
	if err != nil {
		return "", fmt.Errorf("failed to encode onchain address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

func (w *Service) computeOnchainPkScript(pubKey *btcec.PublicKey) ([]byte, error) {
	pkScript, err := script.P2TRScript(txscript.ComputeTaprootKeyNoScript(pubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to compute onchain pk script: %w", err)
	}

	return pkScript, nil
}

func (w *Service) persistState(ctx context.Context) error {
	if w.keyProvider == nil || w.store == nil {
		return nil
	}

	existing, err := w.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load existing state: %w", err)
	}

	if existing == nil {
		return fmt.Errorf("cannot persist state: wallet credentials missing from store")
	}

	keyState := w.keyProvider.ExportState()

	state := &State{
		Version:            hdWalletStateVersion,
		WalletType:         Type,
		OffchainNextIndex:  keyState.OffchainNextIndex,
		EncryptedMasterKey: existing.EncryptedMasterKey,
		PasswordVerifier:   existing.PasswordVerifier,
		PasswordSalt:       existing.PasswordSalt,
		EncryptedMnemonic:  existing.EncryptedMnemonic,
	}

	return w.store.Save(ctx, state)
}

// --- AES-256-GCM encryption (compatible with singlekey wallet pattern) ---

func derivePasswordVerifier(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, pbkdf2Iterations, 32, sha256.New)
}

func deriveEncryptionKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		var err error
		salt, err = randomBytes(passwordSaltSize)
		if err != nil {
			return nil, nil, err
		}
	}
	key := pbkdf2.Key(password, salt, pbkdf2Iterations, 32, sha256.New)
	return key, salt, nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
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

func toBitcoinNetwork(network arklib.Network) chaincfg.Params {
	switch network.Name {
	case arklib.Bitcoin.Name:
		return chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	case arklib.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	case arklib.BitcoinSigNet.Name:
		return chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return arklib.MutinyNetSigNetParams
	default:
		return chaincfg.MainNetParams
	}
}
