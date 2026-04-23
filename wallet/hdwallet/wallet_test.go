package hdwallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

func TestKeyDerivationDeterministic(t *testing.T) {
	masterKey := createTestMasterKey(t)
	provider, err := NewHDKeyProvider(masterKey)
	require.NoError(t, err)

	// Derive index 0 twice — must be identical
	priv1, err := provider.DeriveKeyAtIndex(0)
	if err != nil {
		t.Fatalf("failed to derive key index 0: %v", err)
	}
	priv2, err := provider.DeriveKeyAtIndex(0)
	if err != nil {
		t.Fatalf("failed to derive key index 0 again: %v", err)
	}
	if !bytes.Equal(priv1.Serialize(), priv2.Serialize()) {
		t.Fatal("same index should produce same key")
	}

	// Derive index 5 — must differ from index 0
	priv5, err := provider.DeriveKeyAtIndex(5)
	if err != nil {
		t.Fatalf("failed to derive key index 5: %v", err)
	}
	if bytes.Equal(priv1.Serialize(), priv5.Serialize()) {
		t.Fatal("different indices should produce different keys")
	}

}

func TestParseKeyPathPrefix(t *testing.T) {
	t.Run("parses canonical default path", func(t *testing.T) {
		parsed, err := parseKeyPathPrefix(defaultKeyPathPrefix)
		if err != nil {
			t.Fatalf("parseKeyPathPrefix failed: %v", err)
		}

		expected := []uint32{
			83696968 + hdkeychain.HardenedKeyStart,
			11811 + hdkeychain.HardenedKeyStart,
			0,
		}
		if len(parsed) != len(expected) {
			t.Fatalf("expected %d components, got %d", len(expected), len(parsed))
		}
		for i := range expected {
			if parsed[i] != expected[i] {
				t.Fatalf("unexpected component at %d: want %d, got %d", i, expected[i], parsed[i])
			}
		}
	})

	t.Run("parses mixed hardened and normal path", func(t *testing.T) {
		parsed, err := parseKeyPathPrefix("m/1/2'/3")
		if err != nil {
			t.Fatalf("parseKeyPathPrefix failed: %v", err)
		}

		expected := []uint32{
			1,
			2 + hdkeychain.HardenedKeyStart,
			3,
		}
		if len(parsed) != len(expected) {
			t.Fatalf("expected %d components, got %d", len(expected), len(parsed))
		}
		for i := range expected {
			if parsed[i] != expected[i] {
				t.Fatalf("unexpected component at %d: want %d, got %d", i, expected[i], parsed[i])
			}
		}
	})

	t.Run("rejects malformed input", func(t *testing.T) {
		testCases := []string{
			"",
			"m/",
			"m//1",
			"m/abc/1",
		}

		for _, path := range testCases {
			if _, err := parseKeyPathPrefix(path); err == nil {
				t.Fatalf("expected parseKeyPathPrefix(%q) to fail", path)
			}
		}
	})
}

func TestGetNextKeyAllocatesSequentialIndices(t *testing.T) {
	masterKey := createTestMasterKey(t)
	provider, err := NewHDKeyProvider(masterKey)
	require.NoError(t, err)

	// Successive allocations should give indices 0, 1, 2.
	_, _, idx0, _ := provider.GetNextKey()
	_, _, idx1, _ := provider.GetNextKey()
	_, _, idx2, _ := provider.GetNextKey()

	if idx0 != 0 || idx1 != 1 || idx2 != 2 {
		t.Fatalf("expected indices 0,1,2, got %d,%d,%d", idx0, idx1, idx2)
	}

	// nextKeyIndex should be 3
	if provider.nextKeyIndex != 3 {
		t.Fatalf("expected nextKeyIndex=3, got %d", provider.nextKeyIndex)
	}
}

func TestStateRoundTrip(t *testing.T) {
	masterKey := createTestMasterKey(t)
	provider, err := NewHDKeyProvider(masterKey)
	require.NoError(t, err)

	// Derive indices 0, 1, 2
	_, _, _, _ = provider.GetNextKey()
	_, _, _, _ = provider.GetNextKey()
	_, _, _, _ = provider.GetNextKey()

	// Export state
	state := provider.ExportState()

	// Create new provider with same master key
	provider2, err := NewHDKeyProvider(masterKey)
	require.NoError(t, err)

	if err := provider2.LoadState(state); err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	// Verify
	if provider2.nextKeyIndex != 3 {
		t.Fatalf("expected nextKeyIndex=3, got %d", provider2.nextKeyIndex)
	}

	// State is restored lazily: the known range is preserved and keys are re-derived on demand.
	for i := uint32(0); i < 3; i++ {
		pub, ok := provider2.GetDerivedPubKey(i)
		if !ok || pub == nil {
			t.Fatalf("expected key %d to be derivable after state load", i)
		}
	}
}

func TestConcurrentKeyGeneration(t *testing.T) {
	masterKey := createTestMasterKey(t)
	provider, err := NewHDKeyProvider(masterKey)
	require.NoError(t, err)

	var wg sync.WaitGroup
	count := 100
	wg.Add(count)

	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			_, _, _, err := provider.GetNextKey()
			if err != nil {
				t.Errorf("concurrent key generation failed: %v", err)
			}
		}()
	}

	wg.Wait()

	if provider.nextKeyIndex != uint32(count) {
		t.Fatalf("expected nextKeyIndex=%d, got %d", count, provider.nextKeyIndex)
	}
}

func TestGetPrivKeyForPubKey(t *testing.T) {
	masterKey := createTestMasterKey(t)
	provider, err := NewHDKeyProvider(masterKey)
	require.NoError(t, err)

	// Derive a key and cache it
	_, pub, _, err := provider.GetNextKey()
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	// Should find it
	priv, err := provider.GetPrivKeyForPubKey(pub)
	if err != nil {
		t.Fatalf("failed to find key by pubkey: %v", err)
	}
	if !bytes.Equal(priv.PubKey().SerializeCompressed(), pub.SerializeCompressed()) {
		t.Fatal("returned key does not match")
	}

	// Unknown key outside the known allocation range should fail
	unknownPriv, err := provider.DeriveKeyAtIndex(100)
	if err != nil {
		t.Fatalf("failed to derive unknown key: %v", err)
	}
	unknownPub := unknownPriv.PubKey()

	_, err = provider.GetPrivKeyForPubKey(unknownPub)
	if err == nil {
		t.Fatal("expected error for unknown pubkey")
	}
}

func TestWalletCreateAndUnlock(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()

	// Create wallet
	seed, err := svc.Create(ctx, "testpassword", "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if seed == "" {
		t.Fatal("expected non-empty seed")
	}

	// Should be unlocked after Create
	if svc.IsLocked() {
		t.Fatal("wallet should be unlocked after Create")
	}

	// Lock
	if err := svc.Lock(ctx); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	if !svc.IsLocked() {
		t.Fatal("wallet should be locked after Lock")
	}

	// Unlock
	restored, err := svc.Unlock(ctx, "testpassword")
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if restored {
		t.Fatal("should not be restored (no allocated keys)")
	}
	if svc.IsLocked() {
		t.Fatal("wallet should be unlocked after Unlock")
	}

	// Dump should return mnemonic
	dumped, err := svc.Dump(ctx)
	if err != nil {
		t.Fatalf("Dump failed: %v", err)
	}
	if dumped != seed {
		t.Fatalf("Dump mismatch: got %q, want %q", dumped, seed)
	}
}

func TestWalletCreateFromMnemonic(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()

	seed, err := svc.Create(ctx, "testpassword", testMnemonic)
	if err != nil {
		t.Fatalf("Create from mnemonic failed: %v", err)
	}
	if seed != testMnemonic {
		t.Fatalf("expected mnemonic back, got %q", seed)
	}
}

func TestWalletNewKeyAlwaysFresh(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()

	_, err := svc.Create(ctx, "testpassword", testMnemonic)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	first, err := svc.NewKey(ctx)
	if err != nil {
		t.Fatalf("first NewKey failed: %v", err)
	}

	second, err := svc.NewKey(ctx)
	if err != nil {
		t.Fatalf("second NewKey failed: %v", err)
	}

	if first.Id == second.Id {
		t.Fatalf("expected fresh key ids, got %q twice", first.Id)
	}

	if bytes.Equal(first.PubKey.SerializeCompressed(), second.PubKey.SerializeCompressed()) {
		t.Fatal("expected fresh pubkeys on successive NewKey calls")
	}

	keys, err := svc.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 allocated keys, got %d", len(keys))
	}

	if keys[0].Id != first.Id || keys[1].Id != second.Id {
		t.Fatalf("unexpected listed key ids: got %q, %q", keys[0].Id, keys[1].Id)
	}
}

func TestWalletGetKeyByDerivationPath(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()

	_, err := svc.Create(ctx, "testpassword", testMnemonic)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	allocated, err := svc.NewKey(ctx)
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}

	resolved, err := svc.GetKey(ctx, WithDerivationPath(allocated.Id))
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if resolved.Id != allocated.Id {
		t.Fatalf("expected key id %q, got %q", allocated.Id, resolved.Id)
	}

	if !bytes.Equal(
		resolved.PubKey.SerializeCompressed(),
		allocated.PubKey.SerializeCompressed(),
	) {
		t.Fatal("resolved pubkey does not match allocated key")
	}

	if _, err := svc.GetKey(ctx); err == nil {
		t.Fatal("expected missing key id error")
	}
}

func TestSignMessageUsesFixedKeyWithoutAllocating(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()

	_, err := svc.Create(ctx, "testpassword", testMnemonic)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	msg := make([]byte, 32)
	copy(msg, []byte("hello"))

	sig1, err := svc.SignMessage(ctx, msg)
	if err != nil {
		t.Fatalf("first SignMessage failed: %v", err)
	}
	sig2, err := svc.SignMessage(ctx, msg)
	if err != nil {
		t.Fatalf("second SignMessage failed: %v", err)
	}

	if sig1 != sig2 {
		t.Fatal("expected deterministic signatures from the fixed signing key")
	}

	keys, err := svc.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected SignMessage not to allocate keys, got %d", len(keys))
	}
}

func TestDiscoverKeysRecoversUsedKeysAcrossGapWithinLimit(t *testing.T) {
	svc, idx, _ := newRecoveryTestWallet(t)

	first := vtxoForIndex(t, svc, 0)
	gapped := vtxoForIndex(t, svc, 3)
	idx.vtxosByScript[first.Script] = first
	idx.vtxosByScript[gapped.Script] = gapped

	expanded, err := svc.DiscoverKeys(context.Background(), 2)
	if err != nil {
		t.Fatalf("DiscoverKeys failed: %v", err)
	}
	if !expanded {
		t.Fatal("expected discovery to expand the known key set")
	}

	keys, err := svc.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("expected recovered key range to extend through index 3, got %d keys", len(keys))
	}
	if keys[0].Id != svc.keyProvider.DefaultKeyPath(0) ||
		keys[len(keys)-1].Id != svc.keyProvider.DefaultKeyPath(3) {
		t.Fatalf(
			"unexpected discovered key ids: first=%q last=%q",
			keys[0].Id,
			keys[len(keys)-1].Id,
		)
	}
	if len(idx.scriptQueries) != 3 {
		t.Fatalf("expected 3 discovery windows, got %d", len(idx.scriptQueries))
	}
}

func TestDiscoverKeysStopsWhenGapLimitExceeded(t *testing.T) {
	svc, idx, _ := newRecoveryTestWallet(t)

	first := vtxoForIndex(t, svc, 0)
	tooFar := vtxoForIndex(t, svc, 4)
	idx.vtxosByScript[first.Script] = first
	idx.vtxosByScript[tooFar.Script] = tooFar

	expanded, err := svc.DiscoverKeys(context.Background(), 2)
	if err != nil {
		t.Fatalf("DiscoverKeys failed: %v", err)
	}
	if !expanded {
		t.Fatal("expected discovery to find the first funded key")
	}

	keys, err := svc.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected only the first key to be discovered, got %d", len(keys))
	}
	if keys[0].Id != svc.keyProvider.DefaultKeyPath(0) {
		t.Fatalf("unexpected discovered key id %q", keys[0].Id)
	}
	if len(idx.scriptQueries) != 2 {
		t.Fatalf(
			"expected discovery to stop after the first empty window, got %d queries",
			len(idx.scriptQueries),
		)
	}
}

func TestDiscoverKeysRecoversBoardingRedemptionAndOnchainUsage(t *testing.T) {
	svc, idx, exp := newRecoveryTestWallet(t)

	boardingPriv, err := svc.keyProvider.DeriveKeyAtIndex(0)
	if err != nil {
		t.Fatalf("failed to derive boarding key: %v", err)
	}
	boardingAddr, err := svc.computeBoardingAddress(boardingPriv.PubKey())
	if err != nil {
		t.Fatalf("failed to compute boarding address: %v", err)
	}
	exp.utxosByAddress[boardingAddr] = []explorer.Utxo{
		{Txid: "boarding-tx", Vout: 0, Amount: 1_000},
	}

	redemptionPriv, err := svc.keyProvider.DeriveKeyAtIndex(2)
	if err != nil {
		t.Fatalf("failed to derive redemption key: %v", err)
	}
	redemptionAddr, err := svc.computeRedemptionAddress(redemptionPriv.PubKey())
	if err != nil {
		t.Fatalf("failed to compute redemption address: %v", err)
	}
	exp.utxosByAddress[redemptionAddr] = []explorer.Utxo{
		{Txid: "redemption-tx", Vout: 0, Amount: 1_000},
	}

	onchainPriv, err := svc.keyProvider.DeriveKeyAtIndex(4)
	if err != nil {
		t.Fatalf("failed to derive onchain key: %v", err)
	}
	onchainAddr, err := svc.computeOnchainAddress(onchainPriv.PubKey())
	if err != nil {
		t.Fatalf("failed to compute onchain address: %v", err)
	}
	exp.utxosByAddress[onchainAddr] = []explorer.Utxo{{Txid: "onchain-tx", Vout: 0, Amount: 1_000}}

	expanded, err := svc.DiscoverKeys(context.Background(), 2)
	if err != nil {
		t.Fatalf("DiscoverKeys failed: %v", err)
	}
	if !expanded {
		t.Fatal("expected discovery to find address activity")
	}

	keys, err := svc.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("expected recovered key range to extend through index 4, got %d keys", len(keys))
	}
	if len(idx.scriptQueries) != 4 {
		t.Fatalf("expected 4 offchain discovery windows, got %d", len(idx.scriptQueries))
	}
}

func TestDiscoverKeysFailsWhenLocked(t *testing.T) {
	svc, _, _ := newRecoveryTestWallet(t)

	ctx := context.Background()
	if err := svc.Lock(ctx); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	expanded, err := svc.DiscoverKeys(ctx, 2)
	if err == nil {
		t.Fatal("expected DiscoverKeys to fail for locked wallet")
	}
	if expanded {
		t.Fatal("expected locked wallet discovery to report no expansion")
	}
}

func TestSignTransactionDetectsOwnedOnchainTaprootInput(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()
	_, err := svc.Create(ctx, "testpassword", testMnemonic)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	key, err := svc.NewKey(ctx)
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}

	onchainPkScript, err := svc.computeOnchainPkScript(key.PubKey)
	if err != nil {
		t.Fatalf("failed to compute onchain script: %v", err)
	}

	packet, err := psbt.New(
		[]*wire.OutPoint{{
			Hash:  chainhash.Hash{},
			Index: 0,
		}},
		[]*wire.TxOut{{
			Value:    500,
			PkScript: []byte{txscript.OP_TRUE},
		}},
		2,
		0,
		[]uint32{uint32(txscript.SigHashDefault)},
	)
	if err != nil {
		t.Fatalf("failed to create psbt: %v", err)
	}

	packet.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    1000,
		PkScript: onchainPkScript,
	}

	encoded, err := packet.B64Encode()
	if err != nil {
		t.Fatalf("failed to encode psbt: %v", err)
	}

	signed, err := svc.SignTransaction(ctx, nil, encoded, map[string]string{
		hex.EncodeToString(onchainPkScript): key.Id,
	})
	if err != nil {
		t.Fatalf("SignTransaction failed: %v", err)
	}

	parsed, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		t.Fatalf("failed to parse signed psbt: %v", err)
	}

	if len(parsed.Inputs[0].TaprootKeySpendSig) == 0 {
		t.Fatal("expected taproot key spend signature to be added")
	}

	if len(parsed.Inputs[0].TaprootInternalKey) == 0 {
		t.Fatal("expected taproot internal key to be populated")
	}

	expectedTaprootKey := schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(key.PubKey))
	if hex.EncodeToString(
		parsed.Inputs[0].TaprootInternalKey,
	) != hex.EncodeToString(
		expectedTaprootKey,
	) {
		t.Fatal("unexpected taproot internal key")
	}
}

func TestSignTransactionDoesNotFallbackToKeyScan(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()
	_, err := svc.Create(ctx, "testpassword", testMnemonic)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	key, err := svc.NewKey(ctx)
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}

	onchainPkScript, err := svc.computeOnchainPkScript(key.PubKey)
	if err != nil {
		t.Fatalf("failed to compute onchain script: %v", err)
	}

	packet, err := psbt.New(
		[]*wire.OutPoint{{
			Hash:  chainhash.Hash{},
			Index: 0,
		}},
		[]*wire.TxOut{{
			Value:    500,
			PkScript: []byte{txscript.OP_TRUE},
		}},
		2,
		0,
		[]uint32{uint32(txscript.SigHashDefault)},
	)
	if err != nil {
		t.Fatalf("failed to create psbt: %v", err)
	}

	packet.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    1000,
		PkScript: onchainPkScript,
	}

	encoded, err := packet.B64Encode()
	if err != nil {
		t.Fatalf("failed to encode psbt: %v", err)
	}

	signed, err := svc.SignTransaction(ctx, nil, encoded, nil)
	if err != nil {
		t.Fatalf("SignTransaction failed: %v", err)
	}

	parsed, err := psbt.NewFromRawBytes(strings.NewReader(signed), true)
	if err != nil {
		t.Fatalf("failed to parse signed psbt: %v", err)
	}

	if len(parsed.Inputs[0].TaprootKeySpendSig) != 0 {
		t.Fatal("expected no taproot key spend signature without provided key map")
	}

	if len(parsed.Inputs[0].TaprootInternalKey) != 0 {
		t.Fatal("expected no taproot internal key without provided key map")
	}

	signedWithKeyMap, err := svc.SignTransaction(ctx, nil, encoded, map[string]string{
		hex.EncodeToString(onchainPkScript): key.Id,
	})
	if err != nil {
		t.Fatalf("SignTransaction with key map failed: %v", err)
	}

	parsedWithKeyMap, err := psbt.NewFromRawBytes(strings.NewReader(signedWithKeyMap), true)
	if err != nil {
		t.Fatalf("failed to parse signed psbt with key map: %v", err)
	}

	if len(parsedWithKeyMap.Inputs[0].TaprootKeySpendSig) == 0 {
		t.Fatal("expected taproot key spend signature with provided key map")
	}

	if len(parsedWithKeyMap.Inputs[0].TaprootInternalKey) == 0 {
		t.Fatal("expected taproot internal key with provided key map")
	}
}

func TestWalletWrongPassword(t *testing.T) {
	store := NewInMemoryStore()
	svc := newTestHDWalletService(t, store)

	ctx := context.Background()
	_, err := svc.Create(ctx, "correct", "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := svc.Lock(ctx); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	_, err = svc.Unlock(ctx, "wrong")
	if err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("test secret data")
	password := []byte("mypassword")

	encrypted, err := encryptAES256(plaintext, password)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptAES256(encrypted, password)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted data does not match plaintext")
	}
}

func TestDecryptRejectsShortInput(t *testing.T) {
	_, err := decryptAES256([]byte("short"), []byte("mypassword"))
	if err == nil {
		t.Fatal("expected short encrypted payload to fail")
	}
}

func TestToBitcoinNetworkHandlesMutinyNet(t *testing.T) {
	params := toBitcoinNetwork(arklib.BitcoinMutinyNet)
	if params.TargetTimePerBlock != arklib.MutinyNetSigNetParams.TargetTimePerBlock {
		t.Fatalf(
			"expected mutinynet block time %s, got %s",
			arklib.MutinyNetSigNetParams.TargetTimePerBlock,
			params.TargetTimePerBlock,
		)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	state := &State{
		WalletType:        "hd",
		OffchainNextIndex: 5,
	}

	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded state is nil")
	}

	if loaded.OffchainNextIndex != 5 {
		t.Fatalf("expected persisted next index=5, got %d", loaded.OffchainNextIndex)
	}
}

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

type fakeIndexer struct {
	vtxosByScript map[string]clientTypes.Vtxo
	scriptQueries [][]string
}

type fakeExplorer struct {
	txsByAddress   map[string][]explorer.Tx
	utxosByAddress map[string][]explorer.Utxo
}

func (f *fakeIndexer) GetVtxos(
	_ context.Context,
	opts ...indexer.GetVtxosOption,
) (*indexer.VtxosResponse, error) {
	parsed, err := indexer.ApplyGetVtxosOptions(opts...)
	if err != nil {
		return nil, err
	}

	if len(parsed.Scripts) > 0 {
		query := append([]string(nil), parsed.Scripts...)
		f.scriptQueries = append(f.scriptQueries, query)
	}

	resp := &indexer.VtxosResponse{Vtxos: make([]clientTypes.Vtxo, 0)}
	for _, script := range parsed.Scripts {
		if vtxo, ok := f.vtxosByScript[script]; ok {
			resp.Vtxos = append(resp.Vtxos, vtxo)
		}
	}

	return resp, nil
}

func (f *fakeIndexer) GetCommitmentTx(context.Context, string) (*indexer.CommitmentTx, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetVtxoTree(
	context.Context,
	clientTypes.Outpoint,
	...indexer.PageOption,
) (*indexer.VtxoTreeResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetFullVtxoTree(
	context.Context,
	clientTypes.Outpoint,
	...indexer.PageOption,
) ([]tree.TxTreeNode, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetVtxoTreeLeaves(
	context.Context,
	clientTypes.Outpoint,
	...indexer.PageOption,
) (*indexer.VtxoTreeLeavesResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetForfeitTxs(
	context.Context,
	string,
	...indexer.PageOption,
) (*indexer.ForfeitTxsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetConnectors(
	context.Context,
	string,
	...indexer.PageOption,
) (*indexer.ConnectorsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetVtxoChain(
	context.Context,
	clientTypes.Outpoint,
	...indexer.PageOption,
) (*indexer.VtxoChainResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetVirtualTxs(
	context.Context,
	[]string,
	...indexer.PageOption,
) (*indexer.VirtualTxsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetBatchSweepTxs(context.Context, clientTypes.Outpoint) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) SubscribeForScripts(context.Context, string, []string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (f *fakeIndexer) UnsubscribeForScripts(context.Context, string, []string) error {
	return fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetSubscription(
	context.Context,
	string,
) (<-chan indexer.ScriptEvent, func(), error) {
	return nil, func() {}, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) GetAsset(context.Context, string) (*indexer.AssetInfo, error) {
	return &indexer.AssetInfo{Metadata: []asset.Metadata{}}, fmt.Errorf("not implemented")
}

func (f *fakeIndexer) Close() {}

func (f *fakeExplorer) Start() {}

func (f *fakeExplorer) GetTxHex(string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (f *fakeExplorer) Broadcast(...string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (f *fakeExplorer) GetTxs(addr string) ([]explorer.Tx, error) {
	return append([]explorer.Tx(nil), f.txsByAddress[addr]...), nil
}

func (f *fakeExplorer) GetTxOutspends(string) ([]explorer.SpentStatus, error) {
	return nil, fmt.Errorf("not implemented")
}

func (f *fakeExplorer) GetUtxos(addr string) ([]explorer.Utxo, error) {
	return append([]explorer.Utxo(nil), f.utxosByAddress[addr]...), nil
}

func (f *fakeExplorer) GetRedeemedVtxosBalance(
	string,
	arklib.RelativeLocktime,
) (uint64, map[int64]uint64, error) {
	return 0, nil, fmt.Errorf("not implemented")
}

func (f *fakeExplorer) GetTxBlockTime(string) (bool, int64, error) {
	return false, 0, fmt.Errorf("not implemented")
}

func (f *fakeExplorer) BaseUrl() string {
	return ""
}

func (f *fakeExplorer) GetFeeRate() (float64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (f *fakeExplorer) GetConnectionCount() int {
	return 0
}

func (f *fakeExplorer) GetSubscribedAddresses() []string {
	return nil
}

func (f *fakeExplorer) IsAddressSubscribed(string) bool {
	return false
}

func (f *fakeExplorer) GetAddressesEvents() <-chan clientTypes.OnchainAddressEvent {
	return nil
}

func (f *fakeExplorer) SubscribeForAddresses([]string) error {
	return fmt.Errorf("not implemented")
}

func (f *fakeExplorer) UnsubscribeForAddresses([]string) error {
	return fmt.Errorf("not implemented")
}

func (f *fakeExplorer) Stop() {}

func createTestMasterKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()
	seed := bip39.NewSeed(testMnemonic, "")
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("failed to create master key: %v", err)
	}
	return masterKey
}

func newTestHDWalletService(t *testing.T, store Store) *Service {
	t.Helper()

	svc, err := NewService(Args{
		Store:      store,
		ArkNetwork: arklib.BitcoinRegTest,
	})
	if err != nil {
		t.Fatalf("NewHDWalletService failed: %v", err)
	}

	return svc
}

func newRecoveryTestWallet(t *testing.T) (*Service, *fakeIndexer, *fakeExplorer) {
	t.Helper()

	store := NewInMemoryStore()

	signerSeed := make([]byte, 32)
	signerSeed[31] = 1
	signerPriv, _ := btcec.PrivKeyFromBytes(signerSeed)

	idx := &fakeIndexer{
		vtxosByScript: make(map[string]clientTypes.Vtxo),
	}
	exp := &fakeExplorer{
		txsByAddress:   make(map[string][]explorer.Tx),
		utxosByAddress: make(map[string][]explorer.Utxo),
	}

	svc, err := NewService(Args{
		Store:               store,
		Indexer:             idx,
		Explorer:            exp,
		ArkNetwork:          arklib.BitcoinRegTest,
		SignerPubKey:        signerPriv.PubKey(),
		BoardingExitDelay:   arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
		UnilateralExitDelay: arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	})
	if err != nil {
		t.Fatalf("NewHDWalletService failed: %v", err)
	}

	if _, err := svc.Create(context.Background(), "testpassword", testMnemonic); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	return svc, idx, exp
}

func vtxoForIndex(
	t *testing.T, svc *Service, index uint32,
) clientTypes.Vtxo {
	t.Helper()

	privKey, err := svc.keyProvider.DeriveKeyAtIndex(index)
	if err != nil {
		t.Fatalf("failed to derive key %d: %v", index, err)
	}

	scriptHex, err := svc.computeVtxoScript(privKey.PubKey())
	if err != nil {
		t.Fatalf("failed to compute script for %d: %v", index, err)
	}

	return clientTypes.Vtxo{
		Outpoint: clientTypes.Outpoint{
			Txid: fmt.Sprintf("tx-%d", index),
			VOut: 0,
		},
		Script: scriptHex,
		Amount: 1_000,
	}
}
