// Package identity provides an HD (BIP32/BIP86) implementation of the
// upstream client-lib identity.Identity interface, backed by a pluggable
// IdentityStore for persistence. It's what the SDK uses by default to
// derive keys, sign transactions, and persist encrypted seed material.
//
// # Components
//
//   - service (unexported, returned via [NewIdentity] as
//     client-lib/identity.Identity) — the HD identity itself. Owns the
//     locked/unlocked lifecycle, holds the decrypted mnemonic in memory
//     while unlocked, and dispatches to keyService for derivation.
//
//   - keyService (unexported, see key_service.go) — the BIP32 derivation
//     workhorse. Given the master extended key and an account root, it
//     produces sequential KeyRefs (Id is a derivation-path string,
//     PubKey is the schnorr pubkey at that path). NextKeyId, GetKeyIndex,
//     and DeriveKeyAt are pure path math; GetNextKey advances the
//     persisted NextIndex counter, returning the next unused key.
//
//   - IdentityStore (see identity/store/store.go) — the persistence
//     surface. Stores an [IdentityData] record holding the encrypted
//     extended key, the encrypted mnemonic, and the NextIndex counter.
//     Two backends ship in this repo: identity/store/file (BadgerDB on
//     disk) and identity/store/inmemory (process-local, for tests).
//
// # Lifecycle
//
// A fresh identity starts uninitialized:
//
//  1. [Identity.Create] either generates a new BIP39 mnemonic or restores
//     from a caller-provided one, derives the master xprv at the BIP86
//     account root for the given network, encrypts both with the
//     password using AES-256-GCM, and persists them via IdentityStore.
//     The identity is left locked afterwards.
//  2. [Identity.Unlock] decrypts the seed material and instantiates the
//     keyService. Returns true if the identity had already been unlocked
//     before — useful for clients that want to noop on repeat unlocks.
//  3. [Identity.Lock] drops the in-memory keyService and zeroes the
//     mnemonic bytes (see Lock's comment in identity.go for the wipe
//     ordering). The persisted state is untouched, so a later Unlock
//     restores access.
//  4. [Identity.Dump] returns the plaintext mnemonic — only callable on
//     an unlocked identity. Intended for the wallet's "export seed"
//     flow.
//
// # Key derivation
//
//   - All keys are derived under the BIP86 account root for the
//     configured network (see utils.go: getBIP86RootPath).
//   - KeyRef.Id is the derivation path tail, suitable for round-tripping
//     through NextKeyId / GetKeyIndex / GetKey without the caller needing
//     to know the BIP86 prefix.
//   - The empty string ("") is the "before-first-key" sentinel:
//     NextKeyId("") returns the first key id, GetKeyIndex("") returns 0.
//     This lets the contract manager's gap-limit scan walk the address
//     space starting from a fresh wallet without special-casing the
//     empty-store branch.
//
// # Signing
//
// [Identity.SignTransaction] accepts a base64 PSBT and a map of
// script → keyId, signing each input whose script matches the caller's
// expected key. Tapscript spends use the per-leaf schnorr signature
// path; taproot keyspends use the tweaked key. See signTapscriptSpend
// and signTaprootKeySpend in identity.go for the per-mode logic.
//
// [Identity.SignMessage] schnorr-signs a raw message hash with the
// account's first key. [Identity.NewVtxoTreeSigner] returns a
// short-lived signer session compatible with arkd's VTXO tree musig2
// flow.
//
// # Concurrency
//
// All public methods on the service are guarded by a single
// [sync.RWMutex]. Lookups (IsLocked, GetType, GetKey, GetKeyIndex,
// NextKeyId, ListKeys, signing operations) hold the read lock; mutations
// (Create, Unlock, Lock, NewKey) hold the write lock. The keyService is
// internally lock-free — concurrent reads are safe because it's
// constructed under the service's write lock on Unlock.
//
// # Security notes
//
//   - Seed material is encrypted with AES-256-GCM at rest; the password
//     is stretched via scrypt with a per-record salt (see utils.go:
//     deriveEncryptionKey). A wrong password surfaces as an AEAD tag
//     failure on Unlock.
//   - Lock zeroes the in-memory mnemonic byte buffer. It can't zero
//     intermediate copies the runtime may have made (encryption inputs,
//     etc.) — for callers that need stronger memory guarantees, restart
//     the process.
package identity
