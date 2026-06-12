package arksdk

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

// signerState classifies one signer key relative to the current signer set.
type signerState int

const (
	// signerActive is the current server signer (no action needed).
	signerActive signerState = iota
	// signerToMigrate is a deprecated key whose cutoff is in the future
	// (including keys with no cutoff). Vtxos under this key are settled onto
	// current-signer outputs via reconcileDeprecatedSigners.
	signerToMigrate
	// signerExpired is a deprecated key past its cutoff: the server refuses to
	// co-sign, so its vtxos are unilateral-exit-only. Never attempt a
	// collaborative settle for these.
	signerExpired
	// signerUnknown is internal-only: a stored contract whose signer is neither
	// the current signer nor any advertised deprecated key. It is logged as a
	// warning and NOT counted in any exported field.
	signerUnknown
)

// DeprecatedSignerStatus summarizes the wallet's exposure to signer rotation.
// Callers (e.g. fulmine) can surface it to users. Counts are over spendable
// vtxos grouped by the state of the signer their contract commits to.
type DeprecatedSignerStatus struct {
	// Active is the number of spendable vtxos under the current signer.
	Active int
	// ToMigrate is the number under a deprecated signer that can still be
	// settled collaboratively (cutoff in future, or no cutoff).
	ToMigrate int
	// Expired is the number under a past-cutoff signer (unilateral-exit-only).
	Expired int
	// NearestCutoff is the earliest non-zero cutoff among deprecated signers
	// that still hold spendable vtxos; zero if none.
	NearestCutoff time.Time
	// AmountAtRisk is the total satoshi value under ToMigrate + Expired vtxos.
	AmountAtRisk uint64
	// Migrated reports whether this reconcile actually submitted a Settle to
	// migrate ToMigrate vtxos onto current-signer outputs.
	Migrated bool
}

// classifySigner maps a signer x-only hex to its state given the current signer
// and the deprecated set, using `now` for the cutoff threshold. Deprecated keys
// with a future (or zero) cutoff are signerToMigrate; past-cutoff keys are
// signerExpired. A signer in neither set returns signerUnknown, which callers
// treat as "log and skip" (it is never counted in DeprecatedSignerStatus).
func classifySigner(
	signerHex, currentHex string,
	deprecated map[string]client.DeprecatedSigner,
	now time.Time,
) (signerState, int64) {
	if signerHex == currentHex {
		return signerActive, 0
	}
	d, ok := deprecated[signerHex]
	if !ok {
		return signerUnknown, 0
	}
	// cutoffDate == 0 means "no cutoff": always migratable, never expires.
	if d.CutoffDate == 0 {
		return signerToMigrate, 0
	}
	cutoff := time.Unix(d.CutoffDate, 0)
	if now.After(cutoff) {
		return signerExpired, d.CutoffDate
	}
	return signerToMigrate, d.CutoffDate
}

// deprecatedSignerSet builds an x-only-keyed map of the advertised deprecated
// signers, plus the current signer's x-only hex. Malformed entries are skipped
// with a warning so a bad server response can never break reconciliation.
func deprecatedSignerSet(
	info *client.Info,
) (currentHex string, set map[string]client.DeprecatedSigner) {
	set = make(map[string]client.DeprecatedSigner, len(info.DeprecatedSignerPubKeys))
	if cur, err := normalizeSignerHex(info.SignerPubKey); err == nil {
		currentHex = cur
	} else {
		log.Warnf("reconcile: skipping malformed current signer %q: %v", info.SignerPubKey, err)
	}
	for _, d := range info.DeprecatedSignerPubKeys {
		xOnly, err := normalizeSignerHex(d.PubKey)
		if err != nil {
			log.Warnf("reconcile: skipping malformed deprecated signer %q: %v", d.PubKey, err)
			continue
		}
		if xOnly == currentHex {
			// A deprecated entry equal to the current key is a no-op.
			continue
		}
		set[xOnly] = client.DeprecatedSigner{PubKey: xOnly, CutoffDate: d.CutoffDate}
	}
	return currentHex, set
}

// normalizeSignerHex parses a (compressed or x-only) pubkey hex and returns its
// canonical 32-byte x-only hex.
func normalizeSignerHex(h string) (string, error) {
	buf, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	key, err := btcec.ParsePubKey(buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(schnorr.SerializePubKey(key)), nil
}

// signerSetDigest returns a stable representation of the full signer set
// (current + deprecated), so a live rotation can be detected by comparing
// digests across refreshes.
func signerSetDigest(info *client.Info) string {
	parts := make([]string, 0, 1+len(info.DeprecatedSignerPubKeys))
	if cur, err := normalizeSignerHex(info.SignerPubKey); err == nil {
		parts = append(parts, "cur:"+cur)
	}
	for _, d := range info.DeprecatedSignerPubKeys {
		if xOnly, err := normalizeSignerHex(d.PubKey); err == nil {
			parts = append(parts, xOnly)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// reconcileDeprecatedSigners classifies the wallet's spendable vtxos by the
// state of the server signer their contract commits to, and migrates the
// actionable (dueNow) ones onto current-signer outputs via Settle. It never
// blocks the caller on a migration failure: errors are logged and surfaced,
// not propagated as hard failures (so Unlock survives a failed migration).
//
// Locking: contracts are read under w.dbMu, then the lock is released before
// Settle (which takes w.dbMu internally). The lock is never held across Settle.
func (w *wallet) reconcileDeprecatedSigners(ctx context.Context) (DeprecatedSignerStatus, error) {
	var status DeprecatedSignerStatus

	if w.contractManager == nil {
		return status, nil
	}

	info, err := w.Client().GetInfo(ctx)
	if err != nil {
		return status, err
	}
	currentHex, deprecated := deprecatedSignerSet(info)

	// Fast path: no deprecated signers advertised → nothing to reconcile.
	if len(deprecated) == 0 {
		return status, nil
	}

	// Read spendable/recoverable vtxos and the contracts backing them under the
	// db lock, then release before any Settle.
	w.dbMu.Lock()
	spendable, err := w.store.VtxoStore().GetSpendableOrRecoverableVtxos(ctx)
	w.dbMu.Unlock()
	if err != nil {
		return status, err
	}
	if len(spendable) == 0 {
		return status, nil
	}

	scripts := make([]string, 0, len(spendable))
	for _, v := range spendable {
		scripts = append(scripts, v.Script)
	}
	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return status, err
	}
	signerByScript := signerKeysByScript(ctx, w, contracts)

	now := time.Now()
	var hasToMigrate bool
	for _, v := range spendable {
		sHex, ok := signerByScript[v.Script]
		if !ok {
			// No contract maps this vtxo's script; skip (a foreign or
			// not-yet-discovered script). Discovery (Item A) is responsible for
			// persisting the contract before reconcile runs.
			continue
		}
		state, cutoff := classifySigner(sHex, currentHex, deprecated, now)
		switch state {
		case signerActive:
			status.Active++
		case signerToMigrate:
			status.ToMigrate++
			status.AmountAtRisk += v.Amount
			hasToMigrate = true
			updateNearestCutoff(&status, cutoff)
		case signerExpired:
			status.Expired++
			status.AmountAtRisk += v.Amount
			log.Warnf(
				"reconcile: vtxo %s under expired signer %s is exit-only (past cutoff)",
				v.Script, sHex,
			)
			updateNearestCutoff(&status, cutoff)
		case signerUnknown:
			// Unknown signers are log-only (FR-EXT1-1): never counted, never
			// settled.
			log.Warnf(
				"reconcile: vtxo %s under unknown signer %s (neither current nor deprecated)",
				v.Script, sHex,
			)
		}
	}

	// Migrate the actionable (ToMigrate) vtxos via a subset settle: only the
	// ToMigrate vtxos are passed as inputs, and the change/receiver output
	// commits to the current signer (newOffchainAddress), honoring arkd #822.
	// Expired vtxos are excluded (exit-only); Active vtxos are left untouched.
	// It is idempotent across runs: once migrated, those vtxos are spent and a
	// re-run finds no ToMigrate entries (EC-12, EC-14).
	if hasToMigrate {
		toMigrateVtxos := collectToMigrateVtxos(
			spendable, signerByScript, currentHex, deprecated, now,
		)
		if skipMigrationSettle(toMigrateVtxos) {
			// Defensive guard: hasToMigrate was set above, so collectToMigrateVtxos
			// should return a non-empty subset. If it does not (e.g. a
			// classification/derivation mismatch), skip Settle entirely:
			// WithSettleVtxos(nil) falls back to a FULL settle of every spendable
			// vtxo, which would migrate Active and Expired vtxos too — exactly what
			// the subset settle is designed to avoid. Log and return the status.
			log.Warn(
				"reconcile: classified ToMigrate vtxos but collected an empty " +
					"subset; skipping settle to avoid an accidental full-settle fallback",
			)
			return status, nil
		}
		if _, err := w.Settle(ctx, WithSettleVtxos(toMigrateVtxos)); err != nil {
			// Do not fail the caller (Unlock) on a migration error — log and
			// surface via the returned status.
			log.WithError(err).Warn("reconcile: failed to migrate deprecated-signer vtxos")
			return status, err
		}
		status.Migrated = true
		log.Infof(
			"reconcile: settled %d ToMigrate vtxo(s) onto current-signer outputs",
			len(toMigrateVtxos),
		)
	}

	return status, nil
}

// skipMigrationSettle reports whether the migration Settle must be skipped
// because the collected ToMigrate subset is empty. Passing an empty/nil slice
// to WithSettleVtxos triggers a FULL settle of every spendable vtxo (the
// no-op-options fallback), which would sweep Active and Expired vtxos the subset
// settle is meant to exclude — so an empty subset must never reach Settle.
func skipMigrationSettle(toMigrate []clienttypes.Vtxo) bool {
	return len(toMigrate) == 0
}

// collectToMigrateVtxos returns the subset of spendable vtxos classified as
// signerToMigrate. Used by reconcileDeprecatedSigners to build the
// WithSettleVtxos argument so only the actionable vtxos are included in the
// settlement (Expired and Active vtxos are excluded).
func collectToMigrateVtxos(
	spendable []clienttypes.Vtxo,
	signerByScript map[string]string,
	currentHex string,
	deprecated map[string]client.DeprecatedSigner,
	now time.Time,
) []clienttypes.Vtxo {
	var result []clienttypes.Vtxo
	for _, v := range spendable {
		sHex, ok := signerByScript[v.Script]
		if !ok {
			continue
		}
		state, _ := classifySigner(sHex, currentHex, deprecated, now)
		if state == signerToMigrate {
			result = append(result, v)
		}
	}
	return result
}

func updateNearestCutoff(status *DeprecatedSignerStatus, cutoff int64) {
	if cutoff == 0 {
		return
	}
	t := time.Unix(cutoff, 0)
	if status.NearestCutoff.IsZero() || t.Before(status.NearestCutoff) {
		status.NearestCutoff = t
	}
}

// DeprecatedSignerSummary classifies the wallet's spendable vtxos by signer
// state WITHOUT triggering any migration. Exposed so callers can surface
// rotation exposure (counts, nearest cutoff, amount at risk) to the user.
func (w *wallet) DeprecatedSignerSummary(
	ctx context.Context,
) (DeprecatedSignerStatus, error) {
	var status DeprecatedSignerStatus
	if w.contractManager == nil {
		return status, nil
	}

	info, err := w.Client().GetInfo(ctx)
	if err != nil {
		return status, err
	}
	currentHex, deprecated := deprecatedSignerSet(info)
	if len(deprecated) == 0 {
		return status, nil
	}

	w.dbMu.Lock()
	spendable, err := w.store.VtxoStore().GetSpendableOrRecoverableVtxos(ctx)
	w.dbMu.Unlock()
	if err != nil {
		return status, err
	}
	if len(spendable) == 0 {
		return status, nil
	}

	scripts := make([]string, 0, len(spendable))
	for _, v := range spendable {
		scripts = append(scripts, v.Script)
	}
	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return status, err
	}
	signerByScript := signerKeysByScript(ctx, w, contracts)

	now := time.Now()
	for _, v := range spendable {
		sHex, ok := signerByScript[v.Script]
		if !ok {
			continue
		}
		state, cutoff := classifySigner(sHex, currentHex, deprecated, now)
		switch state {
		case signerActive:
			status.Active++
		case signerToMigrate:
			status.ToMigrate++
			status.AmountAtRisk += v.Amount
			updateNearestCutoff(&status, cutoff)
		case signerExpired:
			status.Expired++
			status.AmountAtRisk += v.Amount
			updateNearestCutoff(&status, cutoff)
		case signerUnknown:
			// Unknown signers are log-only: never counted in the summary.
		}
	}
	return status, nil
}

// signerKeysByScript resolves each contract's signer to its x-only hex.
func signerKeysByScript(
	ctx context.Context, w *wallet, contracts []types.Contract,
) map[string]string {
	out := make(map[string]string, len(contracts))
	for _, c := range contracts {
		handler, err := w.contractManager.GetHandler(ctx, c)
		if err != nil {
			continue
		}
		signerKey, err := handler.GetSignerKey(c)
		if err != nil {
			continue
		}
		out[c.Script] = hex.EncodeToString(schnorr.SerializePubKey(signerKey))
	}
	return out
}
