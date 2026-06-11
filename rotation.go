package arksdk

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

// defaultMigrationMargin is how far ahead of a deprecated key's cutoff a
// migration is considered "due now". A settle submitted within this window
// before the cutoff should confirm before the server stops co-signing for the
// deprecated key (arkd #822). Conservative by design.
const defaultMigrationMargin = 24 * time.Hour

// signerState classifies one signer key relative to the current signer set.
type signerState int

const (
	// signerCurrent is the active server signer (no action).
	signerCurrent signerState = iota
	// signerMigratable is a deprecated key whose cutoff is comfortably in the
	// future (or has no cutoff). It can still be migrated collaboratively.
	signerMigratable
	// signerDueNow is a deprecated key whose cutoff is within the safety
	// margin: migrate now.
	signerDueNow
	// signerExpired is a deprecated key past its cutoff: the server refuses to
	// co-sign, so its vtxos are unilateral-exit-only. Never attempt a
	// collaborative migration for these.
	signerExpired
	// signerUnknown is a stored contract whose signer is neither current nor
	// any advertised deprecated key (defensive; surfaced and logged).
	signerUnknown
)

// DeprecatedSignerStatus summarizes the wallet's exposure to signer rotation.
// Callers (e.g. fulmine) can surface it to users. Counts are over spendable
// vtxos grouped by the state of the signer their contract commits to.
type DeprecatedSignerStatus struct {
	// Current is the number of spendable vtxos under the active signer.
	Current int
	// Migratable is the number under a deprecated signer with a comfortable
	// cutoff (or none).
	Migratable int
	// DueNow is the number under a deprecated signer due for migration now.
	DueNow int
	// Expired is the number under a past-cutoff signer (exit-only).
	Expired int
	// UnknownSigner is the number under a signer that is neither current nor a
	// listed deprecated key.
	UnknownSigner int
	// NearestCutoff is the earliest non-zero cutoff among deprecated signers
	// that still hold spendable vtxos; zero if none.
	NearestCutoff time.Time
	// AmountAtRisk is the total satoshi value under deprecated signers that are
	// dueNow or expired.
	AmountAtRisk uint64
	// Migrated reports whether this reconcile actually submitted a settle to
	// migrate dueNow vtxos onto current-signer outputs.
	Migrated bool
}

// classifySigner maps a signer x-only hex to its state given the current signer
// and the deprecated set, using `now` and `margin` for the cutoff thresholds.
func classifySigner(
	signerHex, currentHex string,
	deprecated map[string]client.DeprecatedSigner,
	now time.Time, margin time.Duration,
) (signerState, int64) {
	if signerHex == currentHex {
		return signerCurrent, 0
	}
	d, ok := deprecated[signerHex]
	if !ok {
		return signerUnknown, 0
	}
	// cutoffDate == 0 means "no cutoff": always migratable, never expires.
	if d.CutoffDate == 0 {
		return signerMigratable, 0
	}
	cutoff := time.Unix(d.CutoffDate, 0)
	switch {
	case now.After(cutoff):
		return signerExpired, d.CutoffDate
	case cutoff.Sub(now) <= margin:
		return signerDueNow, d.CutoffDate
	default:
		return signerMigratable, d.CutoffDate
	}
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
	var hasDueNow bool
	for _, v := range spendable {
		sHex, ok := signerByScript[v.Script]
		if !ok {
			// No contract maps this vtxo's script; skip (a foreign or
			// not-yet-discovered script). Discovery (Item A) is responsible for
			// persisting the contract before reconcile runs.
			continue
		}
		state, cutoff := classifySigner(sHex, currentHex, deprecated, now, defaultMigrationMargin)
		switch state {
		case signerCurrent:
			status.Current++
		case signerMigratable:
			status.Migratable++
			updateNearestCutoff(&status, cutoff)
		case signerDueNow:
			status.DueNow++
			status.AmountAtRisk += v.Amount
			hasDueNow = true
			updateNearestCutoff(&status, cutoff)
		case signerExpired:
			status.Expired++
			status.AmountAtRisk += v.Amount
			log.Warnf(
				"reconcile: vtxo %s under expired signer %s is exit-only (past cutoff)",
				v.Script, sHex,
			)
		case signerUnknown:
			status.UnknownSigner++
			log.Warnf(
				"reconcile: vtxo %s under unknown signer %s (neither current nor deprecated)",
				v.Script, sHex,
			)
		}
	}

	// Migrate the actionable (dueNow) vtxos. Settle moves ALL spendable vtxos
	// onto a fresh current-signer change output, so it both migrates the
	// deprecated-signer vtxos and honors #822 (every output commits to the
	// current signer). It is idempotent across runs: once migrated, those
	// vtxos are spent and a re-run finds no dueNow entries (EC-12, EC-14).
	if hasDueNow {
		if _, err := w.Settle(ctx); err != nil {
			// Do not fail the caller (Unlock) on a migration error — log and
			// surface via the returned status.
			log.WithError(err).Warn("reconcile: failed to migrate deprecated-signer vtxos")
			return status, err
		}
		status.Migrated = true
		log.Infof(
			"reconcile: migrated %d deprecated-signer vtxo(s) onto current-signer outputs",
			status.DueNow,
		)
	}

	return status, nil
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
		state, cutoff := classifySigner(sHex, currentHex, deprecated, now, defaultMigrationMargin)
		switch state {
		case signerCurrent:
			status.Current++
		case signerMigratable:
			status.Migratable++
			updateNearestCutoff(&status, cutoff)
		case signerDueNow:
			status.DueNow++
			status.AmountAtRisk += v.Amount
			updateNearestCutoff(&status, cutoff)
		case signerExpired:
			status.Expired++
			status.AmountAtRisk += v.Amount
		case signerUnknown:
			status.UnknownSigner++
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
