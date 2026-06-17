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
	// Note: a stored contract whose signer is neither the current signer nor any
	// advertised deprecated key is no longer modeled as an enum value. The
	// reconcile loop builds a signerMap of current∪deprecated once and treats a
	// map miss as an inline logged skip (never migrated).
)

// signerInfo is the classified state of one signer x-only hex, precomputed once
// per reconcile pass so the per-vtxo loop is a single map lookup.
type signerInfo struct {
	state signerState
}

// buildSignerMap precomputes the state of every known signer (the current
// signer plus each advertised deprecated key) in a single pass over the
// deprecated set, using `now` for the cutoff threshold. Deprecated keys with a
// future (or zero) cutoff are signerToMigrate; past-cutoff keys are
// signerExpired. The current signer is signerActive. A signer that appears in
// neither set is absent from the returned map; callers treat a map miss as an
// inline "log and skip" (it is never migrated) — this replaces the former
// signerUnknown enum value.
func buildSignerMap(
	currentHex string,
	deprecated map[string]client.DeprecatedSigner,
	now time.Time,
) map[string]signerInfo {
	m := make(map[string]signerInfo, 1+len(deprecated))
	if currentHex != "" {
		m[currentHex] = signerInfo{state: signerActive}
	}
	for xOnly, d := range deprecated {
		// cutoffDate == 0 means "no cutoff": always migratable, never expires.
		if d.CutoffDate == 0 || now.Before(time.Unix(d.CutoffDate, 0)) {
			m[xOnly] = signerInfo{state: signerToMigrate}
		} else {
			m[xOnly] = signerInfo{state: signerExpired}
		}
	}
	return m
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
	key, err := signerPubKeyFromHex(h)
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

// migrationBatches sorts the migration candidates by sats value descending and
// splits them into maxInputs-sized batches. It is a pure function (sorts a copy
// of the input) so the cap behaviour is directly unit-testable.
func migrationBatches(
	candidates []clienttypes.VtxoWithTapTree, maxInputs int,
) [][]clienttypes.VtxoWithTapTree {
	if maxInputs <= 0 {
		maxInputs = defaultMaxMigrationInputs
	}

	sorted := make([]clienttypes.VtxoWithTapTree, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Amount > sorted[j].Amount
	})

	if len(sorted) == 0 {
		return nil
	}

	batches := make(
		[][]clienttypes.VtxoWithTapTree, 0,
		(len(sorted)+maxInputs-1)/maxInputs,
	)
	for start := 0; start < len(sorted); start += maxInputs {
		end := start + maxInputs
		if end > len(sorted) {
			end = len(sorted)
		}
		batches = append(batches, sorted[start:end])
	}
	return batches
}

func (w *wallet) migrationInputLimit() int {
	if w.maxMigrationInputs <= 0 {
		return defaultMaxMigrationInputs
	}
	return w.maxMigrationInputs
}

// reconcileDeprecatedSigners classifies the wallet's spendable vtxos by the
// state of the server signer their contract commits to, in a single pass, and
// migrates the actionable (ToMigrate) ones onto current-signer outputs via the
// safeCheck-free, asset-aware send path (SubmitTx/FinalizeTx). Each capped batch
// is consolidated into one output: all BTC plus every asset in that batch
// collapse into a single vtxo at one fresh current-signer address (the receiver
// declares the per-asset totals so assets are preserved, never stripped). It
// never blocks the caller on a migration failure: the send error is returned to
// the unlock/live-rotation wrapper, which logs it and leaves the wallet usable.
//
// At most the configured migration input limit is migrated per transaction, but
// reconcile loops over every batch in the same pass. No vtxo is left for a later
// reconcile just because the set exceeded the per-transaction cap.
//
// After the send succeeds, all migrated contracts are flipped to
// ContractStateInactive (all-or-nothing: on failure none are flipped, so the
// batch stays active for the next reconcile). Expired contracts (exit-only) are
// flipped at the end of the pass regardless of whether any migration ran. The
// inactivation is a UI signal only; refreshDb reads contracts state-agnostically
// today, so it never hides funds.
//
// Locking: vtxos/contracts are read under w.dbMu, then the lock is released
// before the send (which takes w.dbMu internally via the txHandler). The lock is
// never held across the send.
func (w *wallet) reconcileDeprecatedSigners(ctx context.Context) error {
	if w.contractManager == nil {
		return nil
	}

	info, err := w.Client().GetInfo(ctx)
	if err != nil {
		return err
	}
	currentHex, deprecated := deprecatedSignerSet(info)

	if len(deprecated) == 0 {
		return nil
	}

	w.dbMu.Lock()
	spendable, err := w.store.VtxoStore().GetSpendableOrRecoverableVtxos(ctx)
	w.dbMu.Unlock()
	if err != nil {
		return err
	}
	if len(spendable) == 0 {
		return nil
	}

	scripts := make([]string, 0, len(spendable))
	for _, v := range spendable {
		scripts = append(scripts, v.Script)
	}
	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return err
	}
	signerByScript := signerKeysByScript(ctx, w, contracts)

	// Classify every known signer once (current ∪ deprecated), then make a single
	// pass over the vtxos. classifyVtxos is a pure function (no I/O) so the
	// single-pass classification is directly unit-testable.
	signerMap := buildSignerMap(currentHex, deprecated, time.Now())
	toMigrateVtxos, expiredScripts := classifyVtxos(spendable, signerByScript, signerMap)

	// Resolve the ToMigrate vtxos to the VtxoWithTapTree shape sendOffchain needs
	toMigrate, err := w.buildVtxosWithTapTree(ctx, toMigrateVtxos)
	if err != nil {
		return err
	}

	// Migrate the actionable (ToMigrate) vtxos by consolidating each capped batch
	// into one output: all BTC plus every asset in that batch collapse into a
	// single vtxo at one fresh current-signer address, honoring arkd #822. The
	// consolidated receiver declares the per-asset totals so createAssetPacket
	// balances inputs == outputs per asset and no asset value is stripped. Only
	// the migrated vtxos are pinned as inputs; Expired vtxos are excluded
	// (exit-only) and Active vtxos are left untouched. Idempotent across runs:
	// once migrated, those vtxos are spent and a re-run finds no ToMigrate entries
	// for them.
	//
	// Input cap: at most the configured migration input limit is consolidated per
	// transaction. The set is sorted by sats value descending and then drained in
	// capped batches in this same reconcile pass. This bounds the per-tx
	// input/weight cost without leaving a remainder for a later reconcile.
	//
	// sendOffchain bypasses safeCheck because reconcile runs synchronously during
	// Unlock, before the wallet is marked synced; the public SendOffChain would
	// return ErrIsSyncing here and skip the migration. It still serializes each
	// migration batch through txHandler, so periodic rotation cannot overlap user
	// sends/assets/settles.
	//
	// All-or-nothing rule per batch: inactivation is applied only after that
	// batch's consolidated send returns without error, and only for the migrated
	// scripts. On a send failure the failed batch and all remaining batches stay
	// active for retry, so a contract is never inactivated before the send that
	// consumed its vtxo succeeded.
	if len(toMigrate) > 0 {
		maxInputs := w.migrationInputLimit()
		batches := migrationBatches(toMigrate, maxInputs)
		if len(batches) > 1 {
			log.Infof(
				"reconcile: splitting %d deprecated-signer vtxo(s) into %d migration batch(es), max %d input(s) each",
				len(toMigrate),
				len(batches),
				maxInputs,
			)
		}

		for i, batch := range batches {
			txid, err := w.sendOffchain(ctx, batch)
			if err != nil {
				log.WithError(err).Warnf(
					"reconcile: failed to migrate batch %d/%d (%d vtxo(s)) — left active for retry",
					i+1, len(batches), len(batch),
				)
				return err
			}

			log.Infof(
				"reconcile: consolidated batch %d/%d (%d vtxo(s)) offchain into one current-signer output txid=%s",
				i+1,
				len(batches),
				len(batch),
				txid,
			)

			// Invariant: flip the migrated contracts to inactive only after the
			// send succeeds, and only for the scripts that were migrated.
			migratedScripts := make([]string, 0, len(batch))
			for _, v := range batch {
				migratedScripts = append(migratedScripts, v.Script)
			}
			w.inactivateContracts(ctx, migratedScripts)
		}
	}

	// Flip Expired contracts to inactive regardless of whether a migration ran:
	// their vtxos are exit-only, so "inactive" directs the user to a unilateral
	// exit. No migration to wait for, so the timing invariant does not apply here.
	w.inactivateContracts(ctx, expiredScripts)

	return nil
}

// buildVtxosWithTapTree enriches a plain []clienttypes.Vtxo subset into the
// []clienttypes.VtxoWithTapTree shape that getSpendableVtxos produces, by
// resolving each vtxo's contract and extracting its tapscripts. Vtxos whose
// contract is not found in the store (or whose handler/tapscripts cannot be
// resolved) are skipped with a warning — the same behavior getSpendableVtxos
// exhibits for vtxos missing a contract. Used by reconcileDeprecatedSigners to
// resolve the ToMigrate subset before handing it to sendOffchain.
func (w *wallet) buildVtxosWithTapTree(
	ctx context.Context, subset []clienttypes.Vtxo,
) ([]clienttypes.VtxoWithTapTree, error) {
	if len(subset) == 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(subset))
	for _, v := range subset {
		scripts = append(scripts, v.Script)
	}

	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	contractsByScript := make(map[string]types.Contract, len(contracts))
	for _, c := range contracts {
		contractsByScript[c.Script] = c
	}

	vtxos := make([]clienttypes.VtxoWithTapTree, 0, len(subset))
	for _, v := range subset {
		c, ok := contractsByScript[v.Script]
		if !ok {
			log.Warnf("skipping vtxo %s: no matching contract", v.Script)
			continue
		}
		handler, err := w.contractManager.GetHandler(ctx, c)
		if err != nil {
			log.WithError(err).Warnf("failed to get handler for contract %s", c.Script)
			continue
		}
		tapscripts, err := handler.GetTapscripts(c)
		if err != nil {
			log.WithError(err).Warnf("failed to get tapscripts for contract %s", c.Script)
			continue
		}
		vtxos = append(vtxos, clienttypes.VtxoWithTapTree{
			Vtxo:       v,
			Tapscripts: tapscripts,
		})
	}

	return vtxos, nil
}

// inactivateContracts flips each given contract script to ContractStateInactive.
// Individual failures are logged and skipped — a failed flip never aborts the
// reconcile pass (the inactive state is a UI signal only; refreshDb reads
// contracts state-agnostically, so a missed flip cannot hide funds).
func (w *wallet) inactivateContracts(ctx context.Context, scripts []string) {
	for _, script := range scripts {
		if err := w.store.ContractStore().UpdateContractState(
			ctx, script, types.ContractStateInactive,
		); err != nil {
			log.WithError(err).Warnf("reconcile: failed to inactivate contract %s", script)
		}
	}
}

// classifyVtxos makes a single pass over the spendable vtxos, classifying each
// by the precomputed state of its signer (signerMap). It returns the ordered
// subset of ToMigrate vtxos plus the expired contract scripts to inactivate. It
// is a pure function (no I/O): the only side effect is a log line for a vtxo
// whose signer is in neither the current nor the deprecated set (a map miss),
// which is skipped. Active vtxos are ignored.
func classifyVtxos(
	spendable []clienttypes.Vtxo,
	signerByScript map[string]string,
	signerMap map[string]signerInfo,
) (toMigrate []clienttypes.Vtxo, expiredScripts []string) {
	for _, v := range spendable {
		sHex, ok := signerByScript[v.Script]
		if !ok {
			// No contract maps this vtxo's script; skip (a foreign or not-yet-discovered script).
			continue
		}
		si, known := signerMap[sHex]
		if !known {
			// Signer is neither the current signer nor an advertised deprecated
			// key. Log and skip: never migrated.
			log.Warnf(
				"reconcile: vtxo %s under unknown signer %s (neither current nor deprecated)",
				v.Script, sHex,
			)
			continue
		}
		switch si.state {
		case signerActive:
		case signerToMigrate:
			toMigrate = append(toMigrate, v)
		case signerExpired:
			log.Warnf(
				"reconcile: vtxo %s under expired signer %s is exit-only (past cutoff)",
				v.Script, sHex,
			)
			expiredScripts = append(expiredScripts, v.Script)
		}
	}
	return toMigrate, expiredScripts
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
