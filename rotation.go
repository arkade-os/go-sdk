package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

func (w *wallet) migrationInputLimit() int {
	if w.maxMigrationInputs <= 0 {
		return defaultMaxMigrationInputs
	}
	return w.maxMigrationInputs
}

// reconcileDeprecatedSigners migrates spendable deprecated-signer vtxos to
// current-signer outputs. Each capped chunk is one asset-aware self-send.
// Successful chunks are marked inactive; failed chunks stay active for retry.
// Recoverable, subdust, and cutoff-expired funds are left for auto-settlement.
func (w *wallet) reconcileDeprecatedSigners(ctx context.Context, info *client.Info) error {
	if w.contractManager == nil {
		return nil
	}
	if info == nil {
		return fmt.Errorf("missing server info")
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

	// Classify known signers once, then scan vtxos in one pass.
	signerMap := buildSignerMap(currentHex, deprecated, time.Now())
	toMigrateVtxos := classifyVtxos(
		spendable, signerByScript, signerMap, w.dustAmount,
	)

	// Resolve ToMigrate vtxos to the shape the migration send needs.
	toMigrate, err := w.buildVtxosWithTapTree(ctx, toMigrateVtxos)
	if err != nil {
		return err
	}

	// Drain all migration candidates in capped, serialized, current-signer
	// self-sends. Inactivate only after the chunk send succeeds.
	if len(toMigrate) > 0 {
		maxInputs := w.migrationInputLimit()
		chunks := migrationChunks(toMigrate, maxInputs)
		if len(chunks) > 1 {
			log.Infof(
				"reconcile: splitting %d deprecated-signer vtxo(s) into %d migration chunk(s), max %d input(s) each",
				len(toMigrate),
				len(chunks),
				maxInputs,
			)
		}

		for i, chunk := range chunks {
			txid, err := w.migrateDeprecatedVtxosOffchain(ctx, chunk, info)
			if err != nil {
				log.WithError(err).Warnf(
					"reconcile: failed to migrate chunk %d/%d (%d vtxo(s)) — left active for retry",
					i+1, len(chunks), len(chunk),
				)
				return err
			}

			log.Infof(
				"reconcile: consolidated chunk %d/%d (%d vtxo(s)) offchain into one current-signer output txid=%s",
				i+1,
				len(chunks),
				len(chunk),
				txid,
			)

			// Only flip contracts consumed by the successful chunk.
			migratedScripts := make([]string, 0, len(chunk))
			for _, v := range chunk {
				migratedScripts = append(migratedScripts, v.Script)
			}
			w.inactivateContracts(ctx, migratedScripts)
		}
	}

	return nil
}

// migrateDeprecatedVtxosOffchain migrates deprecated-signer vtxos into one
// current-signer output. It bypasses safeCheck for unlock migration but still
// uses txHandler.
func (w *wallet) migrateDeprecatedVtxosOffchain(
	ctx context.Context,
	toMigrate []clienttypes.VtxoWithTapTree,
	info *client.Info,
) (string, error) {
	if len(toMigrate) == 0 {
		return "", nil
	}
	if info == nil {
		return "", fmt.Errorf("missing server info")
	}

	if w.txHandler == nil {
		return "", ErrNotInitialized
	}

	migrate := func() (any, error) {
		destAddr, err := w.newOffchainAddress(ctx, contract.WithServerInfo(info))
		if err != nil {
			return nil, err
		}

		receiver := buildConsolidatedReceiver(toMigrate, destAddr, w.dustAmount)
		return w.sendMigrationOffchainTx(ctx, toMigrate, receiver)
	}

	rr, err := w.txHandler.handleTx(migrate)
	if err != nil {
		return "", err
	}

	txid, ok := rr.(string)
	if !ok {
		return "", fmt.Errorf("unexpected migration send result type %T", rr)
	}
	return txid, nil
}

// buildConsolidatedReceiver collapses all migrated BTC and assets into one
// current-signer receiver. Sats are summed exactly, asset amounts are grouped by
// asset id, and dustAmount is enforced defensively.
func buildConsolidatedReceiver(
	vtxos []clienttypes.VtxoWithTapTree, destAddr string, dustAmount uint64,
) clienttypes.Receiver {
	var amount uint64
	totals := make(map[string]uint64)
	for _, v := range vtxos {
		amount += v.Amount
		for _, a := range v.Assets {
			totals[a.AssetId] += a.Amount
		}
	}

	if amount < dustAmount {
		amount = dustAmount
	}

	if len(totals) == 0 {
		return clienttypes.Receiver{To: destAddr, Amount: amount}
	}

	ids := make([]string, 0, len(totals))
	for id := range totals {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic asset ordering on the receiver
	assets := make([]clienttypes.Asset, 0, len(ids))
	for _, id := range ids {
		assets = append(assets, clienttypes.Asset{AssetId: id, Amount: totals[id]})
	}

	return clienttypes.Receiver{To: destAddr, Amount: amount, Assets: assets}
}

// sendMigrationOffchainTx is the pinned-input, safeCheck-free migration send.
// Call through migrateDeprecatedVtxosOffchain so txHandler still serializes it.
func (w *wallet) sendMigrationOffchainTx(
	ctx context.Context,
	vtxos []clienttypes.VtxoWithTapTree,
	receiver clienttypes.Receiver,
) (string, error) {
	if len(vtxos) == 0 {
		return "", nil
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	// Subscribe before submitting so the destination notification is not missed.
	tracked, cancel := w.notifyTracked(ctx, receiver.To)
	defer cancel()

	res, err := w.client.SendOffChain(
		ctx,
		[]clienttypes.Receiver{receiver},
		clientwallet.WithVtxos(vtxos),
		clientwallet.WithKeys(signingKeyRefs),
	)
	if err != nil {
		return "", err
	}

	if err := w.saveSendTransaction(ctx, withMigrationOutput(*res, receiver)); err != nil {
		return "", err
	}

	if err := waitTracked(ctx, tracked); err != nil {
		return "", err
	}

	return res.Txid, nil
}

// buildVtxosWithTapTree adds tapscripts for the ToMigrate subset.
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

// inactivateContracts marks scripts inactive; failures are logged and skipped.
func (w *wallet) inactivateContracts(ctx context.Context, scripts []string) {
	for _, script := range scripts {
		if err := w.store.ContractStore().UpdateContractState(
			ctx, script, types.ContractStateInactive,
		); err != nil {
			log.WithError(err).Warnf("reconcile: failed to inactivate contract %s", script)
		}
	}
}

// signerState classifies one signer key relative to the current signer set.
type signerState int

const (
	signerActive signerState = iota
	// Deprecated signer before cutoff, or with no cutoff.
	signerToMigrate
	// Deprecated signer past cutoff; collaborative migration is no longer possible.
	signerExpired
)

// signerInfo is the precomputed state for one x-only signer key.
type signerInfo struct {
	state signerState
}

// buildSignerMap classifies the current and deprecated signers for one reconcile.
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

// deprecatedSignerSet normalizes current/deprecated signers to x-only hex.
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

// signerSetDigest returns a stable current+deprecated signer-set representation.
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

// migrationChunks sorts by sats descending and splits into capped chunks.
func migrationChunks(
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

	chunks := make(
		[][]clienttypes.VtxoWithTapTree, 0,
		(len(sorted)+maxInputs-1)/maxInputs,
	)
	for start := 0; start < len(sorted); start += maxInputs {
		end := start + maxInputs
		if end > len(sorted) {
			end = len(sorted)
		}
		chunks = append(chunks, sorted[start:end])
	}
	return chunks
}

// classifyVtxos returns vtxos safe to migrate immediately via offchain self-send.
func classifyVtxos(
	spendable []clienttypes.Vtxo,
	signerByScript map[string]string,
	signerMap map[string]signerInfo,
	dustAmount uint64,
) (toMigrate []clienttypes.Vtxo) {
	for _, v := range spendable {
		sHex, ok := signerByScript[v.Script]
		if !ok {
			continue
		}
		si, known := signerMap[sHex]
		if !known {
			log.Warnf(
				"reconcile: vtxo %s under unknown signer %s (neither current nor deprecated)",
				v.Script, sHex,
			)
			continue
		}
		switch si.state {
		case signerActive:
		case signerToMigrate:
			if notOffchainMigratable(v, dustAmount) {
				continue
			}
			toMigrate = append(toMigrate, v)
		case signerExpired:
			log.Warnf(
				"reconcile: skipping vtxo %s under cutoff-expired signer %s",
				v.Script, sHex,
			)
		}
	}
	return toMigrate
}

func notOffchainMigratable(v clienttypes.Vtxo, dustAmount uint64) bool {
	return v.IsRecoverable() || (dustAmount > 0 && v.Amount < dustAmount)
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
