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
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	log "github.com/sirupsen/logrus"
)

// detectAndHandleSignerRotation checks if a signer rotation took place and eventually takes care
// of moving all funds to a new address that makes use of the new signer key.
// The operation may require many txs based on the size of the vtxo set (50 inputs per tx).
// Once the migration succedeed, all "old" contracts are marked as inactive.
func (w *wallet) detectAndHandleSignerRotation(ctx context.Context) {
	serverParams, signerSet, err := w.fetchCurrentSignerSet(ctx)
	if err != nil {
		log.WithError(err).Debug("rotation detection: failed to get server params")
		return
	}
	if !w.needsMigration(ctx, signerSet, serverParams.SignerPubKey) {
		return
	}

	log.Debugf(
		"detected deprecation of signer %s, migrating all funds to new contract(s) with "+
			"signer %s...", serverParams.DeprecatedSignerPubKeys[0].PubKey, serverParams.SignerPubKey,
	)

	if err := w.updateConfig(ctx, serverParams); err != nil {
		log.WithError(err).Warn("rotation detection: failed to update config")
		return
	}

	// Advance the digest only after reconcile succeeds, so failures retry.
	if err := w.migrateAllFunds(ctx, serverParams); err != nil {
		log.WithError(err).Warnf("failed to migrate funds after signer rotation")
		return
	}
	w.lastSignerSet = signerSet
}

// needsMigration returns whether a migration is needed for the fetched signer set:
// - if w.lastSignerSet is set and doesn't match the fetched one, a migration is needed.
// - if w.lastSignerSet is unset, but the latest active contract (default or boarding) makes use of
// a different signer pubkey, a migration is needed.
func (w *wallet) needsMigration(ctx context.Context, signerSet, signer string) bool {
	if len(w.lastSignerSet) > 0 {
		return w.lastSignerSet != signerSet
	}

	contract, err := w.store.ContractStore().GetLatestActiveContract(ctx, types.ContractTypeDefault)
	if err != nil {
		log.WithError(err).Warn("failed to get latest default contract")
		return false
	}
	if contract == nil {
		contract, err = w.store.ContractStore().GetLatestActiveContract(
			ctx, types.ContractTypeBoarding,
		)
		if err != nil {
			log.WithError(err).Warn("failed to get latest boarding contract")
			return false
		}
	}
	if contract == nil {
		return false
	}

	handler, err := w.contractManager.GetHandler(ctx, *contract)
	if err != nil {
		log.WithError(err).Warn("failed to get contract handler")
		return false
	}

	signerKey, err := handler.GetSignerKey(*contract)
	if err != nil {
		log.WithError(err).Warn("failed to get contract signer key")
		return false
	}
	// Check the xOnly key, ignore the paroty prefix.
	return signer[2:] != hex.EncodeToString(signerKey.SerializeCompressed())[2:]
}

func (w *wallet) fetchCurrentSignerSet(ctx context.Context) (*client.Info, string, error) {
	if w.fetchSignerSetFn != nil {
		return w.fetchSignerSetFn(ctx)
	}
	clientSvc := w.Client()
	if clientSvc == nil {
		return nil, "", ErrNotInitialized
	}
	serverParams, err := clientSvc.GetInfo(ctx)
	if err != nil {
		return nil, "", err
	}
	return serverParams, signerSet(serverParams), nil
}

func (w *wallet) updateConfig(ctx context.Context, serverParams *client.Info) error {
	cfgData, err := w.client.GetConfigData(ctx)
	if err != nil {
		return err
	}

	signerPubkey, err := signerPubKeyFromHex(serverParams.SignerPubKey)
	if err != nil {
		return err
	}
	deprecatedSigners := deprecatedSignersForConfig(serverParams, signerPubkey)

	updated := *cfgData
	updated.SignerPubKey = signerPubkey
	updated.DeprecatedSigners = deprecatedSigners

	if err := w.clientStore.ConfigStore().AddData(ctx, updated); err != nil {
		return err
	}

	*cfgData = updated

	return nil
}

// migrateAllFunds reports whether the signer digest can advance.
func (w *wallet) migrateAllFunds(ctx context.Context, serverParams *client.Info) error {
	migrate := w.migrateFundsAfterSignerRotationFn
	if migrate == nil {
		migrate = w.migrateAllFundsInChunks
	}
	return migrate(ctx, serverParams)
}

// migrateAllFundsInChunks migrates all funds locked by contracts using the deprecated signer key
// to contracts using the new signer key in chunks. Each capped chunk is one asset-aware self-send.
// After a successful chunk migraation, all "old" contracts are marked inactive. Failed chunks stay
// active for retry.
// Recoverable, subdust, and cutoff-expired funds are excluded and expected to be handled by the
// next settlement if auto-settle is active or by a manual Settle/CollaborativeExit.
func (w *wallet) migrateAllFundsInChunks(ctx context.Context, serverParams *client.Info) error {
	currentHex, deprecated := deprecatedSignerSet(serverParams)

	if len(deprecated) <= 0 {
		return nil
	}

	spendable, err := w.store.VtxoStore().GetSpendableOrRecoverableVtxos(ctx)
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
	toMigrate, err := w.buildVtxosWithTapTree(ctx, toMigrateVtxos, contracts)
	if err != nil {
		return err
	}

	// Drain all migration candidates in capped, serialized, current-signer
	// self-sends. Inactivate only after the chunk send succeeds.
	if len(toMigrate) > 0 {
		chunks := migrationChunks(toMigrate, maxTxInputs)
		if len(chunks) > 1 {
			log.Debugf(
				"splitting %d vtxos into %d chunk(s) of %d tx inputs to migrate all funds",
				len(toMigrate), len(chunks), maxTxInputs,
			)
		}

		inactiveContractsCount := 0
		txids := make([]string, 0, len(chunks))
		for i, chunk := range chunks {
			txid, err := w.migrateFunds(ctx, chunk, serverParams)
			if err != nil {
				log.WithError(err).Warnf(
					"failed to migrate chunk %d/%d (%d vtxos) — left active for retry",
					i+1, len(chunks), len(chunk),
				)
				return err
			}
			txids = append(txids, txid)

			log.Debugf(
				"migrated chunk %d/%d (%d vtxos) to new contract in tx %s",
				i+1, len(chunks), len(chunk), txid,
			)

			// Only flip contracts consumed by the successful chunk.
			migratedScripts := make([]string, 0, len(chunk))
			for _, v := range chunk {
				migratedScripts = append(migratedScripts, v.Script)
			}
			inactiveContractsCount += w.deactivateContracts(ctx, migratedScripts)
		}
		log.Debugf("deactivated %d contract(s)", inactiveContractsCount)
		log.Debugf(
			"migration of funds after signer rotation completed with tx(s) %s",
			strings.Join(txids, ", "),
		)
	}

	return nil
}

// migrateFunds makes a self-send spending all given vtxos locked by old contracts to a new one
// using the new signer key.
func (w *wallet) migrateFunds(
	ctx context.Context, vtxos []clienttypes.VtxoWithTapTree, serverParams *client.Info,
) (string, error) {
	migrate := func() (any, error) {
		destAddr, err := w.newOffchainAddress(ctx, contract.WithServerParams(serverParams))
		if err != nil {
			return nil, err
		}

		receiver := buildReceiverForMigration(vtxos, destAddr, w.dustAmount)
		return w.sendMigrationOffchainTx(ctx, vtxos, receiver)
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
	ctx context.Context, subset []clienttypes.Vtxo, contracts []types.Contract,
) ([]clienttypes.VtxoWithTapTree, error) {
	if len(subset) == 0 {
		return nil, nil
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

// deactivateContracts marks contracts as inactive; failures are logged and skipped.
func (w *wallet) deactivateContracts(ctx context.Context, scripts []string) int {
	count := 0
	for _, script := range scripts {
		if err := w.store.ContractStore().UpdateContractState(
			ctx, script, types.ContractStateInactive,
		); err != nil {
			log.WithError(err).Warnf("failed to deactivate contract %s", script)
			continue
		}
		count++
	}
	return count
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
	serverParams *client.Info,
) (currentHex string, set map[string]client.DeprecatedSigner) {
	set = make(map[string]client.DeprecatedSigner, len(serverParams.DeprecatedSignerPubKeys))
	if cur, err := normalizeSignerHex(serverParams.SignerPubKey); err == nil {
		currentHex = cur
	} else {
		log.Warnf("skipping malformed current signer %q: %v", serverParams.SignerPubKey, err)
	}
	for _, d := range serverParams.DeprecatedSignerPubKeys {
		xOnly, err := normalizeSignerHex(d.PubKey)
		if err != nil {
			log.Warnf("skipping malformed deprecated signer %q: %v", d.PubKey, err)
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

func deprecatedSignersForConfig(
	serverParams *client.Info, currentSigner *btcec.PublicKey,
) []clienttypes.DeprecatedSigner {
	signers := make([]clienttypes.DeprecatedSigner, 0, len(serverParams.DeprecatedSignerPubKeys))
	for _, d := range serverParams.DeprecatedSignerPubKeys {
		pubkey, err := signerPubKeyFromHex(d.PubKey)
		if err != nil {
			log.WithError(err).Warnf("skipping malformed deprecated signer %q", d.PubKey)
			continue
		}
		if currentSigner != nil && pubkey.IsEqual(currentSigner) {
			continue
		}

		var cutoff time.Time
		if d.CutoffDate > 0 {
			cutoff = time.Unix(d.CutoffDate, 0)
		}
		signers = append(signers, clienttypes.DeprecatedSigner{
			PubKey:     pubkey,
			CutoffDate: cutoff,
		})
	}
	return signers
}

func signerPubKeyFromHex(pubkey string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(strings.TrimSpace(pubkey))
	if err != nil {
		return nil, err
	}
	if len(buf) == schnorr.PubKeyBytesLen {
		return schnorr.ParsePubKey(buf)
	}
	return btcec.ParsePubKey(buf)
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

// signerSet returns a stable current+deprecated signer-set representation.
func signerSet(serverParams *client.Info) string {
	parts := make([]string, 0, 1+len(serverParams.DeprecatedSignerPubKeys))
	if cur, err := normalizeSignerHex(serverParams.SignerPubKey); err == nil {
		parts = append(parts, "cur:"+cur)
	}
	for _, d := range serverParams.DeprecatedSignerPubKeys {
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
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Amount > sorted[j].Amount
	})

	chunks := make(
		[][]clienttypes.VtxoWithTapTree, 0, (len(sorted)+maxInputs-1)/maxInputs,
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
	spendable []clienttypes.Vtxo, signerByScript map[string]string,
	signerMap map[string]signerInfo, dustAmount uint64,
) (toMigrate []clienttypes.Vtxo) {
	for _, v := range spendable {
		sHex, ok := signerByScript[v.Script]
		if !ok {
			continue
		}
		si, known := signerMap[sHex]
		if !known {
			log.Warnf(
				"vtxo %s under unknown signer %s (neither current nor deprecated)",
				v.Outpoint, sHex,
			)
			continue
		}
		switch si.state {
		case signerActive:
		case signerToMigrate:
			// Skip recoverable or subdust vtxos, they will be handled by the auto-settle or via
			// the next manual Settle/CollaborativeExit.
			if v.IsRecoverable() || (dustAmount > 0 && v.Amount < dustAmount) {
				continue
			}
			toMigrate = append(toMigrate, v)
		case signerExpired:
			log.Debugf(
				"skipping vtxo %s under signer %s: cutoff date has passed",
				v.Outpoint, sHex,
			)
		}
	}
	return toMigrate
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

// buildReceiverForMigration collapses all migrated BTC and assets into one
// receiver. Sats are summed exactly, asset amounts are grouped by asset id, and dustAmount
// is enforced defensively.
func buildReceiverForMigration(
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
