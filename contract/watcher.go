package contract

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	log "github.com/sirupsen/logrus"
)

const (
	watcherBackoffBase = 1 * time.Second
	watcherBackoffCap  = 30 * time.Second
	watcherEventBuf    = 32
)

// AddressInfo holds the spending metadata for an address derived from a Contract.
// Clients use it to populate UTXOs when explorer events arrive.
type AddressInfo struct {
	Tapscripts []string
	Delay      arklib.RelativeLocktime
}

// Watcher subscribes to the explorer for all addresses derived from active contracts
// and surfaces OnchainAddressEvents for the client to process.
// New contracts are subscribed dynamically via the Manager's OnContractEvent callback.
type Watcher struct {
	exp     explorer.Explorer
	mgr     Manager
	network arklib.Network

	started atomic.Bool

	mu              sync.RWMutex
	addresses       []string
	addressByScript map[string]AddressInfo

	events    chan clientTypes.OnchainAddressEvent
	closeOnce sync.Once
	cancel    context.CancelFunc
}

// NewWatcher creates a Watcher. Call Start to begin watching.
func NewWatcher(exp explorer.Explorer, mgr Manager, network arklib.Network) *Watcher {
	return &Watcher{
		exp:             exp,
		mgr:             mgr,
		network:         network,
		addressByScript: make(map[string]AddressInfo),
		events:          make(chan clientTypes.OnchainAddressEvent, watcherEventBuf),
		cancel:          func() {},
	}
}

// Start loads all current contracts, subscribes their addresses to the explorer,
// and launches the listener goroutine. Newly created contracts are subscribed
// dynamically. Start returns an error only if the initial address load fails or
// Start has already been called; subscription failures are retried internally
// with exponential backoff.
func (w *Watcher) Start(ctx context.Context) error {
	if !w.started.CompareAndSwap(false, true) {
		return fmt.Errorf("watcher: already started")
	}

	contracts, err := w.mgr.GetContracts(ctx, WithState(types.ContractStateActive))
	if err != nil {
		return fmt.Errorf("watcher: load contracts: %w", err)
	}

	for _, c := range contracts {
		w.addContractAddresses(ctx, c)
	}

	watchCtx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.cancel = cancel
	w.mu.Unlock()

	go func() {
		defer w.closeOnce.Do(func() { close(w.events) })

		// Register the callback before subscribing so no contract_created events
		// are missed during the backoff retry window.
		// Dynamic subscription: one goroutine per new contract so the
		// OnContractEvent callback never blocks NewContract -> emit.
		unsub := w.mgr.OnContractEvent(func(c types.Contract) {
			go func() {
				newAddrs := w.addContractAddresses(watchCtx, c)
				if len(newAddrs) == 0 || watchCtx.Err() != nil {
					return
				}
				if err := w.exp.SubscribeForAddresses(newAddrs); err != nil {
					log.WithError(err).Warn("watcher: failed to subscribe new contract addresses")
				}
			}()
		})
		defer unsub()

		if err := w.subscribeWithBackoff(watchCtx); err != nil {
			// Context cancelled before we could subscribe: clean exit.
			return
		}

		w.listen(watchCtx)
	}()

	return nil
}

// Stop cancels the watcher context, shutting down the listener goroutine.
func (w *Watcher) Stop() {
	w.mu.RLock()
	cancel := w.cancel
	w.mu.RUnlock()
	cancel()
}

// Events returns the channel on which the watcher delivers OnchainAddressEvents.
func (w *Watcher) Events() <-chan clientTypes.OnchainAddressEvent {
	return w.events
}

// LookupAddress returns the AddressInfo for a script hex, if known.
func (w *Watcher) LookupAddress(scriptHex string) (AddressInfo, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	info, ok := w.addressByScript[scriptHex]
	return info, ok
}

// addContractAddresses derives and records the address for c under w.mu.
// Returns the slice of new addresses added (for callers that need to subscribe them).
func (w *Watcher) addContractAddresses(ctx context.Context, c types.Contract) []string {
	var addr string
	if c.Type == types.ContractTypeBoarding {
		addr = c.Address
	} else {
		onchain, err := watcherArkToOnchain(c.Address, w.network)
		if err != nil {
			log.WithError(err).Warn("watcher: failed to convert ark address to onchain")
			return nil
		}
		addr = onchain
	}

	sc, err := watcherOutputScript(addr, w.network)
	if err != nil {
		log.WithError(err).Warn("watcher: failed to derive script for contract address")
		return nil
	}
	scriptHex := hex.EncodeToString(sc)

	handler, err := w.mgr.GetHandler(ctx, c)
	if err != nil {
		log.WithError(err).Warnf("watcher: failed to get handler for contract %s", c.Script)
		return nil
	}

	tapscripts, err := handler.GetTapscripts(c)
	if err != nil {
		log.WithError(err).Warnf("watcher: failed to get tapscripts for contract %s", c.Script)
		return nil
	}

	var delay arklib.RelativeLocktime
	exitDelay, err := handler.GetExitDelay(c)
	if err != nil {
		if c.Type != types.ContractTypeBoarding {
			delay = arklib.RelativeLocktime{}
		} else {
			log.WithError(err).Warnf("watcher: skipping contract %s: invalid exit delay", c.Script)
			return nil
		}
	} else {
		delay = *exitDelay
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.addressByScript[scriptHex]; exists {
		return nil
	}
	w.addressByScript[scriptHex] = AddressInfo{
		Tapscripts: tapscripts,
		Delay:      delay,
	}
	w.addresses = append(w.addresses, addr)
	return []string{addr}
}

func (w *Watcher) subscribeWithBackoff(ctx context.Context) error {
	backoff := watcherBackoffBase
	for {
		w.mu.RLock()
		addrs := make([]string, len(w.addresses))
		copy(addrs, w.addresses)
		w.mu.RUnlock()

		if len(addrs) == 0 {
			return nil
		}

		if err := w.exp.SubscribeForAddresses(addrs); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.WithError(err).Warnf("watcher: subscribe failed, retrying in %s", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, watcherBackoffCap)
			continue
		}
		log.Debugf("watcher: subscribed to %d addresses", len(addrs))
		return nil
	}
}

func (w *Watcher) listen(ctx context.Context) {
	// w.events is closed by the Start goroutine's defer on exit.
	ch := w.exp.GetAddressesEvents()
	for {
		select {
		case <-ctx.Done():
			w.mu.RLock()
			addrs := make([]string, len(w.addresses))
			copy(addrs, w.addresses)
			w.mu.RUnlock()
			if err := w.exp.UnsubscribeForAddresses(addrs); err != nil {
				log.WithError(err).Warn("watcher: failed to unsubscribe on stop")
			}
			return
		case ev, ok := <-ch:
			if !ok {
				log.Warn("watcher: explorer event channel closed, resubscribing")
				if err := w.subscribeWithBackoff(ctx); err != nil {
					return
				}
				ch = w.exp.GetAddressesEvents()
				continue
			}
			select {
			case w.events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// watcherOutputScript converts a bitcoin address string to its output script bytes.
func watcherOutputScript(addr string, network arklib.Network) ([]byte, error) {
	params := utils.ToBitcoinNetwork(network)
	decoded, err := btcutil.DecodeAddress(addr, &params)
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(decoded)
}

// watcherArkToOnchain converts an Ark offchain address to its onchain P2TR equivalent.
func watcherArkToOnchain(arkAddr string, network arklib.Network) (string, error) {
	params := utils.ToBitcoinNetwork(network)
	decoded, err := arklib.DecodeAddressV0(arkAddr)
	if err != nil {
		return "", err
	}
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(decoded.VtxoTapKey), &params)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}
