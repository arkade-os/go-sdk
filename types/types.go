package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
	KVStore       = "kv"
	SQLStore      = "sql"
)

type Config struct {
	ServerUrl                    string
	SignerPubKey                 *btcec.PublicKey
	ForfeitPubKey                *btcec.PublicKey
	WalletType                   string
	ClientType                   string
	Network                      arklib.Network
	SessionDuration              int64
	UnilateralExitDelay          arklib.RelativeLocktime
	Dust                         uint64
	BoardingExitDelay            arklib.RelativeLocktime
	ExplorerURL                  string
	ExplorerTrackingPollInterval time.Duration
	ForfeitAddress               string
	WithTransactionFeed          bool
	UtxoMinAmount                int64
	UtxoMaxAmount                int64
	VtxoMinAmount                int64
	VtxoMaxAmount                int64
	CheckpointTapscript          string
	Fees                         FeeInfo
}

func (c Config) CheckpointExitPath() []byte {
	// nolint
	buf, _ := hex.DecodeString(c.CheckpointTapscript)
	return buf
}

type FeeInfo struct {
	IntentFees arkfee.Config
	TxFeeRate  float64
}

type DeprecatedSigner struct {
	PubKey     *btcec.PublicKey
	CutoffDate time.Time
}

type Outpoint struct {
	Txid string
	VOut uint32
}

func (v Outpoint) String() string {
	return fmt.Sprintf("%s:%d", v.Txid, v.VOut)
}

type Vtxo struct {
	Outpoint
	Script          string
	Amount          uint64
	CommitmentTxids []string
	ExpiresAt       time.Time
	CreatedAt       time.Time
	Preconfirmed    bool
	Swept           bool
	Unrolled        bool
	Spent           bool
	SpentBy         string
	SettledBy       string
	ArkTxid         string
	Assets          []Asset
}

type Asset struct {
	AssetId string
	Amount  uint64
}

func (v Vtxo) String() string {
	// nolint
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (v Vtxo) IsRecoverable() bool {
	return v.Swept && !v.Spent
}

func (v Vtxo) Address(server *btcec.PublicKey, net arklib.Network) (string, error) {
	buf, err := hex.DecodeString(v.Script)
	if err != nil {
		return "", err
	}
	pubkeyBytes := buf[2:]

	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return "", err
	}

	a := &arklib.Address{
		HRP:        net.Addr,
		Signer:     server,
		VtxoTapKey: pubkey,
	}

	return a.EncodeV0()
}

type UtxoEventType int

const (
	UtxosAdded UtxoEventType = iota
	UtxosConfirmed
	UtxosReplaced
	UtxosSpent
)

func (e UtxoEventType) String() string {
	return map[UtxoEventType]string{
		UtxosAdded:     "UTXOS_ADDED",
		UtxosConfirmed: "UTXOS_CONFIRMED",
		UtxosReplaced:  "UTXOS_REPLACED",
		UtxosSpent:     "UTXOS_SPENT",
	}[e]
}

type UtxoEvent struct {
	Type  UtxoEventType
	Utxos []Utxo
}

type VtxoEventType int

const (
	VtxosAdded VtxoEventType = iota
	VtxosSpent
	VtxosUpdated
)

func (e VtxoEventType) String() string {
	return map[VtxoEventType]string{
		VtxosAdded:   "VTXOS_ADDED",
		VtxosSpent:   "VTXOS_SPENT",
		VtxosUpdated: "VTXOS_UPDATED",
	}[e]
}

type VtxoEvent struct {
	Type  VtxoEventType
	Vtxos []Vtxo
}

const (
	TxSent     TxType = "SENT"
	TxReceived TxType = "RECEIVED"
)

type TxType string

type TransactionKey struct {
	BoardingTxid   string
	CommitmentTxid string
	ArkTxid        string
}

func (t TransactionKey) String() string {
	return fmt.Sprintf("%s%s%s", t.BoardingTxid, t.CommitmentTxid, t.ArkTxid)
}

type Transaction struct {
	TransactionKey
	Amount      uint64
	Type        TxType
	CreatedAt   time.Time
	Hex         string
	SettledBy   string
	AssetPacket asset.Packet
}

func (t Transaction) String() string {
	buf, _ := json.MarshalIndent(t, "", "  ")
	return string(buf)
}

type TxEventType int

const (
	TxsAdded TxEventType = iota
	TxsSettled
	TxsConfirmed
	TxsReplaced
	TxsUpdated
)

func (e TxEventType) String() string {
	return map[TxEventType]string{
		TxsAdded:     "TXS_ADDED",
		TxsSettled:   "TXS_SETTLED",
		TxsConfirmed: "TXS_CONFIRMED",
		TxsReplaced:  "TXS_REPLACED",
	}[e]
}

type TransactionEvent struct {
	Type         TxEventType
	Txs          []Transaction
	Replacements map[string]string
}

type Utxo struct {
	Outpoint
	Amount      uint64
	Script      string
	Delay       arklib.RelativeLocktime
	SpendableAt time.Time
	CreatedAt   time.Time
	Tapscripts  []string
	Spent       bool
	SpentBy     string
	Tx          string
}

func (u Utxo) ToArkFeeInput() arkfee.OnchainInput {
	return arkfee.OnchainInput{
		Amount: u.Amount,
	}
}

func (u Utxo) IsConfirmed() bool {
	return !u.CreatedAt.IsZero()
}

func (u *Utxo) Sequence() (uint32, error) {
	return arklib.BIP68Sequence(u.Delay)
}

type Receiver struct {
	To       string
	Amount   uint64
	IsChange bool
	Assets   []Asset
}

type VtxoType int

const (
	VtxoTypeNormal VtxoType = iota
	VtxoTypeAsset
)

type DBReceiver struct {
	Receiver
	Index  uint32
	Assets []DBAsset
}

type DBAsset struct {
	AssetId         string
	GroupIndex      uint32
	Amount          uint64
	ExtensionScript []byte
}

func (r Receiver) ToArkFeeOutput() arkfee.Output {
	txout, _, err := r.ToTxOut()
	if err != nil {
		return arkfee.Output{}
	}
	return arkfee.Output{
		Amount: r.Amount,
		Script: hex.EncodeToString(txout.PkScript),
	}
}

func (r Receiver) IsOnchain() bool {
	_, err := btcutil.DecodeAddress(r.To, nil)
	return err == nil
}

func (o Receiver) ToTxOut() (*wire.TxOut, bool, error) {
	var pkScript []byte
	isOnchain := false

	arkAddress, err := arklib.DecodeAddressV0(o.To)
	if err != nil {
		// decode onchain address
		btcAddress, err := btcutil.DecodeAddress(o.To, nil)
		if err != nil {
			return nil, false, err
		}

		pkScript, err = txscript.PayToAddrScript(btcAddress)
		if err != nil {
			return nil, false, err
		}

		isOnchain = true
	} else {
		pkScript, err = script.P2TRScript(arkAddress.VtxoTapKey)
		if err != nil {
			return nil, false, err
		}
	}

	if len(pkScript) == 0 {
		return nil, false, fmt.Errorf("invalid address")
	}

	return &wire.TxOut{
		Value:    int64(o.Amount),
		PkScript: pkScript,
	}, isOnchain, nil
}

type OnchainOutput struct {
	Outpoint
	Script    string
	Amount    uint64
	CreatedAt time.Time
	Spent     bool
	SpentBy   string
}

type OnchainAddressEvent struct {
	Error          error
	SpentUtxos     []OnchainOutput
	NewUtxos       []OnchainOutput
	ConfirmedUtxos []OnchainOutput
	Replacements   map[string]string // replacedTxid -> replacementTxid
}

type SyncEvent struct {
	Synced bool
	Err    error
}

type Metadata struct {
	Key   string
	Value string
}

type AssetModificationParams struct {
	Name   string
	Symbol string
}
