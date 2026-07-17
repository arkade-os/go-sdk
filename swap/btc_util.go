package swap

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lntypes"
)

type claimTransactionParams struct {
	lockupTxid      string
	lockupVout      uint32
	lockupAmount    uint64
	destinationAddr string
	network         *chaincfg.Params
}

// constructClaimTransaction creates a transaction to claim BTC lockup
// This constructs a bare transaction skeleton that will be signed with MuSig2 (key path)
// or Schnorr signature (script path)
func constructClaimTransaction(
	explorerSvc explorer.Explorer, dustAmount uint64, params claimTransactionParams,
) (*wire.MsgTx, error) {
	lockupHash, err := chainhash.NewHashFromStr(params.lockupTxid)
	if err != nil {
		return nil, fmt.Errorf("invalid lockup txid: %w", err)
	}

	destAddr, err := btcutil.DecodeAddress(params.destinationAddr, params.network)
	if err != nil {
		return nil, fmt.Errorf("invalid destination address: %w", err)
	}

	tx := wire.NewMsgTx(2)

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *lockupHash,
			Index: params.lockupVout,
		},
		Sequence: wire.MaxTxInSequenceNum,
	})

	pkScript, err := payToAddrScript(destAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create output script: %w", err)
	}

	tx.AddTxOut(&wire.TxOut{
		Value:    int64(params.lockupAmount),
		PkScript: pkScript,
	})

	vbytes := computeVSize(tx)

	feeRate, err := explorerSvc.GetFeeRate()
	if err != nil {
		return nil, err
	}

	feeAmount := uint64(math.Ceil(float64(vbytes)*feeRate) + 100)
	if params.lockupAmount-feeAmount <= dustAmount {
		return nil, fmt.Errorf("not enough funds to cover network fees")
	}

	tx.TxOut[0].Value = int64(params.lockupAmount - feeAmount)

	return tx, nil
}

func computeVSize(tx *wire.MsgTx) lntypes.VByte {
	baseSize := tx.SerializeSizeStripped()
	totalSize := tx.SerializeSize() // including witness
	weight := totalSize + baseSize*3
	return lntypes.WeightUnit(uint64(weight)).ToVB()
}

func payToAddrScript(addr btcutil.Address) ([]byte, error) {
	switch addr.(type) {
	case *btcutil.AddressWitnessPubKeyHash,
		*btcutil.AddressWitnessScriptHash,
		*btcutil.AddressTaproot:
		// Witness addresses supported
		return txscript.PayToAddrScript(addr)
	default:
		return nil, fmt.Errorf("unsupported address type: %T", addr)
	}
}

func serializeTransaction(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %w", err)
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func deserializeTransaction(txHex string) (*wire.MsgTx, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction: %w", err)
	}

	return tx, nil
}

func networkNameToParams(networkName string) *chaincfg.Params {
	switch networkName {
	case arklib.Bitcoin.Name:
		return &chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case arklib.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	case arklib.BitcoinSigNet.Name, arklib.BitcoinMutinyNet.Name:
		return &chaincfg.SigNetParams
	default:
		return &chaincfg.RegressionNetParams
	}
}
