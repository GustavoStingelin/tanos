// Package bitcoin provides functionality for working with Bitcoin transactions,
// particularly focusing on Taproot (P2TR) address creation and transaction handling.
package bitcoin

import (
	"bytes"
	"fmt"

	secp "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"tanos/pkg/adaptor"
	"tanos/pkg/crypto"
)

// CreateLockingTransaction creates a Bitcoin transaction that locks coins to a P2TR address.
// This transaction represents the funding transaction in the atomic swap.
func CreateLockingTransaction(
	buyerPubKey *secp.PublicKey,
	amount int64,
	prevTxID string,
	prevOutputIndex uint32,
	params *chaincfg.Params,
) (*wire.MsgTx, []byte, error) {
	// Create a new transaction
	tx := wire.NewMsgTx(2) // Version 2 for taproot support

	// Parse previous transaction ID
	prevHash, err := chainhash.NewHashFromStr(prevTxID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid previous transaction ID: %v", err)
	}

	// Add the input using the provided previous outpoint
	prevOut := wire.NewOutPoint(prevHash, prevOutputIndex)
	txIn := wire.NewTxIn(prevOut, nil, nil)
	tx.AddTxIn(txIn)

	// Create a P2TR script for the output using the buyer's key.
	tapKey := txscript.ComputeTaprootKeyNoScript(buyerPubKey)
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return nil, nil, err
	}

	// Add the output
	txOut := wire.NewTxOut(amount, pkScript)
	tx.AddTxOut(txOut)

	return tx, pkScript, nil
}

// SerializeTx serializes a Bitcoin transaction to hex.
func SerializeTx(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return crypto.HexEncode(buf.Bytes()), nil
}

// CreateSpendingTransaction creates a Bitcoin transaction that spends a previous UTXO
// and locks the funds in a new Taproot output that can be spent with an adaptor signature.
// This enables passing funds from one atomic swap to another by spending previous outputs.
func CreateSpendingTransaction(
	prevTxID string,
	prevOutputIndex uint32,
	prevOutputValue int64,
	prevOutputScript []byte,
	fee int64,
	signerPrivKey *secp.PrivateKey,
	newOutputPubKey *secp.PublicKey,
	params *chaincfg.Params,
) (*wire.MsgTx, []byte, error) {
	// Parse previous transaction ID
	prevHash, err := chainhash.NewHashFromStr(prevTxID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid previous transaction ID: %v", err)
	}

	// Create previous outpoint reference
	prevOut := wire.NewOutPoint(prevHash, prevOutputIndex)

	// Create a new transaction
	tx := wire.NewMsgTx(2) // Version 2 for taproot support

	// Add the input
	txIn := wire.NewTxIn(prevOut, nil, nil)
	tx.AddTxIn(txIn)

	// Create a P2TR script for the new output.
	tapKey := txscript.ComputeTaprootKeyNoScript(newOutputPubKey)
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create taproot output: %v", err)
	}

	// Add the output (with amount minus fee)
	outputAmount := prevOutputValue - fee
	if outputAmount <= 0 {
		return nil, nil, fmt.Errorf("fee too high: %d, exceeds amount: %d", fee, prevOutputValue)
	}
	txOut := wire.NewTxOut(outputAmount, pkScript)
	tx.AddTxOut(txOut)

	prevFetcher := txscript.NewCannedPrevOutputFetcher(prevOutputScript, prevOutputValue)
	sigHashes := txscript.NewTxSigHashes(tx, prevFetcher)

	sig, err := txscript.RawTxInTaprootSignature(
		tx, sigHashes, 0, prevOutputValue, prevOutputScript, []byte{},
		txscript.SigHashDefault, signerPrivKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create schnorr signature: %v", err)
	}

	tx.TxIn[0].Witness = wire.TxWitness{sig}

	return tx, pkScript, nil
}

// CreateNostrSignatureLockScript creates a Taproot script that locks funds
// to be spent only with a valid Nostr signature. It uses the commitment
// point derived from the Nostr event's signature nonce.
//
// The script is constructed with the following spending path:
// 1. Key path: the Nostr public key, tweaked with the commitment
// 2. Script path (optional): can include additional spending conditions
//
// When used in conjunction with adaptor signatures, this enables atomic swaps
// between Bitcoin and Nostr events, as the act of spending the output reveals
// the secret needed to recover the Nostr signature.
func CreateNostrSignatureLockScript(
	nostrPubKey *secp.PublicKey,
	commitment *secp.PublicKey,
	params *chaincfg.Params,
) (string, []byte, error) {
	// Combine the nostrPubKey and commitment to create a tweaked key
	// that can only be spent with knowledge of the Nostr signature
	tweakedKey, err := adaptor.AddPubKeys(nostrPubKey, commitment)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create tweaked key: %v", err)
	}

	// Generate a P2TR script and corresponding address using the tweaked key.
	tapKey := txscript.ComputeTaprootKeyNoScript(tweakedKey)
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create taproot output: %v", err)
	}

	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), params)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create taproot address: %v", err)
	}

	return addr.String(), pkScript, nil
}
