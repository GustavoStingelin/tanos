package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	secp "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/nbd-wtf/go-nostr"
)

// generatePrivKey creates a new secp256k1 private key.
func generatePrivKey() *secp.PrivateKey {
	priv, err := secp.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	return priv
}

// addPubKeys returns the sum of two secp256k1 public keys.
// This implements the EC point addition: R = P1 + P2.
func addPubKeys(p1, p2 *secp.PublicKey) (*secp.PublicKey, error) {
	curve := secp.S256()
	x1, y1 := p1.X(), p1.Y()
	x2, y2 := p2.X(), p2.Y()
	x3, y3 := curve.Add(x1, y1, x2, y2)

	fx := new(secp.FieldVal)
	fy := new(secp.FieldVal)

	if overflow := fx.SetByteSlice(x3.Bytes()); overflow {
		return nil, fmt.Errorf("x-coordinate overflow")
	}
	if overflow := fy.SetByteSlice(y3.Bytes()); overflow {
		return nil, fmt.Errorf("y-coordinate overflow")
	}

	return secp.NewPublicKey(fx, fy), nil
}

// createSignedEvent constructs and signs a nostr event using a given private key.
func createSignedEvent(privKeyHex, content string) (nostr.Event, error) {
	ev := nostr.Event{
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Tags:      []nostr.Tag{},
		Content:   content,
	}

	if privKeyHex != "" {
		pub, err := nostr.GetPublicKey(privKeyHex)
		if err != nil {
			return nostr.Event{}, err
		}
		ev.PubKey = pub
	}

	if err := ev.Sign(privKeyHex); err != nil {
		return nostr.Event{}, err
	}

	return ev, nil
}

// extractNonceFromSig extracts the Schnorr nonce (R value) from a nostr Schnorr signature.
// In BIP340 Schnorr signatures, the first 32 bytes represent the x-coordinate of point R.
func extractNonceFromSig(sig string) (*secp.PublicKey, error) {
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return nil, err
	}
	if len(sigBytes) < 64 {
		return nil, fmt.Errorf("signature too short: %d bytes, expected at least 64", len(sigBytes))
	}

	// In Schnorr signatures, the first 32 bytes are the x-coordinate of nonce R
	xBytes := sigBytes[:32]

	// In BIP340, public keys always have even y-coordinate
	// We need to add a 0x02 prefix byte to indicate even y-coordinate
	compressed := append([]byte{0x02}, xBytes...)
	pubKey, err := secp.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce point: %v", err)
	}

	// Verify the correct length of the compressed point
	if len(compressed) != 33 {
		return nil, fmt.Errorf("invalid compressed pubkey length: %d bytes, expected 33", len(compressed))
	}

	return pubKey, nil
}

// schnorrChallenge computes the BIP340 Schnorr challenge e = hash(R || P || m)
// This is a critical security component of the Schnorr signature scheme.
func schnorrChallenge(R, P *secp.PublicKey, message []byte) *big.Int {
	// We need only the x-coordinate (32 bytes) of both keys
	// According to BIP340, we don't use SerializeCompressed because we only need the x-coordinate

	// Extract x-coordinate of nonce R (32 bytes) with padding
	rBytes := padTo32(R.X().Bytes())

	// Extract x-coordinate of public key P (32 bytes) with padding
	pBytes := padTo32(P.X().Bytes())

	// Construct the input for the hash in the order: R || P || message
	hashInput := append(append(rBytes, pBytes...), message...)

	// Use the tagged hash as per BIP340
	hash := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, hashInput)

	// Convert to big.Int as expected
	return new(big.Int).SetBytes(hash[:])
}

// hex32 returns the hexadecimal string of a 32-byte array.
func hex32(b [32]byte) string {
	return hex.EncodeToString(b[:])
}

// AdaptorSignature encapsulates the data of an adaptor signature.
type AdaptorSignature struct {
	NoncePoint *secp.PublicKey  // R' = R + T
	S          *secp.ModNScalar // s_a = k + e*x
	PubKey     *secp.PublicKey  // P
	Message    []byte           // m
}

// generateSchnorrSignature creates a valid BIP340 Schnorr signature.
// It handles the y-parity requirement by negating s if needed.
func generateSchnorrSignature(R *secp.PublicKey, s *secp.ModNScalar) []byte {
	sAdjusted := new(secp.ModNScalar)
	sAdjusted.Set(s)

	// BIP340 requires the y-coordinate to be even
	if R.Y().Bit(0) == 1 {
		// If Y is odd, we negate s: s = n - s
		sAdjusted.Negate()
	}

	// Serialize: R_x || s
	signature := make([]byte, 64)
	copy(signature, padTo32(R.X().Bytes()))
	copy(signature[32:], serializeModNScalar(sAdjusted))

	return signature
}

// Verify checks if an adaptor signature is valid.
// This verifies the equation: s*G == R' + e*P
func (a *AdaptorSignature) Verify() bool {
	// Compute challenge e = H(R'||P||m)
	eBigInt := schnorrChallenge(a.NoncePoint, a.PubKey, a.Message)

	// Convert big.Int to [32]byte for further processing
	eBytes := padTo32(eBigInt.Bytes())

	// Convert to scalar
	eScalar := new(secp.ModNScalar)
	if overflow := eScalar.SetByteSlice(eBytes); overflow {
		return false // Challenge scalar overflow
	}

	// Verification of the equation: s*G == R' + e*P
	// Converting to curve point calculations:
	// 1. Calculate left side: lhs = s*G
	sBytes := serializeModNScalar(a.S)
	lhsX, lhsY := secp.S256().ScalarBaseMult(sBytes)

	// 2. Calculate e*P
	eBytes = serializeModNScalar(eScalar)
	eX, eY := secp.S256().ScalarMult(a.PubKey.X(), a.PubKey.Y(), eBytes)

	// 3. Calculate right side: rhs = R' + e*P
	rhsX, rhsY := secp.S256().Add(a.NoncePoint.X(), a.NoncePoint.Y(), eX, eY)

	// 4. Verify that lhs == rhs
	return lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0
}

// Complete combines the adaptor signature with the secret.
// Returns s' = s + t where t is the secret.
func (a *AdaptorSignature) Complete(secret *secp.ModNScalar) *secp.ModNScalar {
	// s' = s + t
	sFinal := new(secp.ModNScalar)
	sFinal.Add2(a.S, secret)
	return sFinal
}

// ExtractSecret extracts the secret from a completed signature.
// Returns t = s' - s where s' is the completed signature value.
func (a *AdaptorSignature) ExtractSecret(completedSig *secp.ModNScalar) *secp.ModNScalar {
	// t = s' - s
	t := new(secp.ModNScalar)

	// Set t to s'
	t.Set(completedSig)

	// Compute t = -s
	negS := new(secp.ModNScalar)
	negS.Set(a.S)
	negS.Negate()

	// t = s' + (-s) = s' - s
	t.Add(negS)

	return t
}

// GenerateFinalSignature generates a final Schnorr signature from a completed adaptor signature.
// Applies BIP340 parity rules to ensure the y-coordinate is even.
func (a *AdaptorSignature) GenerateFinalSignature(completedSig *secp.ModNScalar) []byte {
	// Apply BIP340 parity rule - the nonce's y-coordinate must be even
	return generateSchnorrSignature(a.NoncePoint, completedSig)
}

// serializeModNScalar converts a ModNScalar to []byte
func serializeModNScalar(s *secp.ModNScalar) []byte {
	var b [32]byte
	s.PutBytes(&b)
	return b[:]
}

// padTo32 adds left zero-padding to ensure the slice has 32 bytes.
// This is optimized to avoid unnecessary allocations by using a fixed-size array.
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32] // return only the first 32 bytes if larger
	}

	// Create a fixed array and copy directly to the correct position
	var padded [32]byte
	copy(padded[32-len(b):], b) // copy directly at the right position
	return padded[:]
}

// createBitcoinP2TRAddress creates a Pay-to-Taproot address from a public key.
// It implements the BIP341 specification for Taproot addresses.
func createBitcoinP2TRAddress(pubKey *secp.PublicKey, params *chaincfg.Params) (string, []byte, error) {
	// For BIP341, we need the "x-only" public key (only the x-coordinate)
	//
	// Note on future improvements:
	// Instead of manually implementing the BIP341 tweaking, schnorr.TweakPubKey()
	// could be used when this function becomes available in a future library.
	// This would simplify the Taproot tweak calculation and ensure full compatibility
	// with the Bitcoin protocol.
	//
	// Example future pseudocode:
	// tweakedKey, _ := schnorr.TweakPubKey(pubKey, nil) // nil for key-only spending path
	// witnessProgram := tweakedKey.XBytes() // get only the 32 bytes of x-coordinate

	// Extract the x-coordinate as an x-only pubkey (32 bytes)
	xOnly := padTo32(pubKey.X().Bytes())

	// Calculate the Taproot tweak according to BIP341
	tweakHash := chainhash.TaggedHash(chainhash.TagTapTweak, xOnly)

	// Create a ModNScalar from the tweak hash
	tweakScalar := new(secp.ModNScalar)
	if overflow := tweakScalar.SetByteSlice(tweakHash[:]); overflow {
		return "", nil, fmt.Errorf("tweak overflow")
	}

	// Calculate the tweaked key: P' = P + t*G
	tweakPrivKey := secp.PrivKeyFromScalar(tweakScalar)
	tweakPubKey := tweakPrivKey.PubKey()

	// Calculate P + H(P||c)*G
	tweakedPubKey, err := addPubKeys(pubKey, tweakPubKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to add public keys: %v", err)
	}

	// Extract the x-coordinate of the tweakedPubKey as an x-only pubkey (32 bytes)
	witnessProgram := padTo32(tweakedPubKey.X().Bytes())

	// Sanity check that we have exactly 32 bytes
	if len(witnessProgram) != 32 {
		return "", nil, fmt.Errorf("invalid witness program length: %d, expected 32", len(witnessProgram))
	}

	// Create the P2TR script
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_1) // SegWit version 1 (taproot)
	builder.AddData(witnessProgram)
	pkScript, err := builder.Script()
	if err != nil {
		return "", nil, err
	}

	// Create a valid bech32m Taproot address using btcutil
	taprootAddress, err := btcutil.NewAddressTaproot(witnessProgram, params)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create taproot address: %v", err)
	}

	return taprootAddress.String(), pkScript, nil
}

// createLockingTransaction creates a Bitcoin transaction that locks coins to a P2TR address.
// This transaction represents the funding transaction in the atomic swap.
func createLockingTransaction(buyerPubKey *secp.PublicKey, amount int64, params *chaincfg.Params) (*wire.MsgTx, []byte, error) {
	// Create a new transaction
	tx := wire.NewMsgTx(2) // Version 2 for taproot support

	// Add a dummy input for demo purposes
	prevHash, _ := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000000")
	prevOut := wire.NewOutPoint(prevHash, 0)
	txIn := wire.NewTxIn(prevOut, nil, nil)
	tx.AddTxIn(txIn)

	// Create a P2TR address and script for the output
	_, pkScript, err := createBitcoinP2TRAddress(buyerPubKey, params)
	if err != nil {
		return nil, nil, err
	}

	// Add the output
	txOut := wire.NewTxOut(amount, pkScript)
	tx.AddTxOut(txOut)

	return tx, pkScript, nil
}

// createAdaptorSignature creates an adaptor signature using the Schnorr scheme.
// This implements the key part of the atomic swap protocol - creating a
// signature that will reveal a secret when completed.
func createAdaptorSignature(privateKey *secp.PrivateKey, adaptorPoint *secp.PublicKey, message []byte) (*AdaptorSignature, error) {
	// Generate a random nonce (k)
	k := generatePrivKey()
	R := k.PubKey()

	// Compute the adaptor nonce point R' = R + T
	adaptorNonce, err := addPubKeys(R, adaptorPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to add pubkeys for adaptor nonce: %v", err)
	}

	// Compute challenge e = H(R'||P||m)
	P := privateKey.PubKey()
	eBigInt := schnorrChallenge(adaptorNonce, P, message)

	// Convert big.Int to [32]byte for further processing
	eBytes := padTo32(eBigInt.Bytes())

	// Convert to scalar
	eScalar := new(secp.ModNScalar)
	if overflow := eScalar.SetByteSlice(eBytes); overflow {
		return nil, fmt.Errorf("challenge scalar overflow")
	}

	// s = k + e*x
	xScalar := new(secp.ModNScalar)
	xScalar.Set(&privateKey.Key)

	// e*x
	exScalar := new(secp.ModNScalar)
	exScalar.Mul2(eScalar, xScalar)

	// k + e*x
	sAdaptor := new(secp.ModNScalar)
	kScalar := new(secp.ModNScalar)
	kScalar.Set(&k.Key)
	sAdaptor.Add2(exScalar, kScalar)

	return &AdaptorSignature{
		NoncePoint: adaptorNonce,
		S:          sAdaptor,
		PubKey:     P,
		Message:    message,
	}, nil
}

// serializeTx serializes a Bitcoin transaction to hex.
func serializeTx(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

// calculateSighash calculates the signature hash for a taproot input.
// This is a simplified version for demonstration purposes.
func calculateSighash(tx *wire.MsgTx, inputIndex int, scriptPubKey []byte) ([]byte, error) {
	// This is a simplified sighash calculation for demonstration purposes
	// In a real implementation, you would use the proper taproot sighash algorithm

	// For now, we'll use a simple hash of the transaction
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}

	// Add the output script being spent for context
	buf.Write(scriptPubKey)

	// Hash the data
	hash := sha256.Sum256(buf.Bytes())
	return hash[:], nil
}

func main() {
	fmt.Println("TANOS: Taproot Adaptor for Nostr-Orchestrated Swaps")
	fmt.Println("------------------------------------------------------")

	// Generate seller's key (also used for nostr signing).
	sellerPrivHex := nostr.GeneratePrivateKey()
	fmt.Println("Seller Private Key:", sellerPrivHex)

	sellerPrivBytes, err := hex.DecodeString(sellerPrivHex)
	if err != nil {
		panic(fmt.Errorf("invalid seller private key: %v", err))
	}
	sellerPriv, _ := secp.PrivKeyFromBytes(sellerPrivBytes)
	sellerPub := sellerPriv.PubKey()

	buyerPriv := generatePrivKey()
	buyerPub := buyerPriv.PubKey()
	fmt.Println("Buyer Public Key:", hex.EncodeToString(buyerPub.SerializeCompressed()))

	event, err := createSignedEvent(sellerPrivHex, "Nostr event for TANOS atomic swap")
	if err != nil {
		panic(err)
	}

	nostrPub, err := nostr.GetPublicKey(sellerPrivHex)
	if err != nil {
		panic(fmt.Errorf("failed to get public key from nostr private key: %v", err))
	}
	fmt.Println("Seller Public Key:", nostrPub)
	fmt.Println("Event ID:", event.ID)
	fmt.Println("Signature:", event.Sig)

	rPub, err := extractNonceFromSig(event.Sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("Nonce R (from nostr sig):", hex.EncodeToString(rPub.SerializeCompressed()))

	msgHash := []byte(event.ID)
	eBigInt := schnorrChallenge(rPub, sellerPub, msgHash)

	// Convert big.Int to [32]byte for further processing
	eNostr := padTo32(eBigInt.Bytes())

	eScalar := new(secp.ModNScalar)
	if overflow := eScalar.SetByteSlice(eNostr); overflow {
		panic(fmt.Errorf("challenge scalar overflow"))
	}

	// Compute eP = e*P
	x, y := secp.S256().ScalarMult(sellerPub.X(), sellerPub.Y(), eNostr)
	fx, fy := new(secp.FieldVal), new(secp.FieldVal)
	if overflow := fx.SetByteSlice(x.Bytes()); overflow {
		panic(fmt.Errorf("x-coordinate overflow in scalar multiplication"))
	}
	if overflow := fy.SetByteSlice(y.Bytes()); overflow {
		panic(fmt.Errorf("y-coordinate overflow in scalar multiplication"))
	}

	// Compute R + eP
	commitment, err := addPubKeys(rPub, secp.NewPublicKey(fx, fy))
	if err != nil {
		panic(fmt.Errorf("failed to add pubkeys for commitment: %v", err))
	}

	fmt.Println("Adaptor Commitment Point (T):", hex.EncodeToString(commitment.SerializeCompressed()))

	// Bitcoin transaction setup
	fmt.Println("\n--- Bitcoin Transaction Setup ---")

	// Use the testnet for development
	params := &chaincfg.TestNet3Params

	// 1. Buyer creates a locking transaction
	lockAmount := int64(100000) // 0.001 BTC in satoshis
	lockTx, lockScript, err := createLockingTransaction(buyerPub, lockAmount, params)
	if err != nil {
		panic(fmt.Errorf("failed to create locking transaction: %v", err))
	}

	// Serialize transaction for display
	lockTxHex, err := serializeTx(lockTx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Locking Transaction (hex):", lockTxHex)

	// 2. Calculate the signature hash for the transaction
	sigHash, err := calculateSighash(lockTx, 0, lockScript)
	if err != nil {
		panic(fmt.Errorf("failed to calculate signature hash: %v", err))
	}

	// 3. Buyer creates an adaptor signature using the Nostr commitment as the adaptor point
	adaptorSig, err := createAdaptorSignature(buyerPriv, commitment, sigHash)
	if err != nil {
		panic(fmt.Errorf("failed to create adaptor signature: %v", err))
	}

	fmt.Println("Bitcoin Adaptor Nonce:", hex.EncodeToString(adaptorSig.NoncePoint.SerializeCompressed()))
	adaptorNonceBytes := adaptorSig.NoncePoint.SerializeCompressed()

	// Serialize the adaptor signature for display
	adaptorSigBytes := serializeModNScalar(adaptorSig.S)
	fmt.Println("Bitcoin Adaptor Signature:", hex.EncodeToString(adaptorSigBytes))

	// 4. Verify the adaptor signature
	if adaptorSig.Verify() {
		fmt.Println("Bitcoin adaptor signature verification: VALID")
	} else {
		fmt.Println("Bitcoin adaptor signature verification: INVALID")
	}

	// 5. Continue with the Nostr part of the protocol
	fmt.Println("Adaptor Nonce (R_a):", hex.EncodeToString(adaptorNonceBytes))

	// Using the same adaptorSig instead of recalculating a new one
	fmt.Println("Adaptor Scalar (s_a):", hex.EncodeToString(adaptorSigBytes))

	// 6. Extract the secret from the Nostr signature
	sigBytes, err := hex.DecodeString(event.Sig)
	if err != nil || len(sigBytes) < 64 {
		panic("invalid signature")
	}

	tSecret := new(secp.ModNScalar)
	if overflow := tSecret.SetByteSlice(sigBytes[32:]); overflow {
		panic(fmt.Errorf("secret scalar overflow in signature"))
	}
	tSecretBytes := serializeModNScalar(tSecret)
	fmt.Println("Extracted Secret (t):", hex.EncodeToString(tSecretBytes))

	// 7. Swap execution - Seller completes the Bitcoin signature
	fmt.Println("\n--- Swap Execution ---")
	fmt.Println("Seller completes the Bitcoin adaptor signature with the Nostr secret...")

	completedSig := adaptorSig.Complete(tSecret)
	completedSigBytes := serializeModNScalar(completedSig)
	fmt.Println("Completed Bitcoin Signature:", hex.EncodeToString(completedSigBytes))

	// 8. Create a valid Schnorr signature for the transaction
	schnorrSig := adaptorSig.GenerateFinalSignature(completedSig)
	fmt.Println("Final Bitcoin Schnorr Signature:", hex.EncodeToString(schnorrSig))

	// 9. In a real implementation, this signature would be validated
	// and included in the transaction's witness data for broadcast
	fmt.Println("Bitcoin signature ready for inclusion in transaction witness.")

	// 10. Buyer extracts the secret from the completed signature
	fmt.Println("\nBuyer extracts the Nostr secret from the Bitcoin signature...")
	extractedSecret := adaptorSig.ExtractSecret(completedSig)
	extractedSecretBytes := serializeModNScalar(extractedSecret)
	fmt.Println("Extracted Nostr Secret:", hex.EncodeToString(extractedSecretBytes))

	// 11. Verify the extracted secret matches the original
	secretMatches := extractedSecret.Equals(tSecret)
	fmt.Printf("Secret verification: %v\n", secretMatches)

	// 12. Complete the Nostr part of the protocol
	sFinal := &secp.ModNScalar{}
	sFinal.Add2(adaptorSig.S, tSecret)
	sFinalBytes := serializeModNScalar(sFinal)
	fmt.Println("Final Signature Scalar (s_c):", hex.EncodeToString(sFinalBytes))

	fmt.Printf("Final Signature: %x%s\n",
		adaptorNonceBytes[1:33],
		hex.EncodeToString(sFinalBytes))

	// Extract secret using the method to verify match
	finalExtracted := adaptorSig.ExtractSecret(sFinal)
	finalExtractedBytes := serializeModNScalar(finalExtracted)
	fmt.Println("Recovered t:", hex.EncodeToString(finalExtractedBytes))
	fmt.Println("t Match:", finalExtracted.Equals(tSecret))

	fmt.Println("\nNostr Event Ready for Broadcast:")
	fmt.Println("ID:", event.ID)
	fmt.Println("Signature:", event.Sig)

	// 13. Bitcoin transaction ready for broadcast
	fmt.Println("\nBitcoin Transaction Ready for Broadcast")
	fmt.Println("Transaction hash:", lockTx.TxHash().String())
}
