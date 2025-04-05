package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	secp "github.com/btcsuite/btcd/btcec/v2"
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
func addPubKeys(p1, p2 *secp.PublicKey) *secp.PublicKey {
	curve := secp.S256()
	x1, y1 := p1.X(), p1.Y()
	x2, y2 := p2.X(), p2.Y()
	x3, y3 := curve.Add(x1, y1, x2, y2)

	fx := new(secp.FieldVal)
	fy := new(secp.FieldVal)
	fx.SetByteSlice(x3.Bytes())
	fy.SetByteSlice(y3.Bytes())

	return secp.NewPublicKey(fx, fy)
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
func extractNonceFromSig(sig string) (*secp.PublicKey, error) {
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return nil, err
	}
	if len(sigBytes) < 32 {
		return nil, fmt.Errorf("signature too short")
	}

	xBytes := sigBytes[:32]
	compressed := append([]byte{0x02}, xBytes...)
	pubKey, err := secp.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce point: %v", err)
	}

	return pubKey, nil
}

// taggedHash implements BIP340 tagged hashing.
func taggedHash(tag string, msg []byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(msg)

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// schnorrChallenge computes e = Hash(R || P || m) using BIP340 tagged hash.
func schnorrChallenge(R, P *secp.PublicKey, m []byte) [32]byte {
	input := append(R.SerializeCompressed()[1:], P.SerializeCompressed()[1:]...)
	input = append(input, m...)
	return taggedHash("BIP0340/challenge", input)
}

// hex32 returns the hexadecimal string of a 32-byte array.
func hex32(b [32]byte) string {
	return hex.EncodeToString(b[:])
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
		panic(err)
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
	eNostr := schnorrChallenge(rPub, sellerPub, msgHash)
	eScalar := new(secp.ModNScalar)
	eScalar.SetByteSlice(eNostr[:])

	x, y := secp.S256().ScalarMult(sellerPub.X(), sellerPub.Y(), eNostr[:])
	fx, fy := new(secp.FieldVal), new(secp.FieldVal)
	fx.SetByteSlice(x.Bytes())
	fy.SetByteSlice(y.Bytes())
	commitment := addPubKeys(rPub, secp.NewPublicKey(fx, fy))

	fmt.Println("Adaptor Commitment Point (T):", hex.EncodeToString(commitment.SerializeCompressed()))

	buyerNonce := generatePrivKey()
	rBuyer := buyerNonce.PubKey()
	adaptorNonce := addPubKeys(rBuyer, commitment)
	fmt.Println("Adaptor Nonce (R_a):", hex.EncodeToString(adaptorNonce.SerializeCompressed()))

	btcMsg := sha256.Sum256([]byte("bitcoin_transaction_hash"))
	eBtc := schnorrChallenge(adaptorNonce, buyerPub, btcMsg[:])
	eBtcScalar := new(secp.ModNScalar)
	eBtcScalar.SetByteSlice(eBtc[:])

	scalar := &secp.ModNScalar{}
	scalar.Mul2(eBtcScalar, &buyerPriv.Key)
	sAdaptor := &secp.ModNScalar{}
	sAdaptor.Add2(scalar, &buyerNonce.Key)

	fmt.Println("Adaptor Scalar (s_a):", hex32(sAdaptor.Bytes()))

	sigBytes, err := hex.DecodeString(event.Sig)
	if err != nil || len(sigBytes) < 64 {
		panic("invalid signature")
	}

	tSecret := new(secp.ModNScalar)
	tSecret.SetByteSlice(sigBytes[32:])
	fmt.Println("Extracted Secret (t):", hex32(tSecret.Bytes()))

	sFinal := &secp.ModNScalar{}
	sFinal.Add2(sAdaptor, tSecret)
	fmt.Println("Final Signature Scalar (s_c):", hex32(sFinal.Bytes()))

	fmt.Printf("Final Signature: %x%s\n", adaptorNonce.SerializeCompressed(), hex32(sFinal.Bytes()))

	tExtracted := &secp.ModNScalar{}
	tExtracted.Set(sFinal)
	tExtracted.Negate()
	tExtracted.Add(sAdaptor)
	tExtracted.Negate()
	fmt.Println("Recovered t:", hex32(tExtracted.Bytes()))
	fmt.Println("t Match:", tExtracted.Equals(tSecret))

	fmt.Println("\nNostr Event Ready for Broadcast:")
	fmt.Println("ID:", event.ID)
	fmt.Println("Signature:", event.Sig)
}
