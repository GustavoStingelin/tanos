package main

import (
	"crypto/sha256"
	"fmt"

	secp "github.com/btcsuite/btcd/btcec/v2"
)

func randPrivKey() *secp.PrivateKey {
	priv, err := secp.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	return priv
}

func addPoints(p1, p2 *secp.PublicKey) *secp.PublicKey {
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

func main() {
	// 1. Seller: private key
	sellerPrivKey := randPrivKey()
	sellerPub := sellerPrivKey.PubKey()

	// 2. Buyer: twist (preimage + public point)
	twistPrivKey := randPrivKey()
	twistPub := twistPrivKey.PubKey()

	// 3. Message to be signed (hash of Nostr event)
	msg := sha256.Sum256([]byte("event_id_abc123"))

	// 4. Seller generates standard Schnorr signature
	k := randPrivKey()
	R := k.PubKey()

	// R' = R + T
	Rprime := addPoints(R, twistPub)

	// e = H(R' || P || m)
	hashInput := append(Rprime.SerializeCompressed(), sellerPub.SerializeCompressed()...)
	hashInput = append(hashInput, msg[:]...)
	e := sha256.Sum256(hashInput)
	eInt := new(secp.ModNScalar)
	eInt.SetByteSlice(e[:])

	// s = k + ex
	eMulX := &secp.ModNScalar{}
	eMulX.Mul2(eInt, &sellerPrivKey.Key)

	s := &secp.ModNScalar{}
	s.Add2(eMulX, &k.Key)

	// s' = s + t
	sPrime := &secp.ModNScalar{}

	sPrime.Add2(s, &twistPrivKey.Key)

	fmt.Println(">> Adaptor Signature (s'):", sPrime.Bytes())
	fmt.Println(">> R':", Rprime.SerializeCompressed())

	// Now: s' is the final signature (schnorr) with R'
	// And the buyer wants to extract t = s' - s

	// 5. Buyer extracts t
	tExtracted := &secp.ModNScalar{}
	tExtracted.Set(sPrime)
	tExtracted.Negate()
	tExtracted.Add(s)   // t = -s' + s = -(s' - s)
	tExtracted.Negate() // t = s' - s

	equal := twistPrivKey.Key.Equals(tExtracted)
	fmt.Println(">> Original twist:", twistPrivKey.Key.Bytes())
	fmt.Println(">> Extracted twist:", tExtracted.Bytes())
	fmt.Println(">> Match?", equal)
}
