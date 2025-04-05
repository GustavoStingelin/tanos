// An example implementation of a TANOS (Taproot Adaptor for Nostr-Orchestrated Swaps) atomic swap.
// This demonstrates how to use the TANOS library to swap a Nostr event signature for Bitcoin.
package main

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"

	"tanos/pkg/bitcoin"
	"tanos/pkg/crypto"
	"tanos/pkg/nostr"
	"tanos/pkg/tanos"
)

func main() {
	fmt.Println("TANOS: Taproot Adaptor for Nostr-Orchestrated Swaps")
	fmt.Println("------------------------------------------------------")

	// Step 1: Create a seller (Nostr content creator)
	// The seller has a Nostr private key and wants to sell a signed event
	sellerPrivKey := nostr.GeneratePrivateKey()
	fmt.Println("Seller Private Key:", sellerPrivKey)

	seller, err := tanos.NewSeller(sellerPrivKey)
	if err != nil {
		panic(fmt.Errorf("failed to create seller: %v", err))
	}

	fmt.Println("Seller Public Key:", seller.NostrPubKey)

	// Step 2: Create a buyer (Bitcoin holder)
	// The buyer wants to purchase access to the Nostr event
	buyer, err := tanos.NewBuyer()
	if err != nil {
		panic(fmt.Errorf("failed to create buyer: %v", err))
	}

	fmt.Println("Buyer Public Key:", crypto.HexEncode(buyer.PublicKey.SerializeCompressed()))

	// Step 3: Seller creates a Nostr event
	err = seller.CreateEvent("Nostr event for TANOS atomic swap")
	if err != nil {
		panic(fmt.Errorf("failed to create event: %v", err))
	}

	fmt.Println("Event ID:", seller.Event.ID)
	fmt.Println("Signature:", seller.Event.Sig)
	fmt.Println("Nonce R (from nostr sig):", crypto.HexEncode(seller.Nonce.SerializeCompressed()))
	fmt.Println("Adaptor Commitment Point (T):", crypto.HexEncode(seller.Commitment.SerializeCompressed()))

	// Step 4: Buyer creates a Bitcoin transaction with funds
	fmt.Println("\n--- Bitcoin Transaction Setup ---")

	// Use the testnet for development
	params := &chaincfg.TestNet3Params

	err = buyer.CreateLockingTransaction(100000, params) // 0.001 BTC in satoshis
	if err != nil {
		panic(fmt.Errorf("failed to create locking transaction: %v", err))
	}

	// Serialize transaction for display
	lockTxHex, err := bitcoin.SerializeTx(buyer.LockingTx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Locking Transaction (hex):", lockTxHex)

	// Step 5: Buyer creates an adaptor signature
	err = buyer.CreateAdaptorSignature(seller.Commitment)
	if err != nil {
		panic(fmt.Errorf("failed to create adaptor signature: %v", err))
	}

	fmt.Println("Bitcoin Adaptor Nonce:", crypto.HexEncode(buyer.AdaptorSig.NoncePoint.SerializeCompressed()))
	fmt.Println("Bitcoin Adaptor Signature:", crypto.HexEncode(crypto.SerializeModNScalar(buyer.AdaptorSig.S)))

	// Step 6: Verify the adaptor signature
	isOdd := buyer.AdaptorSig.NoncePoint.Y().Bit(0) == 1
	fmt.Println("Adaptor nonce R'.Y is odd:", isOdd, "(affects BIP340 verification)")

	if buyer.VerifyAdaptorSignature(seller.Commitment) {
		fmt.Println("Bitcoin adaptor signature verification: VALID")
	} else {
		fmt.Println("Bitcoin adaptor signature verification: INVALID")
	}

	// Step 7: Extract secret from Nostr signature for verification
	secret, err := nostr.ExtractSecretFromSignature(seller.Event.Sig)
	if err != nil {
		panic(fmt.Errorf("failed to extract secret: %v", err))
	}

	fmt.Println("Extracted Secret (t):", crypto.HexEncode(crypto.SerializeModNScalar(secret)))

	// Step 8: Swap execution - Seller completes the Bitcoin signature
	fmt.Println("\n--- Swap Execution ---")
	fmt.Println("Seller completes the Bitcoin adaptor signature with the Nostr secret...")

	finalSig, err := buyer.CompleteAdaptorSignature(seller.Event.Sig)
	if err != nil {
		panic(fmt.Errorf("failed to complete adaptor signature: %v", err))
	}

	// Display the final signature
	fmt.Println("Final Bitcoin Schnorr Signature:", crypto.HexEncode(finalSig))
	fmt.Println("Bitcoin signature ready for inclusion in transaction witness.")

	// Step 9: Buyer verifies the secret matches
	fmt.Println("\nBuyer extracts the secret from the Bitcoin signature...")

	// Extract the secret from the completed signature
	completedSigBytes := finalSig[32:]

	// Create a ModNScalar and set it from the completed signature bytes
	completedSigScalar := new(btcec.ModNScalar)
	if overflow := completedSigScalar.SetByteSlice(completedSigBytes); overflow {
		panic(fmt.Errorf("scalar overflow in completed signature"))
	}

	// Debug: print the extracted values
	fmt.Println("Completed Sig S Portion:", crypto.HexEncode(completedSigBytes))

	// Get the secret directly for comparison
	nostrSecret, err := nostr.ExtractSecretFromSignature(seller.Event.Sig)
	if err != nil {
		panic(fmt.Errorf("failed to extract Nostr secret: %v", err))
	}
	secretBytes := crypto.SerializeModNScalar(nostrSecret)
	fmt.Println("Nostr Secret Directly:", crypto.HexEncode(secretBytes))

	// Extract the secret using the adaptor signature
	extractedSecret := buyer.AdaptorSig.ExtractSecret(completedSigScalar)
	extractedSecretBytes := crypto.SerializeModNScalar(extractedSecret)
	fmt.Println("Extracted Secret via Adaptor:", crypto.HexEncode(extractedSecretBytes))

	// When R'.Y is odd, BIP340 requires special handling
	if buyer.AdaptorSig.NoncePoint.Y().Bit(0) == 1 {
		fmt.Println("DEBUG: Negation needed for BIP340 compatibility.")

		// Try negating the extracted secret to see if it matches
		negatedExtractedSecret := new(btcec.ModNScalar)
		negatedExtractedSecret.Set(extractedSecret)
		negatedExtractedSecret.Negate()

		negatedBytes := crypto.SerializeModNScalar(negatedExtractedSecret)
		fmt.Println("Negated Extracted Secret:", crypto.HexEncode(negatedBytes))

		// Check if the negated secret matches
		negatedMatches := bytes.Equal(negatedBytes, secretBytes)
		fmt.Println("Negated secret matches:", negatedMatches)

		// Run in-depth debugging for BIP340 parity issues
		fmt.Println("\n--- Debug BIP340 Adaptor Signature ---")
		debugResults := buyer.DebugAdaptorSignature(completedSigScalar, nostrSecret)
		for k, v := range debugResults {
			fmt.Printf("  %s: %s\n", k, v)
		}
		fmt.Println("---------------------------------------")
	}

	// Verify the secret matches
	matches, err := buyer.VerifyNostrSecret(completedSigScalar, seller.Event.Sig)
	if err != nil {
		panic(fmt.Errorf("failed to verify secret: %v", err))
	}

	fmt.Printf("Secret verification: %v\n", matches)

	// Step 10: Summary
	fmt.Println("\nNostr Event Ready for Broadcast:")
	fmt.Println("ID:", seller.Event.ID)
	fmt.Println("Signature:", seller.Event.Sig)

	fmt.Println("\nBitcoin Transaction Ready for Broadcast")
	fmt.Println("Transaction hash:", buyer.LockingTx.TxHash().String())
}
