# TANOS: Taproot Adaptor for Nostr-Orchestrated Swaps

TANOS is a library implementing atomic swaps between Bitcoin and Nostr, using Taproot and Schnorr adaptor signatures, developed for the [MIT Bitcoin Hackathon](https://mitbitcoin.dev/).

## Overview

TANOS allows atomic swaps between:
- Bitcoin transactions using Taproot P2TR addresses
- Nostr events with Schnorr signatures

The protocol uses adaptor signatures to ensure atomicity: the buyer only gets the signed Nostr event if they pay with Bitcoin, and the seller only gets the Bitcoin if they reveal the secret from the Nostr signature.

## Inspiration

This project is inspired by [NIP 455: Atomic Signature Swaps](https://github.com/vstabile/nips/blob/atomic-signature-swaps/XX.md), which proposes a standard for performing atomic swaps of cryptographic signatures over Nostr.

## Features

- BIP340-compliant Schnorr adaptor signatures
- Taproot address creation and transaction handling
- Nostr event creation and signing
- Complete atomic swap protocol implementation
- Pure Go implementation

## Project Structure

The project is organized into the following packages:

- `pkg/adaptor` - Adaptor signature implementation using Schnorr
- `pkg/bitcoin` - Bitcoin-related functionality (Taproot, transactions)
- `pkg/crypto` - Common cryptographic utilities
- `pkg/nostr` - Nostr-related functionality
- `pkg/tanos` - High-level swap protocol implementation
- `examples/swap` - Example implementation of a complete swap

## Getting Started

### Prerequisites

- Go 1.24.1 or later
- Bitcoin and Nostr dependencies

### Installation

```bash
git clone https://github.com/GustavoStingelin/tanos.git
cd tanos
go mod download
```

### Running the Example

```bash
go run examples/swap/main.go
```

## The Swap Protocol

1. **Setup**:
   - Seller has a Nostr private key
   - Buyer has Bitcoin

2. **Commitment**:
   - Seller creates and signs a Nostr event
   - Seller extracts the nonce (R) from the signature
   - Seller computes the commitment T = R + e*P

3. **Locking**:
   - Buyer creates a Bitcoin transaction locking funds to a P2TR address
   - Buyer creates an adaptor signature using the commitment T
   - Buyer sends the adaptor signature to the seller

4. **Revealing**:
   - Seller completes the adaptor signature using the secret from the Nostr signature
   - Seller broadcasts the Bitcoin transaction with the completed signature

5. **Verification**:
   - Buyer extracts the secret from the completed signature
   - Buyer verifies that the secret matches the one in the Nostr signature

## Security Considerations

### BIP340 Parity Rules

TANOS carefully implements BIP340 parity rules for Schnorr signatures. According to the specification:

- Schnorr signatures in BIP340 require the Y-coordinate of the nonce point (R) to be even
- When the Y-coordinate is odd, the signature value 's' must be negated
- This affects how secrets are extracted from completed signatures

This implementation automatically handles these parity adjustments, ensuring that:
1. Generated Bitcoin signatures are valid according to BIP340
2. Secrets extracted from signatures are correctly recovered, even after parity adjustments

### Tagged Hashes

For enhanced security, the library uses BIP340-style tagged hashes for all signature challenges, ensuring signatures from different contexts cannot be reused.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- BIP340 (Schnorr Signatures)
- BIP341 (Taproot)
- Nostr Protocol
- [MIT Bitcoin Hackathon](https://mitbitcoin.dev/)
- [NIP 455: Atomic Signature Swaps](https://github.com/vstabile/nips/blob/atomic-signature-swaps/XX.md)
