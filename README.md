# TANOS

**Taproot Adaptor for Nostr-Orchestrated Swaps**

TANOS is an experimental protocol that enables atomic swaps between Bitcoin and Nostr event signatures using Taproot and adaptor signatures. It explores the intersection of programmable Bitcoin transactions and decentralized identity/event systems.

## 🧠 What is TANOS?

TANOS (Taproot Adaptor for Nostr-Orchestrated Swaps) creates a **trustless** way to exchange Bitcoin for signed Nostr events — such as attestations, credentials, encrypted messages, or access tokens — without relying on trusted third parties.

It leverages:

- 🟠 **Bitcoin Taproot** — enabling advanced spending conditions
- 🔐 **Adaptor Signatures** — allowing conditional signature revelation
- 🌐 **Nostr Protocol** — a censorship-resistant event/message transport layer

Together, these primitives enable a new class of atomic interactions between Bitcoin and decentralized identity/data.

## ⚙️ How it works

1. **The buyer** (payer) wants to receive a Nostr-signed event and is willing to pay BTC for it.
2. A Bitcoin Taproot output is created with a spending condition linked to an adaptor signature.
3. **The seller** (signer) prepares a valid Nostr event and uses an adaptor signature to claim the BTC.
4. When the seller claims the Bitcoin, the adaptor signature reveals the full Nostr signature **on-chain**.
5. If the seller does not act before the timeout, the buyer can refund the BTC — and the Nostr signature is never revealed.

✅ This mechanism is fully **trustless**:
- The buyer cannot lose BTC without receiving the valid signature.
- The seller cannot reveal the signature without receiving the BTC.
- No third party or escrow is required — it's all enforced by cryptography and Bitcoin script.

## 🧪 Use Cases

- Buying Nostr-based credentials or access tokens with BTC
- Decentralized pay-to-write or pay-to-attest systems
- Atomic swaps for encrypted data or commitments
- Bitcoin-backed messaging incentives

## 🔬 Status

This is a proof-of-concept developed for the [MIT Bitcoin Hackathon](https://mitbitcoin.dev/). It is not production-ready — but the ideas might be 😉

## 🔗 Inspiration

This project is inspired by [NIP 455: Atomic Signature Swaps](https://github.com/vstabile/nips/blob/atomic-signature-swaps/XX.md), which proposes a standard for performing atomic swaps of cryptographic signatures over Nostr.

## 📜 License

MIT
