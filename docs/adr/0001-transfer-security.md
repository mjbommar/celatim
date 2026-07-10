# ADR 0001: Transfer Security Uses TLS 1.3 With Offer-Bound Pinning

## Status

Accepted for the first product provider.

## Context

Celatim needs authenticated encrypted file transfer before any network product pilot.
The package must not invent a cipher, record layer, handshake, KDF, or nonce schedule.
The first user workflow also needs to work without a public PKI or Celatim account
service.

## Decision

The first direct provider uses the platform TLS implementation through Python's `ssl`
module with TLS 1.3 as the minimum and maximum protocol version. The receiver creates
an ephemeral self-signed certificate for a listener. The transfer offer includes the
SHA-256 fingerprint of its DER certificate and a cryptographically random, single-use
access token.

The sender opens TLS without using the public CA set, reads the peer certificate before
sending application data, and compares its fingerprint with the exact value in the
offer using a constant-time comparison. A mismatch terminates the connection. The
receiver accepts the transfer protocol only after the access token and offer id match
an active offer.

This authenticates the endpoint named by the exact offer, not a natural person. The
receipt labels this trust mode `offer_bound`. A future verified-contact mode must bind
the offer to a separately verified long-term identity before it may claim person-level
authentication.

TLS protects manifests, chunks, acknowledgements, and completion receipts. SHA-256 file
and chunk digests detect local storage corruption and bind resume state; they are not
presented as a replacement for TLS authentication.

Certificate generation uses `cryptography`, imported lazily by transfer setup. The
dependency is exposed through the `transfer` extra so base research imports remain
lazy.

## Consequences

- The first provider is a direct TCP/TLS control provider, not evidence that a catalog
  carrier is native-stack product-ready.
- Anyone holding an unexpired offer may send within its policy. Offers are therefore
  short-lived local-private capabilities and are single-use for new transfers.
- Resume may reuse an accepted offer only for the same transfer id and manifest within
  the receiver's retention window.
- Certificate keys, access tokens, offers, and transfer state never enter public-safe
  evidence artifacts or default logs.
- An independent review remains required before the transfer surface is labeled stable.
