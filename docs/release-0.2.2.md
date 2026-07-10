# Celatim 0.2.2

Celatim 0.2.2 corrects the publication-facing classification of Alice/Bob evidence.

- The public cross-host index and claim ledger now use v2 schemas.
- Execution paths are counted explicitly as generated AF_PACKET frames over VXLAN,
  JSON carrier-artifact handoff over SSH, or JSON-wrapped protocol PDU bytes over a
  TCP control connection.
- Adapter capability buckets remain available but are no longer emitted as
  "run-backed real PDU" or "real daemon" execution claims.
- Path-specific claims include their exact mechanism identifiers and state their
  transport and goodput boundaries.
- Integrity protection is no longer treated as synonymous with confidentiality.
  Catalog rows now distinguish cleartext, encrypted, and deployment-dependent on-path
  visibility before assigning a detection tier.

Carrier encoding, transfer behavior, and the TLS 1.3 padding correction introduced in
0.2.1 are unchanged.
