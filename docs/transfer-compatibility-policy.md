# Transfer Compatibility Policy

Celatim 0.2.x introduces an experimental file-transfer CLI, SDK, wire protocol, local
state format, and provider contract. The word experimental describes API maturity; it
does not permit plaintext transfer, unauthenticated completion, or silent fallback.

## Versioned contracts

- Every serialized transfer object carries an exact `celatim.*.v1` schema version.
- Parsers reject unknown versions, unknown fields, malformed bounds, and invalid enum
  values. They never use pickle or import providers while parsing an offer or state.
- Published `v1` JSON schema shapes are frozen for the 0.2.x line. A required field,
  changed meaning, or incompatible bound requires a new schema version.
- The TLS control protocol is `celatim.transfer_protocol.v1`. Peers must use that exact
  protocol version; incompatible peers fail with `compatibility_failed`.
- Resume reuses the original transfer id, offer, provider, manifest, file digest, chunk
  plan, and trust mode. Celatim refuses incompatible state rather than migrating it
  implicitly.

## Python and provider APIs

The public `celatim.transfer` names documented in the README and packaged API guide are
the supported 0.2.x surface. Patch releases may add methods, optional fields on Python
objects, providers, or error detail, but will not remove or rename documented symbols.

The `celatim.providers` entry-point group and `TransferProvider` protocol are
experimental until a later preview release. Providers must declare their own version,
capabilities, directionality, feedback, record limit, optional extras, privileges,
platforms, and evidence level. Core isolates import failures and duplicate names.

## Security and trust

The only implemented trust mode in 0.2.x is `offer_bound`: Alice authenticates the TLS
certificate fingerprint embedded in the exact offer she received. A receiver label is
display text, not a verified person or account. `verified_contact` is reserved and must
not be advertised until contact-key binding and verification are implemented.

The `tcp-tls` provider and carrier control path require TLS 1.3. Mechanism-carrier file
chunks are encrypted before the unprivileged adapter or privileged packet service sees
them. Provider fallback is disabled unless the caller explicitly enables it and never
removes TLS or offer binding.

## Release maturity

`0.2.x` is suitable for controlled, authorized experiments and developer evaluation.
It is not called stable until the independent cryptographic and privilege-boundary
review, broader cross-host fault campaigns, and migration review in the implementation
checklist are complete.
