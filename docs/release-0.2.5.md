# Celatim 0.2.5

Celatim 0.2.5 is a catalog-semantic correction release. It preserves all public APIs,
wire formats, mechanism identifiers, capacities, and experiment contracts from 0.2.4.

## Specification corrections

- Ten headline catalog rows now distinguish verbatim RFC semantics from
  literature-derived channel interpretations.
- OWAMP padding no longer claims unsupported TWAMP coverage or treats pseudorandom
  padding as mandatory.
- EDHOC, NTP extension-field, DHCP, and DoH descriptions now match their governing
  RFC constraints without overstating arbitrary content or fixed-port behavior.
- ECDSA and timing-channel rows identify which channel interpretations come from
  prior literature rather than the cited protocol specification.
- BGPsec and QUIC negative results are scoped to external mutation instead of implying
  that a cooperating signer or endpoint cannot construct a valid value.

## Verification

The release runs the full Python 3.14 quality, test, installed-wheel, dependency-audit,
metadata, license, and wheel-content gates before publishing through PyPI Trusted
Publishing.
