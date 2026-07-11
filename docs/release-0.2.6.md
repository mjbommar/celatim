# Celatim 0.2.6

Celatim 0.2.6 is a path-measurement correctness release. It preserves existing
mechanism identifiers, wire formats, transfer APIs, and capacity values.

## Path Evidence Corrections

- Routed AF_PACKET experiments now invalidate Scapy's serialized-packet cache when
  recomputing checksums. The stale checksum had caused Linux routers to drop packets
  before Netfilter while direct-L2 captures still observed them.
- The Linux MASQUERADE experiment now requires complete pre-NAT, post-NAT, and receiver
  taps and provides a separately delivered field-zero control.
- A default-drop nftables experiment requires complete three-tap delivery, populated
  allow/drop counters, and a blocked disallowed probe.
- IPv4 Identification survivability is now `path_dependent`, reflecting preservation
  by the measured Linux Netfilter path without generalizing across NAT products.

## Verification

The release runs the full Python 3.14 quality, test, installed-wheel, dependency-audit,
metadata, license, and wheel-content gates before publishing through PyPI Trusted
Publishing. The paper repository separately publishes the strict repeated campaign and
raw-log hashes; one Linux Netfilter family is not treated as a deployment population.
