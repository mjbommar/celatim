# Celatim 0.2.4

Celatim 0.2.4 corrects the TCP reserved-bit carrier for RFC 9768 and adds the
reproducible detector-population campaign used by the companion paper. It is a patch
release over 0.2.3; the authenticated transfer protocol and persisted transfer-state
formats are unchanged.

## TCP semantic correction

- RFC 9768 assigns the former fourth reserved TCP flag to Accurate ECN. The
  `tcp-reserved-bits` mechanism now carries three bits per segment, uses byte mask
  `0x0e`, and preserves the AE bit.
- The minimal TCP PDU, AF_PACKET path, observer, scrubber, generated BPF/nftables/
  iptables rules, Suricata rule, catalog data, and tests use the same three-bit field.
- Independent Scapy and tshark checks verify the corrected layout. Historical
  four-bit experiment results are explicitly marked as superseded.

## Detector evaluation support

- Corpus replay now uses protocol-eligible denominators instead of treating every pcap
  record as eligible for every rule.
- Corpus reports include per-mechanism counts, false-positive estimates, and Wilson
  intervals. The default BPF campaign is limited to independently scoped TCP and IPv4
  predicates rather than aggregating unrelated fixed-offset expressions.
- The new `experiments/detector_population_campaign.py` driver prepares a hash-pinned
  CSE-CIC-IDS2018 pre-attack cohort and evaluates tcpdump/libpcap, tshark/Wireshark,
  Suricata, and a held-out stateful IPv4-ID detector. Reports include train/test roles,
  tool provenance, prevalence-adjusted precision, and conservative Wilson-based
  precision bounds.

## Verification

The release workflow runs the full Python 3.14 quality and installed-package gate,
builds the wheel and source distribution, checks package metadata and wheel contents,
requires Apache-2.0 PEP 639 metadata and the packaged license, and publishes only the
verified distributions through PyPI Trusted Publishing.
