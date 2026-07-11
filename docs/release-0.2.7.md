# Celatim 0.2.7

Celatim 0.2.7 is a daemon-path evidence correctness release. It preserves mechanism
identifiers, wire formats, transfer APIs, and capacity values.

## DNS daemon evidence corrections

- The EDNS(0) `dig`/`dnsmasq` scenario now captures query-bearing DNS packets over
  either UDP or TCP. BIND `dig` sends the 512-byte carrier used by this scenario over
  TCP, so the earlier UDP-only filter could miss a successful daemon transaction.
- Round-trip capture waits for tcpdump's configured packet count before decoding rather
  than terminating the process while a matching packet is still being flushed.
- The pcap decoder supports current Scapy DNS additional-record lists as well as the
  older linked-payload representation. A regression fixture covers DNS-over-TCP with an
  EDNS option.
- `celatim evidence run` and `celatim scenario run` now return a nonzero process status
  when the written evidence document reports `ok: false`.

## Verification

The release runs the complete Python 3.14 quality, test, installed-wheel,
dependency-audit, metadata, license, and wheel-content gates before publishing through
PyPI Trusted Publishing. The paper repository separately publishes repeated aggregate
daemon-path evidence and retains environment-bearing pcaps outside the public tree.
