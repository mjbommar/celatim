# Celatim 0.2.3

Celatim 0.2.3 corrects carrier semantics and strengthens the paper's repeated-execution
evidence. It is a patch release over 0.2.2; the transfer protocol and persisted transfer
state formats are unchanged.

## Protocol and evidence corrections

- The CoAP carrier now places symbols in RFC 7252 experimental elective option 65000.
  Earlier releases used ordinary CoAP payload bytes, which did not match the cataloged
  token/message-ID/option mechanism. The aiocoap evidence path and claim labels now name
  the experimental option explicitly.
- The userspace IPv4 scrubber now converts the packet's IHL nibble to its bit length
  before resolving absolute carrier offsets. Tap evidence records captured, expected,
  and nonzero carrier-unit counts so canonicalization can be distinguished from loss.
- Stale Linux MASQUERADE claims are removed. A run with no packet at the receiver is
  classified as inconclusive rather than preservation or rewriting.

## Repeated measurement support

- `celatim scenario run` accepts `--message`, `--hex`, or `--file`, allowing exact
  caller-supplied payloads in reproducible size sweeps.
- The repository includes split-process native-protocol endpoints and a strict two-host
  campaign controller for HTTP/2 PING, QUIC DCID, SSH KEXINIT, BGP optional-transitive
  attributes, EDNS Padding, RTCP APP, STUN transaction IDs, and CoAP option 65000.
- Native endpoint records include carrier surface, implementation boundary, logical and
  runtime host identity, source revision, response validation, protocol byte counts,
  wall time, and process CPU time without writing payload or wire bytes to evidence JSON.
- Analysis metadata separates primary RFC carriers from ordinary-payload and non-IETF
  comparison rows, and evidence metrics distinguish useful-payload ratio, wire expansion,
  carrier-unit cost, and diagnostic packing utilization.

## Verification

The release workflow runs the full Python 3.14 quality and installed-package gate,
builds the wheel and source distribution, checks package metadata and wheel contents,
requires Apache-2.0 PEP 639 metadata and the packaged license, and publishes only the
verified distributions through PyPI Trusted Publishing.
