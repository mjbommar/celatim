# Production-path evidence ledger

Standard: `agentic-security-bot` "Reproduction & test-evidence standard" /
`ai-assisted-testing.rst`. Three separate questions per result — **where it ran**
(substrate), **how much was synthesized** (Level 1–4), **how it was found** — and we
claim only what the run showed. A Level-2 result REQUIRES a benign control. We audit the
passing test (no `|| true`, no `2>/dev/null` hiding failures, no loosened assertions),
and we separate capacity bounds from production-path measurements.

The paper's reviewer-facing empirical claims should be backed by this ledger: real
Linux network paths, production-grade middleboxes/detectors, real crypto libraries, and
daemon/VM-backed protocol stacks where the mechanism requires them.

See `../../docs/evidence-support-matrix.md` for the generated per-mechanism support
matrix. It separates zero-filled nominal-offset rows from real-PDU, real-daemon,
timing, crypto, and negative-result evidence.

## Evidence buckets, never conflated

| Bucket | What it is | Status |
|---|---|---|
| **Structural capacity bounds** (all 146) | field-width arithmetic + codec round-trip *in memory* | Capacity denominator and upper bound; useful for scale, not a deployed-path result. |
| **Offset-represented zero-blob rows** | covert bits placed at the catalog offset inside a zero-filled synthetic payload | internal consistency evidence only; not real PDU evidence. |
| **Real-PDU packet-path rows** | bits placed in a minimal packet/PDU template and carried over the kernel path | packet-path evidence; still needs independent parser/peer validation for strong claims. |
| **Real-daemon or crypto rows** | real client/server transaction or real signing/verification code produced the carrier | strongest current evidence short of cross-stack VM runs. |
| **Timing rows** | symbols carried in inter-arrival gaps over the kernel path | scheme demonstrated; no rate claim without jitter/SNR sweep. |
| **Negative-result rows** | real crypto/integrity checks reject the attempted channel | contrast cases, not usable channels. |

## Measured results — current grades

| Result | Substrate | Synthesis | Benign control | Audited |
|---|---|---|---|---|
| Wire battery — **137 mechanisms** (`run_battery.py`) | production Linux kernel net stack (netns+veth, offloads off, MTU 16000) | **L2** — crafted entry via AF_PACKET; real transit + real RX bytes; recovery from receiver tap. **Scope split:** the generated support matrix separates minimal-PDU rows from zero-filled nominal-offset rows. The zero-blob rows prove internal consistency of codec/offset/capture only; they do not prove a real BGP/TLS/QUIC/etc. PDU has the layout or would be accepted by a peer. | mixed — minimal-PDU rows use field-zero controls; zero-blob rows have vacuous zero-carrier controls until upgraded | full output, exit code, injected==captured per row; classifies pass/fail/unsupported. **Bugs caught+fixed by the audit:** int-vs-bytes symbols; oversized-pad>MTU + orphaned-sniffer cascade |
| Survivability E5/E6 (`run_mbox.py`, `run_taps.py`) | six Linux hosts, four kernel releases, real kernel + real bump-in-the-wire forwarder | **L2** | **yes** — 18/18 pass-through runs preserved all expected frames and nonzero symbols; 18/18 scrub runs retained every frame but changed all carrier symbols to zero at egress and receiver | tap status records captured/expected and nonzero unit counts; paper report hashes raw logs |
| NAT E7 (`run_nat.py`) | Linux MASQUERADE (`iptables` 1.8.11, nft backend) on six hosts/four kernels | **L2** | **yes** - 18/18 data runs recovered exactly at pre-NAT ingress, post-NAT egress, and receiver; 18/18 field-zero controls delivered every packet with zero symbols at all taps | strict report binds three-tap counts and raw-log hashes; result is one Netfilter implementation, not a NAT population |
| Firewall E7b (`run_firewall.py`) | nftables 1.1.6 default-drop forwarding chain on six hosts/four kernels | **L2** | **yes** - 18/18 data and 18/18 zero-control runs had complete three-tap delivery; every run also populated narrow-allow and catch-all-drop counters and blocked a disallowed ICMP probe | strict report rejects missing firewall controls; same Linux Netfilter family as NAT, not an independent vendor product |
| Detector E8 (`run_detect.py`) | real BPF via `tcpdump` on real pcaps | **L2** | **yes** — 300 benign SYNs ⇒ FP=0 | TP/FP counted from pcap, not asserted |
| Timing F — **3 mechanisms** (`run_timing.py`): `ntp-timing`, `dns-timing`, `quic-padding-frame-count`. Symbol carried in the inter-departure gap (10 ms quantum ≫ veth latency), not a field | real Linux kernel veth path (real scheduling + arrival clock) | **L2** — we choose the gaps; transit delay + arrival timestamps are real | **yes** — constant-rate control ⇒ all-zero symbols ⇒ recovers `b""` (proves the data is in the timing, not the constant bytes) | full output, exit code; round-trips or fails |
| Subliminal G — **2 mechanisms**: `ecdsa-nonce` (`run_subliminal.py`, `cryptography`/OpenSSL) and `rsa-pss-salt` (`run_subliminal_rsa.py`, pure-stdlib RSA + RFC 8017 EMSA-PSS) | standalone real crypto — not the kernel | **L2** (we choose k / the salt); real ECDSA sign+recover with an ephemeral research key and OpenSSL-backed point operations/verification, and a real RSA signature `s=EM^d mod n` with PSS salt recovered from `s^e mod n` | **yes** — random-k / random-salt (honest signer) ⇒ no recoverable payload | round-trips or fails, no model |
| Negative contrast — **4 mechanisms** (`run_negatives.py`): integrity-covered (`ah-…`, `oscore-…`, HMAC-SHA256), signed (`bgpsec-…`, real ECDSA P-256), encrypted (`quic-hdr-protected-…`, HP keystream) | standalone real crypto | demonstration, not a channel | **yes** — the *unmodified* message verifies (control); the *covert* message is rejected / unrecoverable | each prints control_verifies=True AND covert_rejected=True; exits nonzero if any negative unexpectedly "works" |

## Evidence scope and next upgrades

- **All 146 are now accounted for by code, but not by one evidence class:** see the
  support matrix for current counts by codec, zero-blob offset representation, real-PDU
  packet path, daemon/crypto, timing, and negative-result evidence.
- **What "measured" means here:** structural capacity for all 146 remains a bound. The
  wire battery proves bytes survive the kernel path. For zero-filled nominal-offset rows,
  it does not prove the surrounding real protocol PDU layout or peer acceptance; those
  rows require real/minimal PDU fixtures, discriminating non-zero controls, and an
  independent parser or daemon check before they support strong production claims.

## Path to raise the level (no "infeasible" excuses)

- **Already production-path buildable:** every mechanism whose protocol packet can be
  crafted (most L3/L4, encapsulations via `nh`-base absolute offset, payload tunnels via
  the payload) — add a template + locator + benign control, run through the battery.
- **Daemon/VM upgrade path:** encrypted/control-plane interiors (TLS/QUIC/SSH/IKE/ESP;
  BGP/OSPF/IS-IS) should be promoted with real implementations such as FRR/BIRD,
  OpenSSL/OpenSSH, aioquic, strongSwan, BIND/unbound, nginx/h2o, and QEMU/KVM receivers
  when the claim needs stack diversity.

## Audit checklist applied to our harness

- No `|| true` except on idempotent netns teardown / offload toggles (do not gate results).
- No `2>/dev/null` on the result path; the battery prints injected/captured counts and a
  real exit code.
- Assertions are exact (`recovered == payload` and control `== b""`), never loosened.
- Calibration guard (`lab.py calibrate`) cross-checks the inject offset against the
  independent BPF detector, catching the self-consistent-but-wrong offset class of bug.
