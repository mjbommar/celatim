# Testbed and end-to-end testing

How we demonstrate that covert bits actually traverse production-grade protocol
software, measure what gets through, and validate the detectors — and which isolation
technology is appropriate for each kind of mechanism.

This document is reference and rationale. The pure codec/framer/registry layer
(`celatim.channel`) needs none of it — it is property-tested in memory and runs
anywhere. Everything here is the **transport tier** that sits above the `Wire`
protocol and turns *structural* capacity into *measured* capacity.

> Posture: all of this runs in controlled, authorized environments only (namespaces,
> containers, local VMs we own). See the project's Scope and framing in `CLAUDE.md`.
> The default evidence target is realistic execution over real stacks; structural
> capacity remains a bound and cross-check.

---

## 1. What we are testing (and why one testbed can't do it all)

Four distinct measurands, per mechanism:

| Measurand | Question | Needs |
|---|---|---|
| **Fidelity** | do the covert bits arrive intact end to end? | a real receiving stack + a way to read the field |
| **Goodput** | bits/s achieved on a real stack (vs the structural upper bound) | real send/receive, timing |
| **Survivability** | do the bits survive NAT / normalizer / firewall / proxy? | a middlebox in the path + capture before and after it |
| **Detectability** | does our generated rule fire, and at what false-positive rate? | covert + benign traffic, the rule engine in-path |

Two facts make a single testbed insufficient:

- **The covert field lives in different places per carrier class.** L3/L4 header bits,
  encapsulation headers, routing PDUs, TLS/QUIC interiors, application frames, packet
  *timing*, and signature *randomness* each need different machinery to inject and to
  observe. The required tier follows the taxonomy (Section 6).
- **Vantage point is part of the result.** For an *unwitting* receiver the stack
  ignores the field by design, so the socket API never surfaces it — the field is read
  from a packet capture at a chosen point on the path, not from a socket (Section 4).

So the testbed is **tiered**, mirroring the evidence ladder from codec validation to
production-path measurement to cross-stack replication.

---

## 2. Tiers at a glance

| Tier | Technology | Role | In CI? |
|---|---|---|---|
| 0 | in-memory `Wire` (`IdealWire`, `MiddleboxWire`) | codec↔transport wiring and regression checks | yes (have it) |
| 0.5 | two processes over loopback | last-resort smoke test | yes |
| **1** | **netns + veth** | **workhorse: production Linux stacks, middleboxes, detectors, most mechanisms** | yes (root in container) |
| 2 | Docker / compose | production daemons and libraries (FRR, nginx, BIND, strongSwan, OpenSSH/OpenSSL, aioquic) | partial / nightly |
| 3 | QEMU / KVM | cross-OS fidelity; the "unmodified third-party receiver" headline | manual / nightly |

UML (User-Mode Linux) is intentionally omitted — superseded by netns (same kernel) and
QEMU (different kernel), with better tooling.

---

## 3. Each option: when appropriate, when not

### 3.0 In-memory `Wire` (Tier 0) — regression layer

- **What:** `Channel` over `IdealWire` (clean) or `MiddleboxWire(transform)` (applies a
  per-symbol function, e.g. zeroing a field to model a normalizer).
- **Appropriate for:** proving the codec/framer round-trip, validating the registry,
  and catching regressions before a production-path run.
- **Not appropriate for:** any claim about real stacks, real wire behavior, goodput,
  timing, or detector false-positive rates. It is a model, not a measurement.

### 3.0.5 Two processes over loopback

- **What:** sender and receiver processes, `lo` interface.
- **Appropriate for:** a one-off check that the transport plumbing (raw socket, capture,
  decode) is wired correctly before moving to netns.
- **Not appropriate for** (the reason it is only a smoke test): `lo` bypasses the real
  path — no real L2 framing, a huge loopback MTU, no driver/qdisc path, no way to insert
  a middlebox, and offload behavior unlike a NIC. Results here do **not** support
  "through the stack."

### 3.1 Network namespaces + veth — production Linux path (Tier 1)

- **What:** separate network stacks (own interfaces, routing tables, netfilter) inside
  one kernel, joined by `veth` pairs; middleboxes are extra namespaces or `tc`/nftables
  on the links; `tc netem` emulates delay/loss/reorder; libpcap taps each `veth`.
- **Appropriate for:** the bulk of the catalog — L3/L4 header fields, encapsulation,
  most transport and many session mechanisms; survivability (insert a real NAT /
  normalizer namespace); running our generated nft/BPF rules *in-path* for TP/FP; fast,
  scriptable, reproducible, CI-friendly.
- **Not appropriate for / limits:**
  - **Same kernel** — cannot test two *different* OS stacks; the receiver is Linux. Use
    Tier 3 when the claim is "survives a stack we did not write."
  - **veth offload quirks** — GRO/LRO can coalesce frames and clobber per-packet fields;
    checksum offload is software. **Disable offloads** (Section 5.3) or get artifacts.
  - **Timing realism is bounded** by the shared scheduler — usable with care and a
    reported noise floor, but not a substitute for isolated hardware (Section 5.4).
  - Needs root / `CAP_NET_ADMIN` (a container is enough; no hypervisor).

### 3.2 Docker / compose — production daemons (Tier 2)

- **What:** netns + cgroups + packaged production software. Networking is a Linux
  bridge + veth under the hood.
- **Appropriate for:** mechanisms whose realism *is* a specific daemon — FRR/BIRD (BGP,
  OSPF, IS-IS), nginx/h2o (HTTP/2, HTTP/3), BIND/unbound (DNS, DoT/DoH), strongSwan
  (IPsec/IKE), OpenSSL/OpenSSH (TLS, SSH). Pins versions, makes the artifact portable.
- **Not appropriate for:** raw header-field channels — Docker's own iptables NAT and
  bridge rules clutter the path and can themselves rewrite fields. Use bare netns for
  those. Also heavier than netns; don't reach for it when no daemon is required.

### 3.3 QEMU / KVM full VMs — independent stacks (Tier 3)

- **What:** real *separate* kernels, optionally *different* operating systems
  (Linux ↔ Windows ↔ *BSD), connected via host bridge/tap with libpcap on the tap.
- **Appropriate for:** the headline evidence — a Linux sender's field surviving to an
  **unmodified Windows/BSD receiver**, decoded at the receiver's tap (the strongest
  "unwitting receiver" claim); real NIC-driver/offload fidelity; a real middlebox
  appliance image.
- **Not appropriate for:** breadth (too slow/heavy to run for all 123 mechanisms — use
  it selectively for the marquee set); precise timing channels unless CPU-pinned KVM
  with care (virtualization adds jitter, Section 5.4); easy CI.
- **Current packaged surface:** `celatim.testbed.QemuTapVm` creates a host TAP,
  starts QEMU with `-netdev tap,...,script=no,downscript=no`, and tears both down
  through injectable runners; `HostTcpdumpCapture` records host-side TAP pcaps. This
  is infrastructure for manual/nightly cross-stack scenarios, not a completed
  cross-stack evidence claim.

---

## 4. Cross-tier methodology: observing the field

### 4.1 Unwitting vs cooperating decode (the central subtlety)

- **Unwitting receiver:** the real stack ignores the field (that is the mechanism). The
  socket API will never surface it, so the **decoder reads the field from a libpcap
  capture** at the receiver's ingress (a `PcapWire`), using the same `FieldLocator` the
  encoder used.
- **Cooperating receiver:** both ends run our code, so the receiver may decode directly
  from its own capture or a side channel.

`reach` on each mechanism (`unwitting` / `cooperating` / `multihop`) tells the harness
which decode path applies.

### 4.2 Capture at three taps, not two

Tap at **sender egress**, **post-middlebox**, and **receiver ingress**. Comparing the
field across taps proves end-to-end arrival *and localizes where a bit dies* — which is
the survivability table, measured rather than asserted (tracebox methodology applied to
covert fields). "Arrived intact" and "scrubbed at hop 2" come from the same captures.

---

## 5. Cross-tier methodology: realism gotchas

### 5.1 Use real middleboxes

Each middlebox is its own namespace/container in the path: Linux `MASQUERADE` for real
NAT44; nftables running *our generated scrub rules*; a real proxy (squid/nginx) for PEP
behavior; `tc`/eBPF replicating the documented Honda (IMC'11) / tracebox (IMC'13)
rewrites. The box that scrubs the channel and the detector that flags it are the same
artifact read two ways.

### 5.2 Benign baselines for false positives

Detector FP rates need *benign* traffic with realistic field distributions. Replay
public captures (MAWI, CAIDA — L3/L4 headers preserved) through the same tap and run the
generated rules. This is the passive base-rate measurement the paper relies on, run in
the same harness.

### 5.3 Disable NIC offloads

`ethtool -K <if> tso gso gro lro rx off tx off` on every veth/NIC in the path. GRO/LRO
coalesce segments and overwrite per-packet header fields; checksum offload masks bad
checksums. Skipping this corrupts per-segment channels and *looks like* a survivability
failure. This is the most common silent-error source.

### 5.4 Timing channels (Class F) need honesty, not heroics

Virtualization and shared scheduling add jitter that *is* the signal. Do not claim
wire-realism for timing on a busy netns or an unpinned VM. Instead: pin CPUs
(`isolcpus`), use known `tc netem` profiles, **measure and report the baseline
inter-arrival jitter (the noise floor) and the channel SNR**, and anchor the result
against the Anantharam–Verdú queue-capacity model rather than overclaiming. The cleanest
Class-F demonstration is a controlled queue plus a netns measurement with the noise floor
stated.

---

## 6. Which tier each mechanism needs

Driven by carrier class and where the field lives:

| Carrier class / layer | Inject by | Observe by | Tier |
|---|---|---|---|
| A/C header bits (IP, TCP, ICMP, SCTP) | real socket + NFQUEUE/`tc`-eBPF rewriter (Section 7) | receiver pcap | 1 (production Linux); 3 for cross-OS |
| Encapsulation (VXLAN, GRE, SRv6, LISP) | craft + inject; kernel tunnel where available | pcap at decap point | 1 / 2 |
| Routing (BGP, OSPF, IS-IS, PIM) | a real daemon (FRR/BIRD) carrying the field | daemon state + pcap | 2 |
| Session/security (TLS, SSH, IPsec, IKE) | real stack + a hook at the injection point | cooperating endpoint | 2 (3 for stack diversity) |
| Application (HTTP/2-3, DNS, RTP, STUN) | real library hook points (aioquic, h2, dnspython) | cooperating endpoint | 2 |
| Timing / count (F) | controlled send schedule / queue | pcap timestamps + noise floor | 1 pinned (3 with care) |
| Subliminal (G) | hooked (EC)DSA/RSA-PSS signer — **no network** | verifier with shared key | host-local; no tier |

Mechanisms not yet reachable at a production tier stay clearly marked as capacity
bounds until a real-stack run exists. The harness prints coverage with the evidence
level and reason, the same way the detection layer reports rule coverage.

---

## 7. Injecting covert bits into production traffic

The tension: realistic traffic wants the real kernel TCP/TLS/QUIC stack, but the socket
API will not let you set most reserved fields. Do **not** reimplement the stack. Let the
real stack build the flow and rewrite the field in flight:

```
real socket (real TCP/TLS state machine)
   -> tc-egress eBPF / NFQUEUE userspace hook
        writes covert symbol into [base, bit_offset, bit_width]   <- the FieldLocator
   -> veth -> [middlebox netns] -> receiver
        tc-ingress / pcap reads the same field and decodes
```

- This is a **third reuse of `FieldLocator`** — the codec writes the symbol, the hook
  injects it into a real packet, the detector reads it. One spec, three consumers.
- **NFQUEUE** (userspace, via the real stack) is the easy prototype; **`tc`-eBPF** is the
  fast version.
- For **payload-carrying** mechanisms (HTTP/3 frames, padding, opaque blobs) there is no
  rewriter — drive the real library's extension points directly.
- For **subliminal (G)** there is no network step: hook the signer to embed bits in the
  nonce/salt and verify with a key-sharing recipient.

A `PcapWire` and an NFQUEUE/eBPF rewriter are the only genuinely new code per tier; the
`codec_for(mechanism)` encode/decode and the catalog are reused unchanged.

---

## 8. Scenario runner, CI, and coverage

Wrap each test as a declarative scenario, so the topology is data, not code:

```yaml
mechanism: tcp-reserved-bits
topology: { sender: nsA, receiver: nsB, link: veth }
middleboxes: [ { ns: nsM, action: nft-normalize } ]
payload: "covert payload test"
expect: { clean: delivered, with_middlebox: destroyed, detector: fires }
```

The runner builds the namespaces, drives the existing `codec_for(mechanism)`, captures at
the three taps, decodes, runs the generated detector, and emits a result row
(fidelity, goodput, where-it-died, detector verdict, FP rate).

- **CI:** a representative Tier-1 production-Linux subset (root in a container) — fast,
  deterministic.
- **Nightly / manual:** Tier-2 daemon scenarios and Tier-3 cross-OS VMs.
- **Coverage report:** every mechanism is production-path measured or clearly marked as
  a capacity bound, with the reason — the same discipline as `detect.coverage`.

---

## 9. Recommended first slice

One vertical scenario that exercises all four measurands at once, for
`tcp-reserved-bits` (its `FieldLocator` is already in the catalog):

1. Two netns + veth, offloads off.
2. Sender: real socket + NFQUEUE writes the covert nibble; receiver `PcapWire` decodes
   from the ingress tap → assert payload survives the **real stack** (fidelity).
3. Insert a normalizer namespace running our generated nft scrub rule → assert the
   payload is destroyed and the three-tap capture shows it died at the normalizer
   (survivability).
4. Run the generated BPF/nft detector over covert and benign captures → TP/FP
   (detectability).

That proves the full story for one mechanism in one harness, then scales to the subset
through the scenario spec.
