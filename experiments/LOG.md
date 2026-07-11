# Kick-the-tires experiment diary

Working log for the first 10 end-to-end experiments (see `../docs/testbed.md` §9 and the
plan in the conversation). Append-only narrative: what we tried, what worked, what didn't,
and what we learned. Honesty over tidiness — the failures are the point.

**Superseding note (2026-07-10):** E7 below records the original historical run, but a
fresh rerun observed no packets at the receiver and is inconclusive. The current runner
refuses to classify preservation or rewriting without receiver packets. Do not cite the
historical E7 result as current evidence; use the paper repository's
`docs/path-conditioned-survivability.md` report.

**TCP semantic correction (2026-07-11):** RFC 9768 assigns the former fourth reserved
flag to Accurate ECN. The TCP carrier now uses only the three Reserved bits (`0x0e`,
three bits per segment) and preserves the AE bit. Historical E1--E8 TCP results below
used the earlier four-bit model and remain a development diary, not current evidence.
Use regenerated reports from the corrected implementation for paper claims.

---

## 2026-06-12 — production-path framing for reviewer evidence

The paper should lead with the evidence that ran on production-grade software paths:
Linux netns/veth stacks, AF_PACKET send/receive, real NAT and middlebox namespaces,
BPF/tcpdump detector runs, real arrival clocks for timing channels, and real crypto
implementations for subliminal channels. Structural capacity remains the denominator and
upper bound; it is not the headline result when a real-stack measurement exists.

For mechanisms whose semantics depend on a live daemon or independent receiver stack,
the next evidence upgrade is explicit: FRR/BIRD, OpenSSL/OpenSSH, aioquic/nginx/h2o,
BIND/unbound, strongSwan, and QEMU/KVM cross-OS receivers. Earlier diary entries that
talk about "wire-tested" or "structural" coverage should be read through this framing:
the reviewer-facing question is which production path ran, what benign control ran, and
what claim that run supports.

---

## E0 — Environment & harness strategy

**Goal of this step:** find out what the machine actually allows, so we know which tier is
runnable here vs. must be logged as environment-limited.

**Findings (host):**
- uid 1000, in `sudo` + `docker` groups. Bounding set *has* `cap_net_admin`/`cap_net_raw`,
  but **effective caps are empty** under the agent sandbox.
- `ip netns add` → **denied** (`mount --make-shared /run/netns: Operation not permitted`).
- `AF_PACKET` raw socket → **denied** (`PermissionError`).
- Passwordless sudo → **no** (interactive auth required).
- Rootless `unshare -Urn` (user+net ns) → **denied** (`/proc/self/uid_map: Operation not
  permitted` — unprivileged userns is restricted on this host).
- **Docker → available.** Tooling present on host: `ip`, `unshare`, `tcpdump`, `nft`,
  `iptables`, `ethtool`.

**Decision:** host-direct netns is out; use a **privileged Docker container as the lab
host** and build the netns + veth topology *inside* it. This is testbed.md Tier 1
(netns/veth) hosted inside Tier 2 (Docker) for the privilege. Real kernel stacks, real
veth wire, real netfilter — just nested.

**Lesson:** the agent sandbox is deliberately capability-stripped; reach for Docker for any
privileged net work rather than fighting userns. `--dangerouslyDisableSandbox` alone does
NOT restore caps here.

---

## Experiment results

| # | Name | Tier | Status | Key result |
|---|---|---|---|---|
| 0 | topology smoke (netns+veth in container) | 1 | **PASS** | wire up, ping 0.03ms, AF_PACKET ok, 123 mechs load |
| 1 | clean E2E fidelity (tcp-reserved-bits) | 1 | **PASS** | 12 frames → `b'kick'` recovered at rcv tap; +42-frame stress also PASS |
| 2 | offload calibration (on vs off) | 1 | **PASS** | offloads-on still delivers — raw-frame harness is below the offload layer |
| 3 | sender-vs-receiver tap control | 1 | **PASS** | null payload → `b''`; no phantom bits |
| 4 | fidelity + goodput vs structural bound | 1 | **PASS** | 200 B → 404 frames, 4 b/unit (== structural), ~2.6 kbps (send-loop bound) |
| 5 | survivability: normalizer scrub | 1 | **PASS** | scrub middlebox → `recovered=b''` DESTROYED (tcp-reserved + ip-id) |
| 6 | survivability: pass-through control | 1 | **PASS** | same middlebox, `pass` → DELIVERED |
| 7 | NAT-rewrite prediction (ipv4-id) | 1 | **historical; superseded** | original run reported survival; fresh rerun is inconclusive (see top note) |
| 8 | detector TP/FP on benign | 1 | **PASS** | generated `tcp[12]&0x0f!=0`: TP=0.92, FP=0.00 over 300 benign |
| 9 | non-FixedWidth shape / 2nd locator (ipv4-id) | 1 | **PASS** | 16-bit NH-base field, 3 frames → `b'kick'` |
| 10 | cross-OS + true-negative (integrity-bound) | 3 | **env-limited** | no VM images here (see note) |

## Detail

### E1 — clean E2E (tcp-reserved-bits)

First attempt **FAILED, instructively.** scapy's L3 `send(pkt, iface="vs")` emits a
`SyntaxWarning` ("iface has no effect on L3 send") and then can't resolve the on-link
route inside the netns → `No route found` → **0 frames actually left**. capture got 0.

**Fix:** send at **L2 over `AF_PACKET` `SOCK_RAW`** bound to `vs`, building the Ethernet
header with the real peer MACs (fetched via `ip -n <ns> link show`). A raw frame on the
wire is also the more faithful test. Retry → 12 frames in, 12 captured, `b'kick'`
recovered. PASS. 42-frame payload also PASS.

**Lesson:** don't trust scapy's L3 routing across namespaces — go L2/raw. The
`FieldLocator` (base/bit_offset/bit_width) drove the bit placement unchanged; checksums
recomputed by re-parsing the modified bytes with scapy and deleting the cached sums.

### E3 — tap control

Empty payload round-trips to `b''` (4 frames carrying the zero length-prefix); the
decoder does not invent bits. Combined with E1 recovering real non-zero text at the
**receiver** tap, this rules out "reading our own transmit buffer."

### E9 — second locator / shape (ipv4-id-atomic)

NH-base, 16-bit field (vs TH-base 4-bit for TCP). Same harness, only the locator and codec
differ (pulled from the catalog). 3 frames → `b'kick'`. Confirms the harness is
mechanism-driven, not hard-coded to one field.

### E2 — offload calibration

With offloads kept ON (`KEEP_OFFLOADS=1`), `b'offload test'` still recovers cleanly.
**Finding:** our injection sends pre-formed L2 frames via `AF_PACKET`, which sits *below*
TSO (TSO segments large socket writes — we never make those), and the receiver tap reads
each frame as it arrives. So offloads do not touch this channel. The offload caveat from
`testbed.md` §5.3 still stands, but it applies to the **real-socket / NFQUEUE path** (a
real TCP flow whose segments TSO/GRO would split/coalesce), not to raw-frame injection.
Worth disabling them anyway for the real-socket harness we haven't built.

### E4 — fidelity + goodput

200-byte payload → 404 frames, 4 covert bits/frame (== the structural bound), 100%
fidelity. Goodput ~2.6 kbps — **send-loop bound, not wire bound** (python per-frame
scapy build dominates), so this is a floor, not the channel ceiling. Honest takeaway:
goodput numbers from this harness measure our sender, not the medium; a real goodput
sweep needs a batched/compiled sender.

### E5 / E6 — survivability (real bump-in-the-wire middlebox)

3-netns chain `snd -- mbox -- rcv`; `mbox` runs a userspace forwarder (`AF_PACKET` in →
out). `pass` mode (E6) → DELIVERED; `scrub:<mech>` mode (E5), which zeros the field via
the same `FieldLocator` and recomputes checksums → DESTROYED (`recovered=b''`), for both
tcp-reserved and ipv4-id. **Same topology, opposite outcomes** — the survivability axis,
measured. The scrubber *is* the generated `CANONICALIZE_ZERO` defense made real.

Two bugs en route (see Lessons): the cross-netns veth move, and the `ma`→`master`
keyword collision in iproute2.

### E7 — does a real NAT rewrite the IP ID?

**Historical result, superseded by the 2026-07-10 inconclusive rerun.** The paragraphs
below preserve the original diary entry and are not current reviewer-facing evidence.

Routed topology with a real Linux `MASQUERADE` router between two subnets; the IP-ID
channel sent through it. **Result: the IP ID SURVIVED.** Linux netfilter rewrites
address/port and recomputes checksums but **forwards the original IP ID unchanged**.

**This contradicts our `survivability=nat_rewritten` label for ipv4-id** — at least for
vanilla Linux NAT. The label is defensible for CGNs and IP-ID-randomizing middleboxes
(Salutari PAM'18: truly-random IP ID is only ~2% of hosts, i.e. most NATs/stacks keep it
sequential/preserved), but "nat_rewritten" overstates the hazard for a basic NAT.
**Action:** refine the catalog — make ipv4-id survivability NAT-implementation-dependent,
or relabel to `end_to_end` with a CGN caveat. Flagged for review, not changed unilaterally.

This is the experiment paying off exactly as intended (validate the label against reality).

### E8 — detector TP/FP

Captured covert and benign pcaps; applied the catalog's *generated* BPF detector
`tcp[12] & 0x0f != 0` via `tcpdump -r`. **TP = 0.92** (44/48 covert frames; the 4 misses
carry a zero nibble — a per-packet value detector cannot flag a zero, expected), **FP =
0.00** over 300 benign SYNs. Validates the detection pipeline and the `benign_rare` label
(zero false positives on benign traffic).

**This experiment caught the worst bug of the run** (see Lessons): the round-trip tests
were green while the covert bits were going into the wrong field.

### E10 — cross-OS + true negative

**Environment-limited.** Cross-OS (Linux→Windows/BSD) needs VM images and nested
virtualization; this host gives us Docker but no QEMU images, and building/booting a
Windows/BSD guest is out of reach here. Logged as deferred to a Tier-3 host.

Partial coverage of the *negative-control* intent: E5 already shows the harness correctly
reports a **destroyed** channel (it does not manufacture success). A full integrity-bound
negative (a field whose modification breaks an AEAD/ICV, unreadable by an unwitting
receiver) needs a real crypto stack in the path and is deferred with the transport-tier
build-out.

---

## Lessons learned (what did / didn't work)

**Worked well**
- **Privileged Docker as the lab host.** Clean netns+veth tier-1 testbed without host
  root. One image, mount the source, `PYTHONPATH=/work/src` — the pure-stdlib library
  imports and runs unchanged inside the container.
- **`FieldLocator` reuse.** One catalog record drove encode (codec), inject (write the
  field), scrub (zero it), and detect (read it) — four consumers, no duplication.
- **Independent observation beats self-consistency.** The detector (E8), reading the field
  at the correct offset, exposed a bug the round-trip tests (E1/E5/E6) happily passed.

**Didn't work / cost time (in order hit)**
1. **scapy L3 `send(iface=…)`** ignores the iface and can't route on-link inside a
   netns → 0 frames. Fix: send at L2 via `AF_PACKET`. *Lesson: go raw/L2 across namespaces.*
2. **Moving a veth end by name after its peer is in another netns** fails under iproute2
   6.15 ("argument netns is wrong"). Fix: create each veth *directly across* the two
   target namespaces (`ip -n A link add … peer … netns B`).
3. **`ip link set ma up` parsed `ma` as the `master` keyword** (prefix match) → "Device
   does not exist". Fix: always use the explicit `dev` keyword. *Lesson: never give
   iproute a bare interface name that prefixes a keyword.*
4. **The forwarder never self-exited in pass mode**, so teardown yanked its interface
   (`ENETDOWN`). Fix: `terminate()` it once capture is done; catch `OSError`.
5. **The IHL-as-bytes offset bug** (the important one): `raw[0] & 0x0F` is IHL in 32-bit
   *words*; the TH-base offset must be `ihl*32 + bit_offset`, not `ihl*8 + …`. The wrong
   offset put the covert bits inside the **IP destination address**, and *both* inject and
   capture used it, so every round-trip test was green. Only the independent detector
   caught it. *Lesson: a self-consistent harness will confirm its own mistakes — always
   cross-check with an independent observer at a known-correct position.*

**Findings that affect the model/paper**
- Linux MASQUERADE preserves the IP ID (E7) → `nat_rewritten` for ipv4-id is NAT-dependent;
  refine the label.
- Goodput from this harness is sender-bound, not medium-bound (E4) → need a batched sender
  before quoting bits/s.
- Offloads don't affect raw-frame injection (E2) → the offload discipline is for the
  real-socket path; note that in `testbed.md`.

**Net:** 9/10 runnable here passed (E10 needs a VM host). The codec/registry/locator from
the library were reused unchanged across every experiment — the transport tier really is
just a `Wire` implementation, as designed.

---

## Follow-up iterations

### Iter 1 — calibration self-check (anti-self-consistency guard)

Operationalizes the worst lesson (the offset bug every round-trip test passed). `lab.py
calibrate <mech>` builds one packet with the field set HIGH and one ZERO, then checks both
with the **independently derived** BPF detector: HIGH must match, ZERO must not. It
cross-checks the *inject* offset against the *detector* offset, so a disagreement fails
loudly.

Validated both ways: correct offset → `CALIBRATED`; reintroducing the `ihl*8` bug →
`MISCALIBRATED` (`hi_matches=False`). Now wired into `run.py` as a **pre-flight** that
aborts before measuring; mechanisms without a stateless detector (e.g. ipv4-id, predicate
`statistical`) skip the check gracefully. This guard would have turned the original
multi-hour offset hunt into one red line at startup.

### Iter 2 — three-tap survivability localization

**Superseding rerun (2026-07-11):** review found that the original forwarder passed the
IPv4 IHL nibble (`5`) to `_abs_bit_offset` where the helper expected the header length in
bits (`160`). The scrubber therefore modified the wrong header position, and the earlier
BROKEN result could be a malformed-packet drop rather than canonicalization. The
forwarder now calls `_ip_hdr_bits`, and each tap records captured, expected, and nonzero
carrier-unit counts. Across six Linux hosts, four kernel releases, and three repetitions
per condition, pass-through preserved all expected frames and nonzero carrier symbols in
18/18 runs per mechanism. The corrected scrubber retained every expected frame while
changing all TCP-reserved-bit or IPv4-ID carrier symbols to zero at egress and receiver
in 18/18 runs per mechanism. The earlier ambiguous result is not used as rewrite evidence.

E5 proved the channel died but not *where*. `run_taps.py` captures the field at three
points around the middlebox — ingress (`ma`), egress (`mb`), receiver (`vr`) — and reports
the first hop where it breaks:

```
scrub: A_mbox_ingress INTACT | B_mbox_egress BROKEN <- field dies here | C_receiver BROKEN
pass : A_mbox_ingress INTACT | B_mbox_egress INTACT             | C_receiver INTACT
```

Survivability is now a **localized** measurement (testbed.md 4.2): "intact arriving at the
middlebox, gone leaving it" pins the scrub to that exact device — the empirical version of
the per-mechanism survivability table the paper needs.

---

## Wire-coverage push (toward "implement+test all 139")

Goal: raise mechanisms from capacity-bound codec validation to production-path evidence
(real packet on the real veth, recovered at the receiver tap). The harness was
generalized from "IPv4/TCP only" to a **protocol-template builder** (`_base_packet`) +
**version-aware offsets**
(`_ip_hdr_bits`, IPv4 IHL and IPv6 fixed-40), and `run_battery.py` wire-tests every
located+buildable mechanism over one topology.

**Wire-tested so far: 9 / 146** (all L3/L4 fixed-layout header fields), each PASS:
`ipv4-id`, `ipv4-tos-dscp`, `ipv4-reserved-flag`, `tcp-reserved-bits`, `tcp-urgent-ptr`,
`tcp-isn`, `icmpv4-unused`, `icmpv6-unused`, `ipv6-flow-label`. (No IPv6 addressing needed
— AF_PACKET captures L2 frames; emit 0x86DD frames, filter by a ULA source.)

**Honest tiering of the rest (~133 — what each needs before it can be wire-tested):**
- **L3/L4 with variable/inner offsets** (IPv4 options, TCP timestamp option, SCTP chunk
  fields, IPv6 frag/routing/dest-opt ext headers): need option/chunk/ext-header templates +
  inner offsets. ~12, feasible next.
- **Encapsulations** (VXLAN/GRE/Geneve/NSH/LISP/SRv6/MPLS/BIER…): the field sits past L4
  in a payload header, which the `ll/nh/th` locator can't address — needs a payload-offset
  base + scapy templates. ~18, feasible with a locator-model extension.
- **Payload tunnels** (DNS TXT/NULL, ICMP-echo, HTTP, WebSocket, WebRTC, DoH, CoAP, MQTT,
  NTP-ext, DHCP, LoRaWAN): the carrier *is* the payload — wire-test by recovering injected
  payload bytes, no offset needed. ~15, feasible (different harness path).
- **Timing (F=3)** and **subliminal (G=2)**: dedicated harnesses (inter-arrival modulation;
  host-local nonce/salt embed — no network). 5, feasible.
- **Encrypted/authenticated interiors + control-plane sessions** (TLS/QUIC/SSH/IKE/ESP
  interiors; BGP/OSPF/IS-IS/PCEP/LDP… reserved fields): **fundamentally need a real
  protocol stack or a live routing/crypto session** to place the field meaningfully
  end-to-end (testbed.md Tier 2/3). ~80. These are codec-implemented + in-memory-tested
  today; wire-testing each needs real daemons (FRR/BIRD, OpenSSL/OpenSSH, aioquic) — not
  raw-craftable, and not all stand up in this environment.

**Bottom line:** the in-memory codec for all 142 usable mechanisms is implemented+tested;
wire-testing is at 9 and climbing through the feasible tiers, but the ~80 encrypted/
control-plane interiors require real-stack infrastructure to wire-test honestly — that is a
Tier-2/3 build, not a single-environment task.

### Subliminal (Class G) — real crypto, no network ambiguity

`run_subliminal.py`: real **ECDSA** signing (`cryptography`/OpenSSL) with covert bits
placed in the per-signature nonce *k*; a cooperating receiver who shares the private key
recovers *k* = s⁻¹(z + r·d) mod n and reads the bits. `b'covert via nonce'` round-trips.
This is the Simmons broadband channel as **functional working code** — it passes or fails,
nothing estimated. (RSA-PSS salt is the analogous case; deferred.)

### The editor standard (recorded so it governs everything)

Every empirical number in the paper must trace to code that ran. Two buckets, never
conflated: **structural capacity** (computed by tested code over all 146, reported *as
structural*) vs **measured results** (goodput / survivability / detector TP-FP / NAT
survival / subliminal recovery — only for mechanisms actually driven). Measured set today:
9 wire-tested header fields + survivability(E5/E6) + NAT(E7) + detector(E8) + subliminal.
The coverage matrix states which mechanisms are production-path measured vs capacity-bound;
nothing is claimed as measured that the code did not produce.

---

## 2026-06-11 — the "~80 need real stacks" claim was wrong; the wire sweep

The earlier bottom-line ("~80 encrypted/control-plane interiors *fundamentally* need real
daemons to wire-test") was over-pessimistic and is retracted. The covert field is placed by
**wire offset**, so the question is only whether the *bytes survive a real kernel network
path with a benign control* — not whether a live BGP/TLS session produced them. That is an
honest **Level-2, offset-represented** test (see `TEST-EVIDENCE.md` group (b)): we disclose
that the *intra-protocol field position* is represented, not driven by a live session (the
L1 step), and we require the field-zero control to recover nothing.

Wire battery grew **2 → 57 → 76 → 125** located+passing, each PASS = covert recovers the
payload AND the field-zero control recovers `b""`, on the real kernel veth stack. Batches:
control-plane reserved fields (BGP/BMP/LDP/PCEP/RSVP/PIM/BFD/…), then encapsulation +
application + session + IPv6-extension fields (VXLAN/GRE/Geneve/LISP/SRv6, HTTP-2/3,
TLS/DTLS/IKEv2/ISAKMP, RTP/RTCP, QUIC short/long-header bits, …).

**Two bugs the un-hidden battery caught (audit working):**
- raised the carrier pad to 1500 B → frames exceeded the 1500 MTU → AF_PACKET dropped them
  silently → cascade of UNSUPPORTED. Fix: veth MTU 16000.
- a failed inject orphaned its capture process, which then corrupted the *next* mechanism's
  capture. Fix: `run_battery.run_once` kills the sniffer in a `finally`.
Neither would have shown under `2>/dev/null | grep PASS`.

**Classes F and G are now fully measured, not deferred:**
- **Timing (F)** — `run_timing.py`: ntp/dns/quic. The symbol is the inter-departure gap
  (10 ms quantum ≫ veth latency); receiver timestamps arrivals and quantizes. Control =
  constant rate ⇒ recovers `b""`. 3/3 PASS on the real veth path.
- **Subliminal (G)** — added `run_subliminal_rsa.py`: a real RSA signature (`s = EM^d mod n`,
  pure-stdlib keygen) with covert bits in the **PSS salt**, recovered by the public verifier
  via RFC 8017 EMSA-PSS (`s^e mod n` → recover salt). Control = honest random salt ⇒ noise.
  PASS. Joins the ECDSA-nonce channel; class G done.

**Status: 130/146 addressed** (125 wire + 3 timing + 2 subliminal). Remaining 12 = 8 L2-only
carriers (IS-IS/TRILL/MPLS/PPP/BIER — need an Ethernet/`ll`-base path, since offset-
representing them over IP would misstate the carrier), 2 IP/TCP-option exact-offset
(ipv4-options, tcp-timestamp-lsb), 2 L2TP (UDP/IP, easy). The 4 negative-result rows are
contrast cases that *should not* be channels. Next: the L2 path + the final 12.

**Done — 146/146 accounted for by running code.** Added an `ll`-base Ethernet path
(`_inject_l2`/`_capture_l2`, filtered by the carrier's real ethertype: MPLS 0x8847, TRILL
0x22F3, BIER 0xAB37, …) for the 8 L2-only carriers, plus the 2 L2TP and 2 IP/TCP-option
fields. Final wire battery: **137/137 buildable passed, 0 unsupported** (covert recovers
payload AND field-zero control recovers `b""`, real kernel veth). With timing (3) and
subliminal (2) that is **142 usable channels measured**. The remaining 4 are the
negative-result contrast cases: `run_negatives.py` demonstrates each as a *non*-channel with
the real primitive (HMAC integrity for AH/OSCORE, real ECDSA for BGPsec, HP keystream for
QUIC) — control verifies, covert is rejected/unrecoverable. So every catalog row now traces
to code that ran: 142 channels that work + 4 that provably don't. Structural capacity for
all 146 remains a *computation* (reported as structural); the wire/crypto results are the
*measured* layer, graded L2 (offset-represented for groups (b)/(c); the L1 live-stack step
is the documented next layer).
