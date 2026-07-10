# File-Transfer Roadmap Audit

**Audited:** 2026-07-10

**Release surface:** Celatim 0.2.0 experimental

This audit maps the companion repository's ten-workstream roadmap to shipped code and
verified artifacts. `implemented` means usable in the experimental release. It does not
mean that every later stable-release gate in the roadmap is closed.

| Workstream | Experimental implementation | Stable-release remainder |
|---|---|---|
| XFER-001 file commands and APIs | `transfer send/listen`, typed file/byte/async-stream sources, stable open source descriptor, bounded chunks, safe names, destination-local spool, durable writes, whole-file hash, atomic placement | Sparse-file policy and replace-in-place collision mode remain non-goals for 0.2.x |
| XFER-002 offers | Bounded versioned URI/JSON offers, expiry, access token, TLS certificate pin, offline redacted inspection, single-use replay enforcement | Contact identity binding, explicit revocation command, and QR presentation are not implemented |
| XFER-003 receiver service | Async server, foreground CLI lifecycle, status/stop, persisted identity/offers/state, concurrency and file-size limits, timeouts, restart and resume, generated systemd packet-service unit | Per-peer aggregate byte quotas and a separately installed long-running receiver unit need broader operational design |
| XFER-004 encryption | TLS 1.3 direct path, offer-bound certificate authentication, encrypted carrier chunks, redaction, tamper/wrong-pin/replay tests, no plaintext carrier path | Independent security review, verified contacts, identity rotation/revocation UI, and migration review remain open |
| XFER-005 resume and ACKs | Numbered chunks, receiver fsync before ACK, persisted ACK sets, duplicate/reorder checks, authenticated final ACK, bounded retries, cancellation/resume, cross-host process-kill campaign | Broader interface/host-failure campaigns and measured-loss decision on optional erasure coding remain release gates |
| XFER-006 selection | Machine-readable manifests, deterministic priority, eligibility preflight, explicit fallback only, platform/offer/file/privilege/integration checks | Measured reliability/goodput ranking and a complete rejected-candidate diagnostic receipt remain future work |
| XFER-007 packet service | Peer-credential Unix IPC, strict bounded messages, UID/provider/interface allowlists, exact flow filter, batch pacing, CAP_NET_RAW-only systemd service, unprivileged cross-host clients | Independent privilege-boundary review and broader syscall/confinement testing remain open |
| XFER-008 async SDK | Public typed client/server/operation, file/bytes/async-stream APIs, bounded event queue, cancellation, resume, status, structured errors, no public transport `Any` handles | A synchronous convenience facade and streaming receiver callback can be added without changing the wire contracts |
| XFER-009 providers | Public protocol and manifests, `celatim.providers` entry points, lazy failure isolation, external distribution fixture, reusable conformance suite, evidence levels | Promotion policy needs more measured providers before any default carrier selection |
| XFER-010 progress and failures | Versioned states/events/errors/receipts, ordered operation events, progress counters, retry events, bounded queue, JSON/JSONL/human output, redacted status and errors | Persisted event sequence continuity and rate estimates remain stable-surface follow-up work |

## Verified gates

- Existing research `send`, `recv`, and `roundtrip` behavior remains covered by the
  complete package suite.
- Ruff format/lint, `ty`, 962 tests, installed sdist/wheel smoke, external provider
  install, all extras, dependency audit, and `git diff --check` passed before this audit.
- Four direct cross-host transfers covered two host pairs, both directions, and files
  from empty through 5 MiB.
- A 32 MiB process-kill campaign resumed from the receiver's durable acknowledgement
  set and produced identical final SHA-256 values.
- Five installed-wheel techniques completed with unprivileged applications; the four
  raw-packet carrier providers used a CAP_NET_RAW-only local service and were labeled
  `synthetic_outer_frame`.

## Readiness conclusion

Celatim 0.2.0 is ready as an experimental transfer-contract and controlled-lab release.
It is not ready to be described as a stable general-use file-transfer product. The
independent security and privilege review is the primary external gate. The remaining
selection telemetry, event continuity, contact identity, and broader fault campaigns
are explicit follow-up work rather than hidden release claims.
