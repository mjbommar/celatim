# File-Transfer Implementation Checklist

This checklist tracks implementation of the companion paper repository's
`docs/celatim-file-transfer-roadmap.md`. The roadmap is the requirements source; this
file records implementation state in the canonical package repository.

Status values are `pending`, `in_progress`, `verified`, and `blocked`.

## Milestone 0: Contract And Compatibility Freeze

- [x] `verified` Preserve top-level research `send`, `recv`, and `roundtrip` commands.
- [x] `verified` Add the `celatim transfer ...` command namespace.
- [x] `verified` Add the public typed `celatim.transfer` module.
- [x] `verified` Define offer, manifest, state, receipt, event, error, provider, and
  packet-service schemas.
- [x] `verified` Define transfer state transitions and error taxonomy.
- [x] `verified` Record transfer-security and local-state architecture decisions.
- [x] `verified` Add schema, compatibility, and public API fixtures.

## Milestone 1: Secure Local Transfer Core

- [x] `verified` Add bounded streaming file source and atomic destination sink.
- [x] `verified` Add the TLS 1.3 secure provider and offer-bound certificate pinning.
- [x] `verified` Add typed async transfer operations, events, cancellation, and receipts.
- [x] `verified` Pass tamper, cancellation, large-file, and bounded-memory tests.

## Milestone 2: Offers And Persistent Receiver

- [x] `verified` Add short-lived single-use transfer offers and replay tracking.
- [x] `verified` Add persistent `TransferServer` lifecycle, quotas, and restart recovery.
- [x] `verified` Add installed-wheel Alice/Bob two-command smoke.

## Milestone 3: Acknowledged Resume

- [x] `verified` Add numbered chunks and receiver durable acknowledgements.
- [x] `verified` Persist acknowledged ranges and resume state safely.
- [x] `verified` Pass interruption, duplication, reordering, stale-state, and disk-full tests.

## Milestone 4: Selection And Privilege Boundary

- [x] `verified` Add deterministic provider preflight, negotiation, and explicit fallback.
- [x] `verified` Add the authenticated, bounded Unix-socket packet-service contract.
- [x] `verified` Pass unprivileged client and privileged-service confinement tests.

## Milestone 5: Provider SDK And Native-Path Pilots

- [x] `verified` Add entry-point provider discovery and failure isolation.
- [x] `verified` Add an external fixture provider and reusable conformance suite.
- [x] `verified` Label native, daemon, real-PDU, and synthetic carriage evidence honestly.

## Milestone 6: Pilot And Stable Surface

- [x] `verified` Run installed-wheel, multi-host, interruption, and security verification.
- [x] `verified` Freeze v1 schemas and documented compatibility policy.
- [ ] `pending` Resolve independent security-review findings.
- [x] `verified` Update README hello worlds for users, developers, and academics.
- [x] `verified` Sync a manifest-verified snapshot into `rfc-tunnel-survey`.
- [x] `verified` Complete a requirement-by-requirement roadmap audit.

## Workstream Coverage

| Workstream | Primary milestones | Status |
|---|---:|---|
| `CELATIM-XFER-001` file commands and APIs | 0-2 | `verified` |
| `CELATIM-XFER-002` transfer offers | 0, 2 | `verified` |
| `CELATIM-XFER-003` receiver service | 2 | `verified` |
| `CELATIM-XFER-004` authenticated encryption | 0-1 | `verified_internal_review_pending` |
| `CELATIM-XFER-005` resume and acknowledgements | 3 | `verified` |
| `CELATIM-XFER-006` selection and preflight | 4 | `verified` |
| `CELATIM-XFER-007` packet service | 4 | `verified` |
| `CELATIM-XFER-008` typed async SDK | 0-1 | `verified` |
| `CELATIM-XFER-009` provider plugins | 0, 5 | `verified` |
| `CELATIM-XFER-010` progress and failures | 0-1 | `verified` |
