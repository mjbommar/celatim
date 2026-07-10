# File-Transfer Validation, 2026-07-10

This record captures the verification used for the Celatim 0.2.0 experimental transfer
surface. It contains no transfer offers, access tokens, private keys, payload bytes, or
packet captures.

## Package gates

- CPython: 3.14.3.
- `make qa`: Ruff format and lint clean, `ty` clean, 962 tests passed and 18 privileged
  or environment-specific tests skipped.
- `make package-smoke`: built `celatim-0.2.0.tar.gz`, built the wheel from the sdist,
  installed it outside the checkout, verified lazy base imports, installed all eight
  extras, exercised all console entry points, and completed a two-process authenticated
  file transfer.
- `make security-audit`: no known vulnerabilities in the locked project, development,
  and optional dependency set.
- Final wheel: `celatim-0.2.0-py3-none-any.whl`, SHA-256
  `f862e108d595469def02b8d0f22b0fb36e8268006741a617f7275559e7dd2860`; Twine metadata
  and `check-wheel-contents` passed.
- External provider fixture: built and installed as a separate distribution, discovered
  through `celatim.providers`, and passed the public conformance suite.

## Direct cross-host transfers

The same locally built 0.2.0 wheel was installed on `s0`, `s1`, `s2`, and `s3`. Four
receiver-first transfers covered both directions of two host pairs and several sizes.

| Sender | Receiver | Size | Provider | Result |
|---|---|---:|---|---|
| `s0` | `s1` | 0 bytes | `tcp-tls` | authenticated, acknowledged, verified; SHA-256 matched |
| `s1` | `s0` | 64 KiB | `tcp-tls` | authenticated, acknowledged, verified; SHA-256 matched |
| `s2` | `s3` | 1 MiB | `tcp-tls` | authenticated, acknowledged, verified; SHA-256 matched |
| `s3` | `s2` | 5 MiB | `tcp-tls` | authenticated, acknowledged, verified; SHA-256 matched |

An additional 32 MiB `s0` to `s1` transfer was killed after Alice had persisted 112
chunk acknowledgements. Bob had durably persisted 113 chunks and moved to `paused`.
`celatim transfer resume` reused the original manifest and completed the remaining
chunks. The source and atomically placed destination both had SHA-256
`a367be137029fbf8be312e5f0d4c43efc4da455fda7237bb1d1f048c37cc394f`.

## Packet-service providers

The application processes ran as the normal user. A systemd transient service held
only `CAP_NET_RAW`, with `NoNewPrivileges=yes`, an explicit Unix-socket peer UID,
provider allowlist, and interface allowlist. The socket was user-owned with mode 0660.

Five 1 KiB file-transfer techniques completed from `s0` to `s1` with authenticated
control, durable acknowledgement, final verification, and matching SHA-256 values:

| Provider | Packet protocol | Evidence label |
|---|---|---|
| `tcp-tls` | TCP/TLS 1.3 | `direct_tls_control` |
| `afpacket.http2-ping-opaque` | TCP | `synthetic_outer_frame` |
| `afpacket.quic-connection-id` | UDP | `synthetic_outer_frame` |
| `afpacket.rtp-rtcp-ext-app` | UDP | `synthetic_outer_frame` |
| `afpacket.ipv4-id-atomic` | TCP | `synthetic_outer_frame` |

The carrier providers encrypted the file chunk before adapter encoding. Capture-flow
filtering and a bounded 2,000-frame/second packet-service pacing policy prevented
unrelated LAN traffic and raw-socket burst loss from being mistaken for carrier data.
The IPv4 ID adapter also verified that a missing Scapy integration is rejected during
preflight as `provider_unavailable`, not reported as an internal transfer failure.

These carrier results validate the installed encrypted provider, packet-service, and
adapter path. They do not claim native production-stack placement for each mechanism.

## Remaining external gate

The implementation has an internal threat-model and code review, negative tests,
dependency audit, and capability-bounded lab validation. An independent review of the
TLS pinning and key lifecycle, carrier encryption, resume state, atomic sink, and packet
service is still required before any stable or general-use claim.
