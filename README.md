# Celatim

Celatim is a typed Python 3.14+ package for authenticated file transfer and reproducible
research on covert channels and steganographic carriers in IETF protocol fields. It
provides an offer-based transfer CLI and async SDK alongside channel codecs, protocol
data-unit implementations, controlled endpoint transports, capacity models, detector
and scrub guidance, scenario execution, and evidence artifacts.

The project accompanies a survey and measurement paper. Its channel and defensive
implementations are published together so researchers can reproduce the measurements,
inspect assumptions, and evaluate both communication and normalization behavior.

Use Celatim only in controlled environments and on systems and networks you are
authorized to test.

The transfer surface is experimental in 0.2.x. Its network paths are encrypted and
refuse ambiguous completion, but the independent security-review gate remains open;
see [the compatibility policy](docs/transfer-compatibility-policy.md) and the
[current validation record](docs/file-transfer-validation-20260710.md).

## Requirements

- CPython 3.14 or newer.
- Linux for AF_PACKET, network-namespace, tcpdump, and QEMU/TAP workflows.
- No optional protocol stack is imported by the base package.

## Hello world: Alice and Bob

Install the transfer extra on both machines:

```bash
python -m pip install 'celatim[transfer]'
```

Bob starts a receiver and writes a short-lived offer to a file:

```console
bob$ celatim transfer listen \
  --output-dir ~/Downloads \
  --host 0.0.0.0 \
  --advertise-host 192.0.2.20 \
  --offer-out bob.offer
Ready: celatim://v1/eyJ...
```

Bob sends `bob.offer` to Alice through the channel they already use. Alice sends one
file with that offer:

```console
alice$ celatim transfer send report.pdf --to-file bob.offer
Complete: 193024 bytes, authenticated, acknowledged, and verified
```

Bob receives `~/Downloads/report.pdf` only after durable chunk acknowledgements,
whole-file verification, and atomic placement. The default `offer_bound` trust mode
authenticates the exact receiver certificate embedded in the offer; a receiver label is
not a verified person. Use `celatim transfer status` and
`celatim transfer resume TRANSFER_ID` after an interruption.

## Hello world: application developer

The CLI and SDK use the same typed transfer core:

```python
from pathlib import Path

from celatim.transfer import TransferClient, TransferOffer


async def send_report(invite: str) -> None:
    offer = TransferOffer.parse(invite)
    async with TransferClient.open_default() as client:
        operation = await client.send_file(Path("report.pdf"), offer)
        async for event in operation.events():
            print(event.status.value, event.bytes_transferred)
        receipt = await operation.result()
        assert receipt.authenticated
        assert receipt.acknowledged
        assert receipt.verified
```

`TransferServer`, `TransferOperation`, versioned offers/manifests/receipts/events,
structured `TransferFailure` values, provider discovery through `celatim.providers`,
and the reusable provider conformance suite are public under `celatim.transfer`.
`send_stream()` accepts an async iterable of byte chunks through a bounded private disk
spool; `send_bytes()` is the in-memory convenience form.

## Hello world: academic researcher

The research API remains available without the transfer extra:

```python
from celatim import PayloadSource, roundtrip_payload

result = roundtrip_payload(
    "http2-ping-opaque",
    PayloadSource.hex("00 ff 80 41"),
)
assert result.ok
assert result.payload == b"\x00\xff\x80A"
```

This is an in-memory codec/session result, not native-stack network evidence. Use
packaged scenarios and inspect each result's evidence label when making empirical
claims.

## Installation

```bash
python -m pip install celatim
celatim --help
```

The wheel installs one primary command, `celatim`, plus four deterministic report
generators from the same codebase:

- `celatim-paper-figures`
- `celatim-paper-macros`
- `celatim-paper-tables`
- `celatim-support-matrix`

## Install profiles

Optional dependencies are grouped by capability:

| Extra | Capability |
|---|---|
| `celatim[transfer]` | TLS 1.3 file transfer, offer pinning, and encrypted carrier records |
| `celatim[packet]` | Scapy packet construction, parsing, and pcap integration |
| `celatim[crypto]` | ECDSA and RSA-PSS transcript experiments |
| `celatim[daemon]` | hyper-h2 and aioquic production-stack paths |
| `celatim[dns]` | dnspython message paths |
| `celatim[ssh]` | Paramiko SSH message paths |
| `celatim[iot]` | aiocoap and paho-mqtt message paths |
| `celatim[realtime]` | WebSocket message paths |

For example:

```bash
python -m pip install 'celatim[packet,crypto,daemon]'
```

## Research Python API

Mechanism discovery exposes executable transport metadata without importing optional
stacks:

```python
from celatim import MechanismProfile

profile = MechanismProfile.from_catalog("http2-ping-opaque")
print([path.kind.value for path in profile.adapter.paths])
```

The public API also includes scenario discovery, evidence generation, pcap decode and
scrub helpers, timing sweeps, installation checks, testbed requirements, and packaged
document/schema inspection. Lower-level codecs, PDU implementations, detector rules,
and transport classes remain available through focused `celatim.*` submodules.

## Command line

Inspect mechanisms and packaged contracts:

```bash
celatim mechanism list
celatim mechanism show http2-ping-opaque
celatim scenario list
celatim docs list
celatim schema list
celatim testbed requirements
```

Run an in-memory binary-payload round trip:

```bash
celatim roundtrip \
  --mechanism http2-ping-opaque \
  --hex "00 ff 80 41"
```

Run a packaged non-privileged pcap scenario and write evidence:

```bash
celatim scenario run \
  --scenario-id http2-ping-opaque-real-pdu-smoke \
  --artifact-dir out/carriers \
  --pcap-dir out/pcaps \
  --log-dir out/logs \
  --output out/evidence.json
```

Generate defensive artifacts:

```bash
celatim detector rules \
  --output-dir out/detector-rules \
  --output out/detector-rules.json
celatim guidance generate --output out/detector-scrub-guidance.md
celatim guidance windows-capture --output out/windows-capture-guidance.md
```

## Architecture

Celatim is one PEP 621 project with one `celatim` package:

- `celatim.channel`: bit packing, codecs, framing, and transport-agnostic drivers.
- `celatim.pdu`: parser-visible protocol data-unit implementations.
- `celatim.transports`: in-memory, file, pcap, timing, and production-path transports.
- `celatim.testbed`: netns/veth, AF_PACKET, daemon, tcpdump, and QEMU/TAP helpers.
- `celatim.detect`: detector predicates, executable replay, and offline scrub support.
- `celatim.metrics`: separate storage, timing, and subliminal capacity models.
- `celatim.report`: deterministic tables, figures, matrices, and defensive guidance.
- `celatim.scenario`: versioned scenario loading and controlled execution.
- `celatim.transfer`: secure offers, clients, servers, providers, state, receipts, and
  privilege-separated packet I/O.

The wheel includes its default catalog, protocol-rate assumptions, JSON Schemas,
scenario definitions, and operator documentation. CLI defaults resolve those resources
with `importlib.resources`, so installed commands do not depend on a source checkout.

Optional integrations are imported only when their transport is selected. The installed
package smoke verifies that a base import does not load Scapy, cryptography, aioquic,
dnspython, Paramiko, aiocoap, paho-mqtt, or WebSockets.

## Evidence boundaries

Celatim distinguishes structural capability from executed evidence:

- Storage carriers report field width and both header-relative and on-wire density.
- Timing/count carriers use a separate rate model.
- Subliminal cryptographic carriers use separate entropy bounds.
- Evidence records identify the transport, parser validation, controls, endpoint
  topology, artifact hashes, and claim status.
- Public indexes contain hashes and classifications rather than sensitive payloads,
  transcripts, host paths, or reviewer-only artifacts.

Privileged experiments live under `experiments/`. They require explicit operator action
and do not run during normal installation, import, or non-privileged CI.

The chosen-nonce ECDSA transcript path is likewise research-only. It creates a fresh
ephemeral key for each local transcript, uses `cryptography`/OpenSSL for curve operations
and verification, and must not be used with production or long-lived signing keys.

The companion
[`rfc-tunnel-survey`](https://github.com/mjbommar/rfc-tunnel-survey) repository vendors
a manifest-verified snapshot of this project alongside the paper, RFC corpus, generated
figures, and evidence indexes. This repository is the canonical package and PyPI release
source.

## Development

Install the locked development environment and run every package gate:

```bash
make ci
```

That target runs:

1. `uv sync --locked --all-groups`
2. `uv lock --check`
3. `uv run ruff format --check .`
4. `uv run ruff check .`
5. `uv run ty check`
6. `uv run pytest`
7. `scripts/installed_wheel_smoke.py`
8. `pip-audit` against every locked development and optional dependency

The type gate covers the package, tests, release scripts, and production experiment
drivers. There are no directory-wide type-check exclusions; optional-stack boundaries
use their concrete library modules so they remain statically resolvable.
GitHub runs the same gate on pushes, pull requests, manual dispatches, and a weekly
schedule so newly published dependency advisories are detected without waiting for a
source change.

The installed-wheel smoke builds an sdist, builds the wheel from that sdist, installs it
without dependencies into a fresh virtual environment, changes to a directory outside
the checkout, and exercises all five console entry points plus representative public
API, binary-payload, and two-process Alice/Bob workflows. After proving the base import
does not load optional stacks, it installs every wheel-declared extra into the isolated
environment, imports each integration dependency, and records the resolved versions.

Build and validate release distributions with:

```bash
uv build --out-dir dist
uvx twine check dist/*
uvx check-wheel-contents dist/*.whl
```

## Release workflow

GitHub releases trigger `.github/workflows/release.yml`. The workflow requires a tag
that exactly matches `v<project.version>`, reruns the full CI and installed-package gate,
validates wheel metadata and contents, and passes verified artifacts to a separate PyPI
publishing job.

Only that final job receives `id-token: write`, uses the protected `pypi` environment,
and exchanges GitHub's OIDC identity for a short-lived PyPI credential. No PyPI token is
stored in the repository. See [`RELEASING.md`](RELEASING.md) for the trusted-publisher
identity and release procedure.

Celatim is licensed under the [Apache License 2.0](LICENSE). Release validation requires
the exact SPDX expression and packaged license file in the wheel.
