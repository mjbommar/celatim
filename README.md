# Celatim

Celatim is a typed Python 3.14+ package for covert-channel research, measurement, and
controlled endpoint experiments across IETF protocol fields. It turns the mechanism
catalog into channel encoders and decoders, production-path transports, structural
capacity estimates, detection and scrub guidance, evidence artifacts, and paper tables.

The code is part of the public research artifact under the project's settled dual-use
release posture. The manuscript, catalog, aggregate measurements, detection/scrub
guidance, and channel implementations are released together so readers can reproduce
the measurements and independently evaluate both channel and defensive behavior.
References below to private or restricted evidence concern payloads, transcripts,
environment paths, and other sensitive run data; they do not restrict source-code
availability. Run the implementation only in controlled, authorized environments.

## Layout
- `src/celatim/model.py` — `Mechanism` data model + invariants
- `src/celatim/catalog.py` — load `data/mechanisms.jsonl` (single source of truth)
- `src/celatim/channel/` — codecs, framing, registry, and transport-agnostic driver
- `src/celatim/adapter.py` — per-mechanism adapter status, capabilities, and real-PDU fixtures
- `src/celatim/crypto_transcript.py` — local ECDSA and RSA-PSS transcript transports for Class G evidence
- `src/celatim/envelope.py` — carrier-aware send/recv JSON envelope helpers
- `src/celatim/errors.py` — typed library exceptions for caller-visible failures
- `src/celatim/docs/` — packaged API, scenario, reviewer, and troubleshooting guides
- `src/celatim/transports.py` — reusable transport/tap implementations
- `src/celatim/testbed/` — reusable netns/veth, tcpdump, AF_PACKET, daemon, and QEMU/TAP helpers
- `src/celatim/metrics/` — Class A-E storage density, Class F timing/count rate,
  and Class G subliminal entropy metrics
- `src/celatim/detect/` — detector predicates plus stateless and stateful detector plans
- `src/celatim/layout/loader.py` — bridge to the C ground-truth tool
- `src/celatim/report/` — LaTeX appendix-table generator, public guidance, support
  matrix, deterministic paper macros/SVG figures, and protocol-rate assumption reports
- `cmeasure/header_facts.c` — header/field widths from `<netinet/*>`, emitted as JSON
- `experiments/` — netns/veth lab, NAT/middlebox/tap tests, detector runs, timing
  experiments, subliminal-crypto experiments, and evidence logs
- `scenarios/` — TOML smoke scenarios for repeatable `celatim scenario run`
- `schemas/scenario-v1.schema.json` — machine-readable scenario TOML contract
- `schemas/scenario-inventory-v1.schema.json` — machine-readable scenario inventory contract
- `schemas/scenario-execution-plan-v1.schema.json` — reviewer execution-plan contract
- `schemas/testbed-requirements-v1.schema.json` — privileged/daemon/VM testbed requirements contract
- `schemas/support-matrix-v1.schema.json` — machine-readable support matrix contract
- `schemas/evidence-run-v1.schema.json` — machine-readable evidence result contract
- `schemas/evidence-index-v1.schema.json` — reviewer-bundle evidence index contract
- `schemas/public-evidence-index-v1.schema.json` — public-safe hash-only evidence index projection
- `schemas/pcap-decode-v1.schema.json` — standalone pcap carrier decode report contract
- `schemas/timing-sweep-v1.schema.json` — timing baseline and quantum-sweep contract
- `schemas/public-bundle-v1.schema.json` — public-safe artifact manifest contract
- `schemas/public-bundle-verify-v1.schema.json` — public-safe artifact verification contract
- `schemas/reviewer-bundle-v1.schema.json` — reviewer-bundle manifest contract
- `schemas/reviewer-bundle-verify-v1.schema.json` — reviewer-bundle verification contract
- `schemas/doctor-v1.schema.json` — reviewer preflight report contract
- `examples/evidence-run-http2-ping-opaque.json` — golden evidence result example
- `data/mechanisms.jsonl` — structured mechanism catalog used by tests and paper output
- `data/protocol_rates.toml` — cited carrier-unit rates for structural throughput
  upper-bound figures; not measured production-goodput evidence

## Installation

```bash
python -m pip install celatim
celatim --help
```

The distribution contains one import namespace and one primary command. Python callers
use `import celatim`; operators use `celatim`. Paper batch generators are installed from
the same wheel as `celatim-paper-macros`, `celatim-paper-tables`,
`celatim-paper-figures`, and `celatim-support-matrix`.

## Install profiles

The base install covers catalog, codec, framing, in-memory/file/pcap-artifact, packaged
resource, report, and non-privileged scenario workflows. Optional integrations are
isolated behind extras so importing the base package does not import those stacks:

- `celatim[packet]`: Scapy packet and pcap integrations.
- `celatim[crypto]`: ECDSA and RSA-PSS cryptographic transcript experiments.
- `celatim[daemon]`: `hyper-h2` and `aioquic` production-stack paths.
- `celatim[dns]`: dnspython message paths.
- `celatim[ssh]`: Paramiko SSH message paths.
- `celatim[iot]`: aiocoap and paho-mqtt message paths.
- `celatim[realtime]`: WebSocket message paths.

## Development

```bash
make ci
uv build --out-dir dist
uvx twine check dist/*
uvx check-wheel-contents dist/*.whl
make -C cmeasure && ./cmeasure/header_facts
```

`make ci` checks the lock, formatting, lint, types, the full standalone test suite,
and an installed-wheel smoke outside the checkout. The optional dependency groups can
also be installed directly with `uv sync --extra packet --extra crypto --extra daemon`.

Representative CLI workflows include:

```bash
uv run celatim-support-matrix --output out/evidence-support-matrix.md
uv run celatim matrix generate --output out/evidence-support-matrix.md
uv run celatim matrix generate --format json --output out/support-matrix.json
uv run celatim-paper-tables --output out/field-catalog-longtable.tex
uv run celatim-paper-figures --rates data/protocol_rates.toml --output-dir out/figures --manifest out/figures-manifest.json
uv run celatim figures generate --output-dir out/figures --output out/figures-manifest.json
uv run celatim rates show --format markdown --output out/protocol-rates.md
uv run celatim detector rules --output-dir out/detector-rules --output out/detector-rules-manifest.json
uv run celatim detector windows-guidance --output out/windows-pktmon-etw-guidance.md
uv run celatim roundtrip --mechanism rtp-rtcp-ext-app --hex "00 ff 80 41"
uv run celatim send --mechanism http2-ping-opaque --session-id file-demo --hex "00 ff 80 41" --transport-dir out/wire
uv run celatim recv --mechanism http2-ping-opaque --session-id file-demo --transport-dir out/wire
uv run celatim lab up
uv run celatim lab down
uv run celatim send --mechanism http2-ping-opaque --session-id live-pkt --hex "00 ff 80 41" --afpacket-ipv4
uv run celatim recv --mechanism http2-ping-opaque --session-id live-pkt --afpacket-ipv4 --expected-frames 1
uv run celatim evidence run --scenario-id pcap-smoke --mechanism http2-ping-opaque --hex "00 ff 80 41" --pcap-dir out/pcaps
uv run celatim pcap decode --mechanism http2-ping-opaque --pcap out/pcaps/pcap-smoke_covert.pcap --expected-hex "00 ff 80 41" --output out/pcap-decode.json
uv run celatim evidence run --scenario-id smoke --mechanism http2-ping-opaque --hex "00 ff 80 41" --transport-dir out/evidence-wire
uv run celatim evidence run --scenario-id timed-smoke --mechanism http2-ping-opaque --hex "00 ff 80 41" --timed-transport
uv run celatim timing sweep --mechanism dns-timing --hex "00 ff 80 41" --unit-rate-hz 100 --quantum-s 0.010 --quantum-s 0.005 --output out/timing-sweep.json
uv run celatim timing observed-sweep --mechanism dns-timing --hex "00 ff 80 41" --unit-rate-hz 100 --trace-json out/observed-timing-trace.json --output out/observed-timing-sweep.json
uv run celatim evidence run --scenario-id retry-smoke --mechanism http2-ping-opaque --hex "00 ff 80 41" --max-receive-attempts 3
uv run celatim evidence run --scenario-id logged-smoke --mechanism http2-ping-opaque --hex "00 ff 80 41" --log-dir out/logs --run-id logged-smoke
uv run celatim evidence index out --output out/evidence-index.json
uv run celatim evidence public-index --evidence-index out/evidence-index.json --output out/public-evidence-index.json
uv run celatim doctor --artifact-dir out/doctor --output out/doctor.json
uv run celatim docs list
uv run celatim docs show --name api-guide
uv run celatim scenario list
uv run celatim scenario plan
uv run celatim testbed requirements
uv run celatim testbed qemu-preflight --disk-image receiver.qcow2 --no-kvm --output out/qemu-preflight.json
uv run celatim scenario run --scenario-id http2-ping-opaque-real-pdu-smoke --transport-dir out/scenario-wire
uv run celatim scenario run --scenario-id http2-ping-opaque-hyper-h2 --transport-transcript-json out/transcripts/{scenario_id}-{case}.json --output out/http2-hyper-h2-evidence.json
uv run --group daemon celatim scenario run --scenario-id http3-reserved-settings-aioquic --transport-transcript-json out/transcripts/{scenario_id}-{case}.json --output out/http3-aioquic-evidence.json
uv run --group daemon celatim scenario run --scenario-id quic-connection-id-aioquic --transport-transcript-json out/transcripts/{scenario_id}-{case}.json --output out/quic-aioquic-evidence.json
uv run celatim scenario run --scenario scenarios/http2-ping-opaque.toml --artifact-dir out/artifacts
uv run celatim scenario run --scenario-id ecdsa-nonce-local-crypto-transcript --transport-transcript-json out/transcripts/{scenario_id}-{case}.json --output out/ecdsa-evidence.json
uv run celatim scenario run --scenario-id rsa-pss-salt-local-crypto-transcript --transport-transcript-json out/transcripts/{scenario_id}-{case}.json --output out/rsa-pss-evidence.json
uv run celatim schema show --name scenario-v1
uv run celatim schema show --name scenario-inventory-v1
uv run celatim schema show --name scenario-execution-plan-v1
uv run celatim schema show --name testbed-requirements-v1
uv run celatim schema show --name support-matrix-v1
uv run celatim schema show --name evidence-run-v1
uv run celatim schema show --name evidence-index-v1
uv run celatim schema show --name public-evidence-index-v1
uv run celatim schema show --name pcap-decode-v1
uv run celatim schema show --name timing-sweep-v1
uv run celatim schema show --name qemu-tap-preflight-v1
uv run celatim schema show --name public-bundle-v1
uv run celatim schema show --name public-bundle-verify-v1
uv run celatim schema show --name reviewer-bundle-v1
uv run celatim schema show --name reviewer-bundle-verify-v1
```

Privileged production-path runs live in `experiments/` and use Linux namespaces,
veth links, real middleboxes, tcpdump/BPF, and real crypto libraries. See
`experiments/TEST-EVIDENCE.md` for the current evidence ledger and `docs/testbed.md`
for the tiering and daemon/VM plan.
The reusable pieces are moving into `celatim.testbed`: `NetnsPair` builds and tears
down the `snd`/`rcv` veth topology with non-fatal offload disabling,
`TcpdumpCapture` starts a namespaced `tcpdump -w` capture through an injectable process
runner, `AfpacketFrameSocket` sends or receives raw Ethernet frames through an
injectable socket factory, and `AfpacketCarrierTransport` wraps parser-visible
adapter carrier bytes in Ethernet/IPv4 TCP or UDP frames before decoding them back
through the mechanism adapter. `ManagedDaemon` starts long-running production daemons
through the same injectable process-runner pattern, waits on explicit readiness probes,
and terminates or kills the process on context exit. `DnsmasqResolverConfig` and
`DigQueryConfig` capture the real DNS daemon/client command shape from the legacy
EDNS(0) padding experiment so that path can be promoted into scenario TOML without
copying subprocess snippets. `run_afpacket_roundtrip` gives privileged scenarios a
receiver-before-sender wrapper: it opens the receiver socket, optionally holds a
capture context open, sends the carrier frames, then returns the same `ReceiveResult`
shape as other transports. The CLI exposes split live endpoints through
`send --afpacket-ipv4` and `recv --afpacket-ipv4 --expected-frames`; TOML scenarios
can also set `transport.kind = "afpacket_ipv4"`. Privileged AF_PACKET scenarios can
set `capture_pcap`, `capture_namespace`, `capture_interface`, `capture_filter`,
`capture_snaplen`, and `capture_require_output` under `[transport]` to hold a
namespaced tcpdump capture open during the receiver-before-sender run. Evidence output
records the resulting pcap as a `transport_capture` artifact with size and SHA-256,
and each `EvidenceRecord` includes endpoint OS metadata that labels same-process,
same-host artifact, same-kernel netns, and future cross-stack VM topologies.
DNS daemon transport metadata records best-effort `dnsmasq --version` and `dig -v`
command provenance with return codes, output hashes, and bounded excerpts, so
real-daemon evidence carries daemon/client version context in the evidence artifact.
`send_dns_edns0_padding()` and `receive_dns_edns0_padding()` expose the same
`dig`/`dnsmasq` path as split reusable helpers: the sender emits padding queries, and
the receiver owns daemon lifecycle, tcpdump waiting, pcap decode, and receive evidence.
`run_hyper_h2_ping_roundtrip()` exercises HTTP/2 PING opaque bytes through independent
`hyper-h2` client/server state machines in one process, validates PING ACK opaque
bytes, and can write private transcript artifacts for scenario evidence.
`run_aioquic_h3_settings_roundtrip()` exercises HTTP/3 reserved SETTINGS values
through independent `aioquic` H3Connection instances in one process, uses a controlled
local-settings hook before aioquic serializes the H3 control stream, and records that
hook in private transcript metadata.
`run_aioquic_connection_id_roundtrip()` exercises QUIC Initial destination connection
IDs through independent `aioquic` client/server connection objects in one process,
uses a controlled pre-connect client CID hook before aioquic serializes the Initial
datagram, and records that hook in private transcript metadata.
`EcdsaNonceTranscriptTransport` signs one ECDSA message per Class G carrier symbol,
verifies every signature, recovers the embedded nonce symbols locally, and records a
private JSON transcript plus honest-random control signatures.
`RsaPssSaltTranscriptTransport` builds standards-conforming RSA-PSS signatures with
caller-controlled salt bytes, verifies them through `cryptography`, recovers the salt
from the public RSA operation, and records honest-random PSS controls. Scenario TOML
can set `transport.kind = "crypto_ecdsa_nonce"` or `transport.kind =
"crypto_rsa_pss_salt"` with `transcript_json`, or callers can pass
`--transport-transcript-json` to place transcript artifacts in a reviewer bundle.
Capture paths are case-scoped automatically for covert and benign-control runs, or can
use `{scenario_id}` and `{case}` templates. `celatim lab up` and
`celatim lab down` now expose the reusable `NetnsPair` topology directly
through the stable CLI, with knobs for namespace names, interfaces, CIDRs, MTU,
offload handling, and binary paths. These helpers are tested without root using fake
runners and fake sockets. `QemuTapVm` and `HostTcpdumpCapture` package the manual
QEMU/TAP lifecycle for future cross-stack VM scenarios, and
`celatim testbed qemu-preflight` emits a non-mutating readiness report with
guest image, tool, KVM, TAP command, and QEMU argument checks without creating a TAP
device or starting a VM. The root `make reviewer-qemu-preflight` target writes the
same report under reviewer artifacts for manual/nightly preparation. These are
readiness artifacts only; they do not claim cross-stack evidence yet. The remaining
work is to move nominal-offset field injection/capture out of the monolithic
experiment scripts and add more daemon-backed paths.
Private reviewer bundle manifests can include schema-backed readiness reports with
`celatim bundle manifest --testbed-preflight qemu-preflight.json`; public
bundles keep only hash-only references to private reviewer manifests and do not copy
manual VM readiness reports.
`celatim.observer` adds run-level structure-oracle checks for the current real-PDU
fixtures. Evidence for HTTP/2 PING, QUIC connection ID, and RTCP APP records the
observer name, validator type, checked/failed unit counts, target-field offset and
length, extracted-field hashes, and the minimum non-zero surrounding bytes seen. This
makes the "real surrounding PDU bytes" claim auditable in the evidence JSON instead
of relying only on a static support-matrix label. The same observer path runs
negative mutation controls that write the symbol at a nominal carrier start or zero
all non-target surrounding bytes; evidence marks those controls successful only when
the mutated carrier fails validation.

`celatim` is the stable Python API for endpoint, session, measurement, and reviewer
workflows. It exports `ChannelSession`, `MechanismProfile`, `PacingConfig`, reliability
controls, file/pcap/timed and production-path transports, channel/catalog primitives,
scenario evidence APIs, structured errors, endpoint helpers, and typed result models.
For common endpoint paths, `send_payload()`, `receive_payload()`, and
`roundtrip_payload()` use the same session and envelope machinery as the CLI and return
JSON-serializable typed results.

The `celatim` command is the sole interactive CLI. Its endpoint commands can load a
packaged scenario with
`--scenario-id`, using the scenario mechanism, payload, pacing, reliability, and local
transport defaults while allowing explicit payload and transport overrides. Crypto
transcript scenarios use `--transcript-json`: `send` writes the verified transcript
artifact and `recv` replays that persisted transcript in a separate receiver command.
AF_PACKET packet-path scenarios can run through endpoint `roundtrip --capture-pcap`
so the receiver is armed before the live sender transmits and the capture artifact is
recorded; split AF_PACKET `send`/`recv` is available when callers coordinate the
receiver with `recv --expected-frames`, using the `expected_frames` value emitted by
`send`. The EDNS(0) DNS daemon scenario can also run through endpoint
`roundtrip --capture-pcap`, using the packaged `dig`/`dnsmasq` transport and recording
the query pcap, daemon readiness, answer summaries, and tool-version metadata. Split
EDNS(0) daemon `send`/`recv` is available with the same explicit coordination:
`send` emits `dig` queries and reports `expected_frames`, while
`recv --expected-frames ... --capture-pcap ...` starts `dnsmasq`, waits for tcpdump,
decodes the pcap, and records daemon/tool metadata. Direct HTTP/2 `hyper-h2`
endpoint roundtrips are available with transcript artifacts through
`roundtrip --scenario-id http2-ping-opaque-hyper-h2 --transcript-json ...`. Direct
HTTP/3 and QUIC `aioquic` endpoint roundtrips are available through
`roundtrip --scenario-id http3-reserved-settings-aioquic --transcript-json ...` and
`roundtrip --scenario-id quic-connection-id-aioquic --transcript-json ...`; the H3
path labels the controlled local-settings hook, and the QUIC path labels the
controlled pre-connect client CID hook. The
command also exposes packaged scenario list/run, evidence, support-matrix generation,
docs/schema inspection, detection and scrub guidance, doctor, and lab/testbed
workflows. Endpoint commands accept
caller-provided payload bytes as UTF-8 text, hex, or a binary file.
`send` writes a JSON envelope containing carrier symbols and, for parser-validated
real-PDU fixtures, the actual carrier bytes plus their SHA-256 hashes. `recv` decodes
that envelope, parses carrier bytes when present, rejects mismatches between carrier
bytes and symbols, and `roundtrip` checks byte-for-byte recovery in one process. The
adapter registry records whether a mechanism is a parser-validated real-PDU fixture, a
daemon/crypto/timing path, a minimal packet template, or an offset-represented
zero-blob row. It also exposes `profile.adapter.paths`, a path registry that names the
available transport kinds, evidence tier, required tools/extras, default scenario id,
and artifact behavior for each mechanism. Scenario evidence runs reject transport
kinds that are not registered for the selected adapter before entering a transport
implementation. Library callers can use `celatim.build_send_envelope` and
`celatim.parse_envelope_symbols` directly without going through argparse.
The Celatim wheel includes the default catalog, JSON schemas, documentation, and smoke scenario
specs. CLI defaults use those packaged resources, so `celatim roundtrip`,
`celatim scenario list`, `celatim schema show`,
`celatim matrix generate`, `celatim-support-matrix`, and
`celatim-paper-tables` run outside the repository tree. Pass `--catalog`,
`--scenario-dir`, or `--scenario` to use experiment-specific files instead.

## Release workflow

The checked release commands are:

```bash
make ci
uv build --out-dir dist
uvx twine check dist/*
uvx check-wheel-contents dist/*.whl
```

The package-smoke stage builds the sdist and wheel, installs the wheel into a fresh virtual environment,
changes into an outside-checkout work directory, and runs the packaged console scripts
against their default resources. It covers docs/schema/scenario discovery, doctor,
roundtrip, timing sweep, scenario evidence, evidence indexing, support-matrix
generation, paper-table generation, import timing, and representative in-memory
round-trip timing without relying on `cwd=measurement` or an editable install.
The smoke checks endpoint imports, `roundtrip_payload()`,
`profile.adapter.paths`, the `celatim` console script,
send/recv JSON, scenario-backed send/recv/roundtrip/evidence commands,
scenario/docs/matrix commands, and packet/tap aliases outside the checkout.
The pytest stage runs the unified package suite, which
checks version metadata, default catalog loading, codec/framer round-trip behavior,
endpoint helpers, the console-script entry point, transport aliases, and typed errors
through the installed package import surface.
Use `celatim matrix generate --format json` when CI or reviewer tooling needs
the same support matrix as a schema-backed `support-matrix-v1` document instead of
Markdown.

GitHub releases trigger `.github/workflows/release.yml`. The workflow builds and
validates the sdist and wheel, then publishes through PyPI trusted publishing from the
`pypi` environment. The exact pending-publisher identity and release procedure are in
[`RELEASING.md`](RELEASING.md). Publishing remains blocked until the project license is
selected and its PEP 639 metadata is added.

`celatim evidence run` executes a covert payload and benign control payload
together and emits the current JSON evidence schema, including adapter status,
payload hashes, byte-for-byte recovery, pacing metadata, parser validation when a
real-PDU fixture is available, parser provenance, detector provenance, scenario
metadata such as evidence tier and privilege, and reproducibility metadata such as
the catalog hash, package version, runtime environment, command transcript, and
scenario spec path.
Controls can be supplied as text, hex, a binary file, or generated bytes with
`--control-random-bytes N`; generated controls are labeled `control_random_bytes` in
the evidence JSON.
Each run has a top-level `run_id`; pass `--run-id` for deterministic artifact names.
Pass `--log-dir` to write a structured JSONL run log and record it as the top-level
`run_log` artifact. If `--artifact-dir` is set and `--log-dir` is omitted, run logs are
written under `artifact_dir/run-logs`, so failed reviewer runs leave a compact event
trail next to the carrier artifacts.
File, pcap, configured live AF_PACKET capture, and crypto transcript evidence runs
include a `transport_artifact` record with the transport/capture path, size, and
SHA-256 hash so reviewer bundles can audit the session record without rerunning the
scenario.
Real-PDU fixture runs also include `observer_validations` for each covert/control
case, so a wrong nominal offset, missing carrier bytes, or all-zero surrounding
structure is visible as an observer failure. Their `mutation_controls` field records
the deliberate wrong-offset and zero-surrounding-byte controls that failed as expected.
Pcap-backed marquee cases include `parser_provenance` entries for supported
tshark/Wireshark dissector fields. These records include display/decode settings,
field paths, command/return-code/output hashes, parsed-packet counts, and a
`tool_missing` result when tshark is unavailable; they are provenance, not a hard
runtime dependency.
Each case includes `detector_provenance`: current stateless cases record an executed
same-code detector plus generated-not-executed BPF/nft/iptables-u32 rule provenance.
`celatim detector rules` writes the same generated rule families plus a
Markdown detector appendix, a stateful detector plan, and Zeek/Suricata-style
templates for parser/baseline work. The public guidance and stateful plan include
catalog-authored detector predicates, false-positive posture, and
`annotation_source`; the current catalog has explicit detector posture for every row,
and guidance reports explicit-vs-derived annotation counts to catch regressions.
Pcap-backed TCP reserved-bit cases also run the
generated BPF rule through tcpdump/libpcap over the scenario pcap when tcpdump is
installed, recording the command, return code, and stdout/stderr hashes. Non-stateless
cases record the catalog detectability classification and explicitly mark scenario
controls as smoke fixtures rather than false-positive estimates.
`celatim detector replay --pcap TRACE --source-kind public_benign_trace`
runs an independent detector backend over an external pcap and emits a
`detector-replay-v1` report with trace hash, source/license fields, filtering
assumptions, per-rule command/output provenance, and aggregate checked/matched
packet-rule counts. The default `--backend bpf` path executes generated libpcap
filters through tcpdump. `--backend tshark_display_filter` executes a Wireshark
display-filter detector where the mechanism has a supported dissector field.
`--backend suricata_rule` executes a generated Suricata `tcp.hdr`/`byte_test` IDS
rule for the TCP reserved-bit marquee path and parses `eve.json` alerts. Aggregate
false-positive rates are populated only for authorized or public benign traces whose
trace provenance is complete and whose independent detector executions succeeded.
Complete provenance means a trace name, license/access policy, and filtering
assumptions; public traces also need a source URL or citation. Each replay report
also carries `false_positive_claim_status` and `false_positive_claim_blockers` so a
null false-positive rate records whether the blocker was source class, missing trace
metadata, an empty mechanism set, or incomplete detector execution. Use
`local_generated_control` or `scenario_control_fixture` for synthetic captures; those
reports stay useful for smoke coverage but keep `false_positive_estimate=false`.
For trace campaigns, write a `detector-trace-manifest-v1` JSON file with pcap paths,
source kinds, licenses, and filtering assumptions, then run
`celatim detector replay-corpus --trace-manifest traces.json --output
detector-replay-corpus.json`. The `detector-replay-corpus-v1` report aggregates
checked/matched packet-rule counts across traces and only populates a corpus
false-positive rate when every included trace is public or authorized benign traffic
and every selected detector execution succeeds.
For scrubber smoke checks, `celatim scrub pcap --mechanism
tcp-reserved-bits --input-pcap dirty.pcap --output-pcap scrubbed.pcap --output
scrub-report.json` canonicalizes the TCP reserved nibble to zero in a classic
Ethernet pcap and emits a `scrub-report-v1` artifact. The report is explicitly
labeled `same_code_offline_pcap_scrub_smoke_not_live_middlebox`; it is useful for
checking the catalog scrub strategy and detector/scrubber plumbing, but it is not a
claim about a live in-path normalizer.
Pass `--artifact-dir` to write parser-visible carrier bytes for real-PDU fixture
scenarios and include per-artifact paths, sizes, and SHA-256 hashes in the result.
`celatim evidence index` scans evidence-run JSON files or directories and
builds a reviewer evidence index containing each evidence JSON hash, scenario id,
mechanism id, status, command transcript, catalog hash, package/runtime metadata,
scenario metadata, scenario spec path, transport artifact hashes, detector provenance,
observer validation and mutation-control counts, carrier-structure/control-strength
classifications, and top-level evidence-tier, privilege, expected-runtime, tool, and
Python-extra summaries for the bundle. Pass
`--path-root` to rewrite
evidence, run-log, and transport artifact paths relative to a bundle root.
`celatim evidence public-index --evidence-index evidence-index.json` projects
that private index into `public-evidence-index-v1`, preserving aggregate counts and
evidence/run-log/transport hashes plus carrier-structure/control-strength
classifications while dropping commands and reviewer-only evidence, pcap, run-log,
carrier, and scenario-spec paths.
`celatim bundle manifest` hashes the scenario inventory, doctor report,
evidence index, generated paper table, optional Celatim package artifacts
(`celatim` wheel plus `uv.lock`), raw scenario TOML specs, and testbed packaging
files into a top-level `reviewer-bundle-v1` manifest so a reviewer can audit bundle
completeness without opening every file first.
`celatim bundle verify --manifest bundle-manifest.json` re-hashes those
referenced files and emits a `reviewer-bundle-verify-v1` report, exiting nonzero on
missing files, hash/size mismatches, or summary fields in the manifest that no longer
match the referenced doctor, scenario inventory, and evidence index. Verification
also follows the evidence index to check referenced evidence JSON, run-log,
pcap/transport, and carrier artifacts.
`celatim bundle public-manifest` hashes a public-safe subset of the bundle:
catalog, support matrix, detector/scrub guidance, generated detector rule artifacts,
Windows capture guidance, scenario inventory, the public evidence-index projection,
generated paper table, and hash-only references to the private reviewer bundle manifest
and verifier.
It does not include evidence JSON, pcap records, run logs, carrier dumps, or a duplicate
of the source code in the public evidence directory; the source is published through
the release repository and distributions. `celatim bundle public-verify`
re-hashes those public files and scans the bundle root for sensitive evidence classes
such as pcap, JSONL run-log, carrier, evidence, or experiment paths. This evidence-bundle
separation is not a source-code embargo.

`celatim scenario run` loads the same evidence-run configuration from a
packaged scenario id or TOML scenario spec. Use `--scenario-id` for installed-package
smoke runs and `--scenario` for an explicit local TOML file. Scenario specs are
versioned by `schema_version = "celatim.scenario.v1"` and have a checked
`scenario-v1` JSON Schema covering payload/control inputs, pacing, reliability,
artifact output, reviewer metadata, local transports, AF_PACKET packet-path settings,
and live tcpdump capture knobs. Scenario metadata records expected evidence tier,
privilege, expected runtime, required tools, and required Python extras; `scenario
list` exposes these fields plus top-level inventory summaries under the
`scenario-inventory-v1` schema for reviewer planning. `scenario plan` emits a
`scenario-execution-plan-v1` document with default-run inclusion, manual-review
counts, execution-mode counts, per-scenario reviewer commands, and skip reasons for
scenarios that need tools, extras, or privilege. `testbed requirements` emits a
`testbed-requirements-v1` manifest for live AF_PACKET, real-daemon, Docker, middlebox,
and QEMU/KVM paths. `doctor` treats declared tools, extras, and scenario privileges as
required preflight checks for the selected scenario set, and
`--require-testbed-profile` makes a named testbed profile's tools, extras, and
privileges mandatory.
Checked-in smoke scenarios currently cover the parser-validated HTTP/2 PING, QUIC
connection ID, RTCP APP, and minimal TCP reserved-bit real-PDU paths, plus manual
privileged EDNS(0) daemon and AF_PACKET TCP paths. The HTTP/2 `hyper-h2`, HTTP/3/QUIC
`aioquic`, ECDSA nonce, and RSA-PSS salt transcript scenarios are listed as
extra-dependent
non-privileged runs and excluded from default targets unless the `daemon` or `crypto`
extras are installed.

Library-facing code raises typed `celatim.errors` exceptions for unsupported
mechanisms, transport/tap failures, decode failures, and malformed envelopes.
Scenario evidence runs keep failed covert/control cases in the JSON result with
`evidence.ok = false` and an error string so artifact runs remain auditable.
`celatim.session.SessionFramingConfig` adds a session envelope above the
field-level framer for large or explicitly chunked messages. Chunked sessions carry
the session tag, chunk index, total chunk count, end marker, and SHA-256 checks for
each chunk and the reassembled payload; evidence records report `session_framing`,
`chunk_count`, and `integrity_sha256`.
`celatim.session.ReliabilityPolicy` controls receive attempts, retry backoff,
duplicate chunk suppression, timeout-aware tap receive through `PacingConfig.timeout_s`,
and optional loss-triggered retransmit requests for transports that implement
`retransmit_symbols`. Evidence records include
`reliability` metadata with the configured policy, observed attempts/retries,
timeout observations, retransmit requests, duplicate chunks, loss detection, and chunk
recovery counts.
`celatim.transports.FileTransport` is a reusable local transport/tap that writes one
JSON record per session, including parser-visible carrier bytes and hashes for
real-PDU adapters. It lets sender and receiver sessions run in separate processes
while using the same validation path as the CLI envelope; the CLI exposes it through
`send --transport-dir`, `recv --transport-dir`, `evidence run --transport-dir`, and
`scenario run --transport-dir`.
`celatim.transports.PcapTransport` writes one classic Ethernet pcap file per session
for real-PDU adapters. Each pcap record is an Ethernet/IPv4 carrier frame and the tap
extracts parser-visible carrier bytes back through the mechanism adapter. This gives
reviewer artifacts a standard capture file that tcpdump can inspect and hashable
transport records; it is not yet a live NIC, daemon, or AF_PACKET path.
`celatim.transports.extract_pcap_carriers`, `celatim.pcap_decode.decode_pcap`,
and `celatim pcap decode` decode a standalone classic pcap/tap artifact
through the same parser-visible carrier extraction path and emit `pcap-decode-v1`
with pcap hashes, carrier-unit hashes, recovered payload bytes, optional
expected-payload match status, optional tshark/Wireshark parser provenance, and an explicit
`same_code_pcap_decode_not_independent_trace_validation` claim label.
`celatim.observer.parser_provenance_for` is the Python API for optional tshark
dissector provenance over those pcaps; it currently maps TCP reserved bits, HTTP/2
PING opaque bytes, QUIC connection IDs, RTCP APP data, and EDNS(0) padding to
Wireshark field exports where the dissector supports the carrier.
`celatim.detect.replay_detectors_on_pcap` is the Python API behind detector replay:
pass catalog mechanisms, a pcap path, an explicit `TraceSourceKind`, and optionally a
`DetectorReplayBackend`. Reports only claim false-positive estimates for
`public_benign_trace` or `authorized_benign_trace` sources with complete source
metadata whose independent tool execution succeeds, and the top-level aggregate rate
is computed only from executed detector runs. Reports expose
`false_positive_claim_status` and `false_positive_claim_blockers` for the same claim
decision. The checked-in external-tool backends are tcpdump/libpcap BPF,
tshark/Wireshark display filters, and a Suricata IDS rule for the TCP reserved-bit
marquee path.
Use `celatim.detect.load_trace_manifest` and
`celatim.detect.replay_detector_corpus` for multi-trace campaigns. Manifest paths
resolve relative to the manifest location, and the corpus report preserves per-trace
source/license metadata while aggregating counts across all selected mechanisms.
`celatim.detect.scrub_tcp_reserved_bits_pcap` is the first executable scrubber
helper. It rewrites classic Ethernet pcaps for the TCP reserved-bit marquee path,
recomputes TCP checksums on changed IPv4/TCP frames, and returns the same
`scrub-report-v1` shape used by the CLI.
Private reviewer bundle manifests can hash these schema-backed replay and scrub
reports with `celatim bundle manifest --detector-replay
detector-replay.json --scrub-report scrub-report.json`; public bundles keep hash-only
references to the private reviewer manifest unless a report is separately selected
for publication.
`celatim.transports.TimedMemoryTransport` is a deterministic timing-aware local
transport for endpoint and scenario smoke tests. It applies caller-selected base delay
and symbol period through a sleeper, records per-carrier-unit timestamps, and emits a
`timing_trace` with observed offsets, inter-arrival intervals, and scheduling error
statistics. Evidence records also include a derived `timing_profile` with jitter
summary, tolerance source, estimated symbol-error rate, SNR when a quantum and
non-zero jitter are available, observed/scheduled unit rates, effective local goodput,
and an explicit local-demonstration rate label. This is useful API evidence for
pacing control; realistic timing-channel capacity claims still require the later
netns/daemon jitter, SNR, and rate sweeps.
`celatim.timing_sweep.run_timing_sweep` and `celatim timing sweep`
produce a separate `timing-sweep-v1` report for local timing mechanisms. The report
sends a baseline control payload before covert trials, sweeps one or more quanta, and
records SNR, symbol-error rate, payload-error rate, achieved local goodput, and a
local raw-bits-per-symbol capacity-model upper bound for each trial. Its claim status
is still `local_timed_memory_scheme_demonstration_not_capacity`.
`celatim.timing_sweep.run_observed_timing_sweep` and
`celatim timing observed-sweep` ingest externally captured timestamp offsets
and recovered bytes into the same report shape for netns, daemon, or VM timing paths.
Observed-trace reports carry
`observed_trace_timing_sweep_not_capacity_until_trace_provenance_review`; production
timing claims still require controlled captures with reviewer-grade trace provenance.
`celatim.metrics.timing` provides the reusable Class F capacity helpers behind that
discipline: Anantharam-Verdu `mu/e` queue-rate bounds in nats/s or bits/s, observed
symbol-rate upper bounds, and structured comparisons between the two. Class G rows use
`celatim.metrics.subliminal` for Simmons-style broadband catalog entropy ranges or
caller-supplied narrowband entropy bounds.
`celatim.report.macros` generates the paper's scale macros from the structured
catalog plus self-contained RFC/wiki metadata, so counts such as mechanism totals and
spec-acknowledged RFCs are not hand-edited in `paper/main.tex`.
`celatim.report.protocol_rates` loads `protocol_rates.toml` and joins those
carrier-unit rates to catalog mechanisms for structural throughput upper-bound figures.
The rows are explicitly labeled `structural_upper_bound_not_measured_goodput`.
`celatim.report.detector_rules` writes generated detector rule artifacts with claim
status `generated_not_executed_no_false_positive_estimate` for stateless files and
`generated_not_executed_requires_trace_baseline` for stateful plans/templates; executed
detector evidence still comes from scenario provenance or detector replay reports. The
stateful rows carry effective detector predicates, false-positive posture, and whether
the annotation came from explicit catalog metadata or a carrier-class default.
`celatim.report.windows_pktmon_guidance_markdown` writes Windows pktmon/ETW capture
guidance with claim status `capture_guidance_not_header_bit_filter`, explicitly
separating Windows trace collection from arbitrary header-bit detector claims.
Storage-path evidence records include a derived `throughput_profile`. For today's
packet, pcap, and zero-offset storage paths, it records `throughput_status:
sender_bound`, leaves `payload_rate_bps` and `observed_unit_rate_hz` null, and labels
the basis as `sender_bound_no_production_window`. Bits/s fields should stay null
until a batched/compiled or otherwise production-path sender provides a measured
window.

`celatim docs list` and `celatim docs show` expose packaged API,
scenario-authoring, reviewer-quickstart, and troubleshooting guides from the installed
wheel. `celatim schema show` prints the checked-in scenario, evidence, index,
and doctor JSON Schemas. The schemas and golden example are regression-tested so reviewer
artifacts keep the same shape as the live `scenario run` and `evidence index` output.
`celatim doctor` emits a JSON preflight report for the runtime environment,
packaged resources, scenario specs, optional external tools, and artifact-directory
writability. The environment check records the installed package version, Python
version, executable, platform, kernel release, and machine type before any scenario is
run. Scenario preflight validates TOML files against `scenario-v1`, so unknown or
malformed production-path knobs fail before a reviewer run starts. The package exposes
install extras for `packet` (Scapy), `crypto` (ECDSA and RSA-PSS dependencies), and
`daemon` (`hyper-h2`, `aioquic`, plus external daemon/testbed tools); `doctor --optional-extra packet` reports missing optional modules as
warnings, and `--require-extra packet` promotes them to failures. Missing optional
packet-path tools are warnings by default; installed tools record their binary path
and known version-command output. `--require-tool` promotes a tool check to a failure
and the command exits nonzero. The preflight report has a checked schema available via
`celatim schema show --name doctor-v1`.

From the repository root, `make reviewer-scenarios` writes a versioned scenario
inventory to `artifacts/reviewer/scenarios.json`, `make reviewer-plan` writes a
reviewer execution plan to `artifacts/reviewer/execution-plan.json`, `make
reviewer-testbed` writes privileged/daemon/VM requirements to
`artifacts/reviewer/testbed-requirements.json`, and `make reviewer-doctor` writes a
preflight report under `artifacts/reviewer/doctor/`. `make
reviewer-smoke` runs one
non-privileged pcap-backed real-PDU scenario, writes evidence JSON, carrier dumps,
pcap transport records, bundle-local copies of the scenario inventory and doctor
report, a generated table copy, an evidence index, `bundle-manifest.json`, and
`bundle-verify.json` under
`artifacts/reviewer/smoke/`. `make
reviewer-full` runs all checked-in non-privileged real-PDU smoke scenarios and writes
the same bundle shape under `artifacts/reviewer/full/`. Both private bundles include
bundle-local copies of the scenario TOML specs plus the current testbed Dockerfile and
testbed notes as hashed manifest artifacts; private manifests can also hash
schema-backed detector replay, detector replay corpus, scrub, and testbed preflight
reports. The generated
evidence indexes use
bundle-local paths for evidence JSON, run logs, and pcap records. `make
public-bundle` writes `artifacts/reviewer/public/` with only public-safe aggregate
artifacts, generated detector/scrub guidance, generated detector rule artifacts,
Windows capture guidance, the reviewer execution plan, the testbed requirements
manifest, a hash-only public evidence-index projection, a `public-bundle-v1` manifest
over the private reviewer bundle hashes, and a `public-bundle-verify-v1` report
enforcing the public-safe path policy.
`make paper-tables` regenerates the checked-in appendix longtable from
`measurement/data/mechanisms.jsonl`.

## Next engineering
See `../PLAN.md` for the remaining paper/report generation work, broader daemon-backed
scenarios, and infrastructure for repeatable result packaging.
