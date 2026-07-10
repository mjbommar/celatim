# celatim API Guide

This package provides an experimental authenticated file-transfer surface and public
research software for the RFC tunnel survey. Use it only in controlled and authorized
environments. The research surface encodes caller payload bytes into measured protocol
carriers and emits evidence describing what was exercised; the product transfer
surface keeps payloads encrypted and does not emit research evidence by default.

The Python examples below are tested against the packaged catalog resources and only
write artifacts beneath the current working directory.

## Authenticated file transfer

Install `celatim[transfer]` and import the typed async API from `celatim.transfer`.
Alice parses Bob's short-lived offer and starts an operation:

```python
from pathlib import Path

from celatim.transfer import TransferClient, TransferOffer


async def send_file(offer_text: str) -> None:
    offer = TransferOffer.parse(offer_text)
    async with TransferClient.open_default() as client:
        operation = await client.send_file(Path("report.pdf"), offer)
        async for event in operation.events():
            handle_progress(event)
        receipt = await operation.result()
        assert receipt.authenticated and receipt.acknowledged and receipt.verified
```

Bob can embed the receiver without invoking the CLI:

```python
from pathlib import Path

from celatim.transfer import TransferServer


async def receive_one() -> None:
    async with TransferServer(Path("incoming"), host="0.0.0.0") as server:
        offer = await server.create_offer(expires_in_s=900)
        publish_offer(offer.to_uri())
        receipt = await server.receive()
        index_received_file(receipt.path)
```

`TransferOperation` exposes ordered events, cancellation, and a typed result. Resume
uses `TransferClient.resume(transfer_id)` and the original authenticated manifest.
`TransferClient.send_stream()` accepts an async iterable of byte chunks through a
bounded owner-only disk spool, while `send_bytes()` is the in-memory convenience form.
The spool is retained for resume after failure and removed after authenticated success.
`TransferFailure` supplies a stable code, retryable/resumable flags, and a safe next
action. `TransferStateStore` persists owner-only atomic state; `ReceiverFile` writes a
destination-local spool and exposes the final name only after synchronization and
whole-file verification.

The implemented `offer_bound` trust mode authenticates the TLS certificate fingerprint
inside the exact offer received by Alice. It does not authenticate a human identity.
Provider fallback is opt-in. The built-in direct provider is `tcp-tls`; configured
AF_PACKET providers are labeled `synthetic_outer_frame` and require the separately
configured capability-bounded packet service.

## Core objects

Install the public `celatim` distribution and import endpoint, session, measurement,
and reviewer APIs from its single `celatim` namespace.

- `MechanismProfile.from_catalog(mechanism_id, catalog_path=None)` loads a catalog
  row, its codec, its adapter status, and its current evidence classification.
  `profile.adapter.paths` lists the registered execution paths for that mechanism,
  including the transport kind, evidence tier, required tools/extras, default
  scenario id where available, and whether the path records an artifact.
- `ChannelSession(profile, transport, ...)` is the sender/receiver workflow object.
- `Sender` and `Receiver` are structural protocol interfaces for objects that provide
  `send_message(...)` and `receive_message(...)`; `ChannelSession` satisfies both.
- `PayloadSource.text(...)`, `.hex(...)`, `.file(...)`, and `.random(...)` are
  reusable payload selectors for endpoint helpers; plain `bytes` still work.
- `send_payload()`, `receive_payload()`, and `roundtrip_payload()` are convenience
  helpers for the common memory/file/pcap/timed local transport paths.
- `send_scenario_payload()`, `receive_scenario_payload()`, and
  `roundtrip_scenario_payload()` load packaged scenarios by id, apply payload or
  local transport overrides, and run endpoint workflows from Python for the common
  memory/file/pcap/timed local transport paths.
- `decode_pcap_payload()` decodes a parser-visible pcap artifact into the
  schema-backed `PcapDecodeReport` used by the CLI, including recovered payload
  bytes, pcap hashes, parser provenance, and optional expected-payload matching.
- `scrub_pcap_payload()` runs the supported offline pcap scrubber path and returns
  the schema-backed `PcapScrubReport` used by the CLI, including input/output hashes
  and before/after matched-packet counts.
- `catalog_path()`, `load_mechanisms()`, `codec_for()`, `Framer`, `Channel`, and
  `IdealWire` expose the pure catalog/codec/framing layer for callers that need to
  validate payload encoding without entering a transport.
- `list_mechanism_summaries()` and `get_mechanism_detail()` expose the same
  mechanism/adapter discovery metadata as the endpoint CLI, including transport kinds
  and default scenario ids.
- `list_scenarios()`, `plan_scenarios()`, `list_scenario_ids()`, and `get_scenario()`
  expose the packaged scenario inventory, reviewer execution plan, runnable id list,
  and typed scenario configs from Celatim.
- `list_documents()`, `get_document_text()`, `list_schemas()`, `get_schema_text()`,
  `list_protocol_rates()`, `get_protocol_throughput_estimates()`,
  `get_protocol_rates_markdown()`, `get_detector_rule_artifacts()`,
  `get_detector_rule_manifest()`, `write_detector_rule_files()`,
  `get_detector_scrub_guidance_markdown()`, `get_windows_capture_guidance_markdown()`,
  `get_support_matrix_report()`, and `get_support_matrix_markdown()` expose packaged
  documentation, JSON Schemas, structural rate assumptions, public-safe detector
  artifacts, guidance, and support-matrix reports without shelling out to
  `celatim`.
- `get_testbed_requirements()` and `get_qemu_tap_preflight_report()` expose the
  privileged/daemon/VM readiness inventory and non-mutating QEMU/TAP command plan
  used by the Celatim CLI.
- `check_installation()` runs the packaged doctor/preflight checks from Python,
  including catalog/schema/scenario resources, selected tools/extras, testbed
  profiles, and artifact-directory writability.
- `PacingConfig` carries caller-selected rate, timing, and receive timeout controls.
- `ReliabilityPolicy` controls receive attempts, retry backoff, duplicate
  suppression, and optional loss-triggered retransmit requests for transports that
  implement `retransmit_symbols(session_id)`. Timeout-aware taps can implement
  `receive_symbols_with_timeout(session_id, timeout_s)`.
- `run_evidence_payload()` is the Python helper for scenario-id or ad hoc evidence
  runs; it mirrors `celatim evidence run` by accepting `PayloadSource`
  overrides, control payloads, artifact/log directories, and local transport choices.
- `run_timing_sweep_payload()` and `run_observed_timing_sweep_payload()` expose
  schema-backed `timing-sweep-v1` reports for local timed-memory sweeps and observed
  tap trace ingestion from Python.
- `manage_netns_lab()` exposes the standard Linux netns/veth lab lifecycle from
  Python and can return a dry-run command plan for rootless preflight checks.
- `EvidenceRecord` is returned with each receive or round-trip result.
- `EcdsaNonceTranscriptTransport` and `RsaPssSaltTranscriptTransport` are the local
  Class G signing transcript paths; they require the `crypto` extra at runtime.

The `celatim` distribution owns both the `celatim` command and Python API for endpoint,
scenario, evidence, support-matrix, documentation, and lab/testbed workflows. Paper
batch generators are separate entry points installed by the same wheel.

## In-memory round trip

```python
from celatim import ChannelSession, InMemoryTransport, MechanismProfile

profile = MechanismProfile.from_catalog("http2-ping-opaque")
transport = InMemoryTransport()
session = ChannelSession(profile, transport)

result = session.run_roundtrip(b"\x00reviewer\xff")
assert result.payload == b"\x00reviewer\xff"
assert result.evidence.mechanism_id == "http2-ping-opaque"
```

Use this tier for regression coverage only. It proves endpoint and framing behavior,
not deployed network behavior.

The helper API wraps the same session/envelope implementation. Payload-source helpers
turn text, hex, files, or generated random controls into the bytes expected by the
endpoint helpers:

```python
from celatim import (
    PayloadSource,
    random_payload,
    receive_payload,
    scrub_pcap_payload,
    send_payload,
)

sent = send_payload(
    "http2-ping-opaque",
    PayloadSource.hex("00 68 65 6c 70 65 72 ff"),
    session_id="api-helper",
)
received = receive_payload(sent, expected_payload=PayloadSource.hex("00 68 65 6c 70 65 72 ff"))
assert received.payload == b"\x00helper\xff"
control = random_payload(16)
assert len(control) == 16
doc = received.to_json()
assert doc["evidence"]["ok"]
assert doc["recovered_hex"] == "0068656c706572ff"
assert doc["expected_matches"]
```

Helper result objects expose `to_json()` for machine-readable caller logs. The
documents include payload hashes, recovered bytes, carrier/parser metadata, transport
artifact paths where present, and the nested receive evidence record.
`receive_payload(..., expected_payload=...)` and
`roundtrip_payload(..., expected_payload=...)` accept bytes or `PayloadSource` values
and raise `ControlFailureError` when recovered bytes differ.

Scenario endpoint helpers use the same scenario ids as the CLI while keeping results
as typed Python objects:

```python
from celatim import PayloadSource, roundtrip_scenario_payload

scenario_result = roundtrip_scenario_payload(
    "http2-ping-opaque-real-pdu-smoke",
    payload=PayloadSource.hex("00 ff 80 42"),
    pcap_dir="out/pcaps",
    expected_payload=PayloadSource.hex("00 ff 80 42"),
)

assert scenario_result.ok
assert scenario_result.sent.session_id == "http2-ping-opaque-real-pdu-smoke"
assert scenario_result.sent.transport_kind == "pcap"
assert scenario_result.expected_matches
```

For mechanism and scenario selection, use the discovery helpers before constructing a
session or scenario-backed command:

```python
from celatim import (
    get_detector_rule_artifacts,
    get_detector_rule_manifest,
    get_detector_scrub_guidance_markdown,
    get_document_text,
    get_mechanism_detail,
    get_protocol_rates_markdown,
    get_protocol_throughput_estimates,
    get_scenario,
    get_schema_text,
    get_support_matrix_report,
    get_windows_capture_guidance_markdown,
    list_documents,
    list_mechanism_summaries,
    list_protocol_rates,
    list_scenario_ids,
    list_schemas,
    plan_scenarios,
    write_detector_rule_files,
)

summaries = list_mechanism_summaries(transport_kind="http2_hyper_h2")
assert summaries[0].id == "http2-ping-opaque"

detail = get_mechanism_detail("http2-ping-opaque")
assert "http2_hyper_h2" in detail.to_json()["adapter"]["transport_kinds"]

default_ids = list_scenario_ids(default_included_only=True)
assert "http2-ping-opaque-real-pdu-smoke" in default_ids

plan = plan_scenarios()
assert plan.default_included_count == len(default_ids)

scenario = get_scenario("http2-ping-opaque-real-pdu-smoke")
assert scenario.mechanism_id == "http2-ping-opaque"

assert "api-guide" in {document.name for document in list_documents()}
assert get_document_text("api-guide").startswith("# celatim API Guide")
assert "evidence-run-v1" in {schema.name for schema in list_schemas()}
assert "celatim.evidence_run.v1" in get_schema_text("evidence-run-v1")
assert "dns-timing" in {rate.mechanism_id for rate in list_protocol_rates()}
assert get_protocol_throughput_estimates()[0].structural_upper_bound_bps > 0
assert "structural_upper_bound_not_measured_goodput" in get_protocol_rates_markdown()
assert "detector-rules.md" in {
    artifact.filename for artifact in get_detector_rule_artifacts()
}
assert get_detector_rule_manifest()["schema_version"] == "celatim.detector_rules.v1"
assert write_detector_rule_files("out/detector-rules")
assert get_detector_scrub_guidance_markdown().startswith("# Detector and Scrub Guidance")
assert get_windows_capture_guidance_markdown().startswith(
    "# Windows pktmon / ETW Capture Guidance"
)

matrix = get_support_matrix_report()
assert matrix.schema_version == "celatim.support_matrix.v1"
```

## File and pcap artifact transports

`FileTransport` stores one JSON carrier record per session. `PcapTransport` stores one
classic pcap file per session and requires an adapter that can build parser-visible
carrier bytes. The checked pcap-backed scenarios include payload-field fixtures such
as HTTP/2 PING opaque bytes and a minimal TCP-header fixture for `tcp-reserved-bits`.

```python
from pathlib import Path

from celatim import ChannelSession, FileTransport, MechanismProfile

profile = MechanismProfile.from_catalog("http2-ping-opaque")
transport = FileTransport(profile, Path("out/wire"))

sender = ChannelSession(profile, transport)
receipt = sender.send_message(b"\x00\xffpayload", session_id="demo")

receiver = ChannelSession(profile, transport)
result = receiver.receive_message(receipt.session_id)
assert result.payload == b"\x00\xffpayload"
```

Use `PcapTransport` when a reviewer artifact should include a hashable capture file.
It is still an artifact transport, not a live NIC tap. For standalone capture
recovery, use `extract_pcap_carriers()` or `decode_pcap()` against an existing classic
pcap/tap artifact:

```python
from pathlib import Path

from celatim import ChannelSession, MechanismProfile, PcapTransport, decode_pcap

profile = MechanismProfile.from_catalog("http2-ping-opaque")
transport = PcapTransport(profile, Path("out/pcaps"))
ChannelSession(profile, transport).send_message(b"\x00\xffpayload", session_id="demo")

report = decode_pcap(profile, transport.path_for("demo"), expected_payload=b"\x00\xffpayload")
assert report.ok
```

The resulting `pcap-decode-v1` report records pcap hashes, carrier-unit hashes,
recovered payload bytes, optional expected-payload matching, optional tshark/Wireshark
parser provenance, and a conservative same-code parser claim label.

## Evidence runs

`run_evidence_payload()` executes a covert payload and a benign control payload through
a packaged scenario id or ad hoc scenario configuration and returns JSON-serializable
evidence. Use lower-level `run_evidence()` only when constructing `ScenarioConfig`
manually.

```python
from celatim import PayloadSource, run_evidence_payload

result = run_evidence_payload(
    scenario_id="api-smoke",
    mechanism="http2-ping-opaque",
    payload=PayloadSource.hex("00 ff 70 61 79 6c 6f 61 64"),
    control_payload=PayloadSource.text("control"),
    pcap_dir="out/pcaps",
    log_dir="out/logs",
    run_id="api-smoke-run",
)
assert result.ok
doc = result.to_json()
assert doc["run_log"]["kind"] == "run_log"
```

Evidence JSON includes payload hashes, recovered bytes, adapter status, parser
validation where available, parser provenance, detector provenance, observer
validations, mutation controls, transport artifacts, run id, structured run-log
artifact, scenario metadata, command/reproducibility metadata, pacing, reliability,
timing metadata, throughput-claim metadata, and endpoint OS metadata. The
`endpoint_os` block labels local regression runs as `same_process`, artifact-backed
runs as `same_host_artifact`, current netns/veth paths as `same_kernel_netns`, and
future VM-backed runs as `cross_stack_vm` only when an independent receiver OS is
actually present.
For future VM paths, `celatim.testbed.build_qemu_tap_preflight_report()`,
`celatim.get_qemu_tap_preflight_report()`, `celatim testbed
qemu-preflight`, and `celatim testbed qemu-preflight` emit a non-mutating
QEMU/TAP readiness report: guest disk existence, QEMU and `ip` tool discovery,
optional `/dev/kvm` access, `tcpdump` discovery for host TAP captures, TAP
setup/cleanup commands, and the exact QEMU argv. The report has claim status
`preflight_only_no_vm_started`; it does not create a TAP device, start a VM, or claim
cross-stack channel evidence.
For the DNS EDNS(0) daemon path, case-level `transport_metadata` includes daemon
readiness, answer summaries, and best-effort `dnsmasq --version` / `dig -v`
provenance with return codes, output hashes, and bounded excerpts.
For the ECDSA nonce and RSA-PSS salt paths, case-level `transport_metadata` records
the crypto parameters, signature count, verified-signature count, recovered-symbol
count, transcript hash, and honest-random control summary. The transcript artifact is
private evidence; public bundle projections carry only hash/size references.
For storage paths, `throughput_profile` separates configured pacing and evidence
classification from goodput claims. Current packet/path rows are
`sender_bound_no_bits_per_second_claim` and leave `payload_rate_bps` null; a bits/s
value belongs there only after a production-path measurement window is available.
For timing paths, `run_timing_sweep()`,
`celatim.run_timing_sweep_payload()`, `celatim timing sweep`, and
`celatim timing sweep` produce a separate `timing-sweep-v1` artifact with a
baseline control run before covert trials, per-quantum SNR, symbol-error rate,
payload-error rate, achieved local goodput, and a raw-bits-per-symbol local capacity
upper bound. These reports remain labeled
`local_timed_memory_scheme_demonstration_not_capacity`. Use
`run_observed_timing_sweep()`, `celatim.run_observed_timing_sweep_payload()`,
`celatim timing observed-sweep`, or `celatim timing observed-sweep`
when a netns, daemon, or VM path has already produced observed timestamp offsets and
recovered bytes; that path preserves trace metadata and uses
`observed_trace_timing_sweep_not_capacity_until_trace_provenance_review` until the
captured trace provenance is reviewed.
For model-level estimates, use `celatim.metrics.timing` for Class F queue-rate and
observed-symbol-rate bounds, and `celatim.metrics.subliminal` for Class G broadband
or caller-supplied narrowband entropy bounds.
For paper artifacts, `celatim.report.catalog_figure_artifacts()` and
`write_catalog_figures()` generate deterministic SVG figures from the catalog; the CLI
surface is `celatim-paper-figures` or `celatim figures generate`.
`celatim.report.survey_scale_macros()` and `survey_scale_macros_tex()` generate the
paper's LaTeX scale macros from the catalog plus self-contained RFC/wiki metadata; the
CLI surface is `celatim-paper-macros`.
`celatim.report.load_protocol_rates()` loads the packaged rate assumptions used for
the throughput upper-bound figure, and `celatim rates show` renders the same
assumptions for review. These rates remain structural assumptions, not measured
production-goodput evidence.
`celatim.report.detector_rule_artifacts()` and
`write_detector_rule_artifacts()` generate the public-safe detector appendix and
nftables, iptables `u32`, BPF, Zeek, and Suricata-style detector files. Stateless
files use claim status `generated_not_executed_no_false_positive_estimate`; stateful
plans/templates use `generated_not_executed_requires_trace_baseline`. Generated
guidance/stateful rows include effective detector predicates, false-positive posture,
and `annotation_source` so authored catalog values are separated from class-derived
defaults.
`celatim.report.windows_pktmon_guidance_markdown()` generates Windows pktmon/ETW
capture guidance with claim status `capture_guidance_not_header_bit_filter`; it is
capture guidance, not a Windows firewall header-bit detector.
Machine-readable artifact contracts are available through
`celatim schema show`; the QEMU/TAP readiness report uses
`qemu-tap-preflight-v1`.
For pcap-backed marquee cases, `parser_provenance` records optional tshark/Wireshark
field exports with decode/display settings, field paths, parsed packet counts, and
command/output hashes. Missing tshark is recorded as `tool_missing` and does not make
the scenario fail.
For pcap-backed TCP reserved-bit cases, detector provenance includes tcpdump/libpcap
BPF execution metadata when tcpdump is available; generated nftables, iptables `u32`,
and BPF rules are recorded as separate provenance artifacts. Scenario controls remain
smoke fixtures, not false-positive estimates.

Detector replay is separate from scenario evidence. Use it for public or otherwise
authorized benign traces:

```bash
celatim detector replay \
  --pcap traces/benign.pcap \
  --source-kind public_benign_trace \
  --trace-name mawi-sample \
  --filtering-assumption "TCP packets only; no known experimental traffic" \
  --output out/detector-replay.json
```

The resulting `detector-replay-v1` report records the trace hash, source/license
metadata, filtering assumptions, tcpdump/libpcap command metadata, matched packet
counts, and aggregate checked/matched packet-rule rates. Aggregate false-positive
rates are populated only when the source is a public or authorized benign trace, the
trace has complete provenance, and every selected independent detector execution
succeeded. Complete provenance means a trace name, license/access policy, and
filtering assumptions; public traces also need a source URL or citation. The report
also includes `false_positive_claim_status` and `false_positive_claim_blockers` so
non-claims identify missing metadata, non-FP source classes, empty mechanism sets, or
incomplete detector execution. Synthetic pcaps should use `local_generated_control`
or `scenario_control_fixture`, which keeps `false_positive_estimate=false`.
The default backend is `--backend bpf`. To execute a Wireshark/tshark display-filter
detector where a supported field exists, use:

```bash
celatim detector replay \
  --pcap traces/benign.pcap \
  --source-kind public_benign_trace \
  --backend tshark_display_filter \
  --output out/detector-replay-tshark.json
```

The initial tshark replay backend covers the TCP reserved-bit marquee detector with
`tcp.flags.res != 0`; unsupported mechanisms are reported as unsupported rather than
silently mapped to a same-code check.
For the same marquee detector, `--backend suricata_rule` writes a generated Suricata
rule using `tcp.hdr` plus `byte_test`, runs Suricata over the pcap when available,
and parses matching alerts from `eve.json`:

```bash
celatim detector replay \
  --pcap traces/benign.pcap \
  --source-kind public_benign_trace \
  --backend suricata_rule \
  --output out/detector-replay-suricata.json
```

Missing Suricata is recorded as `tool_missing` and does not become a
false-positive estimate.
For multi-trace campaigns, create a `detector-trace-manifest-v1` JSON file and run:

```bash
celatim detector replay-corpus \
  --trace-manifest traces/detector-traces.json \
  --output out/detector-replay-corpus.json
```

The `detector-replay-corpus-v1` report aggregates checked/matched packet-rule counts
across traces and only emits a corpus false-positive rate when every trace is public
or authorized benign traffic and every selected detector execution succeeds; the same
claim status and blockers are preserved at both corpus and per-trace summary levels.
Python callers can use `celatim.detect.load_trace_manifest()` and
`celatim.detect.replay_detector_corpus()` for the same workflow.
For an executable scrubber smoke check over the TCP reserved-bit marquee path:

```bash
celatim scrub pcap \
  --mechanism tcp-reserved-bits \
  --input-pcap traces/dirty.pcap \
  --output-pcap out/scrubbed.pcap \
  --output out/scrub-report.json

celatim scrub pcap \
  --mechanism tcp-reserved-bits \
  --input-pcap traces/dirty.pcap \
  --output-pcap out/scrubbed.pcap \
  --output out/scrub-report.json
```

The `scrub-report-v1` artifact records input/output hashes and before/after matched
packet counts. Its claim status is
`same_code_offline_pcap_scrub_smoke_not_live_middlebox`, so it should be read as an
offline countermeasure plumbing check, not live middlebox evidence.
Private reviewer manifests can include these reports with
`bundle manifest --detector-replay detector-replay.json --scrub-report
scrub-report.json`. Public bundles use `evidence public-index` for a hash-only
evidence-index projection and keep hash-only references to the private reviewer
manifest unless a replay or scrub report is
separately selected for publication.

To generate public-safe rule artifacts and stateful detector templates for review:

```bash
celatim detector rules \
  --output-dir out/detector-rules \
  --output out/detector-rules-manifest.json
```

For Windows pktmon/ETW capture guidance:

```bash
celatim detector windows-guidance \
  --output out/windows-pktmon-etw-guidance.md
```

For public artifact guidance, run:

```bash
celatim guidance generate --output detector-scrub-guidance.md
```

The generated Markdown summarizes detection posture, scrub strategy, and per-mechanism
defensive guidance from catalog fields without embedding channel code, evidence JSON,
pcaps, run logs, or carrier dumps. The channel source is published separately with the
release distributions.
For machine-readable evidence planning, `celatim matrix generate --format
json` emits `support-matrix-v1` with per-mechanism adapter status, capabilities,
evidence bucket, carrier structure, control strength, independent validator, throughput
status, and upgrade priority.
When building a public bundle, pass generated detector files through
`bundle public-manifest --detector-rule-artifact ...` and pass the Windows guidance
through `--windows-capture-guidance`; pass the `evidence public-index` output as the
bundle evidence index. These artifacts are hashed as public-safe artifacts and verified
by `bundle public-verify`.

## CLI equivalents

```bash
celatim roundtrip --mechanism http2-ping-opaque --hex "00 ff 80 41"
celatim send --mechanism http2-ping-opaque --session-id demo --hex "00 ff" --transport-dir out/wire
celatim recv --mechanism http2-ping-opaque --session-id demo --transport-dir out/wire --expect-hex "00 ff"
celatim send --scenario-id http2-ping-opaque-real-pdu-smoke --transport-dir out/scenario-wire
celatim recv --scenario-id http2-ping-opaque-real-pdu-smoke --transport-dir out/scenario-wire
celatim roundtrip --scenario-id http2-ping-opaque-real-pdu-smoke --pcap-dir out/pcaps
celatim pcap decode --mechanism http2-ping-opaque --pcap out/pcaps/http2-ping-opaque-real-pdu-smoke.pcap --expect-hex "00 ff"
celatim scrub pcap --mechanism tcp-reserved-bits --input-pcap traces/dirty.pcap --output-pcap out/scrubbed.pcap --output out/scrub-report.json
celatim doctor --artifact-dir out/doctor-artifacts --output out/doctor.json
celatim schema list --output out/schemas.json
celatim schema show --name evidence-run-v1 --output out/evidence-run.schema.json
celatim rates show --format json --output out/protocol-rates.json
celatim timing sweep --mechanism dns-timing --hex "00 ff" --unit-rate-hz 100 --quantum-s 0.01 --output out/timing-sweep.json
celatim timing observed-sweep --mechanism dns-timing --hex "00 ff" --unit-rate-hz 100 --trace-json out/observed-trace.json --output out/observed-timing-sweep.json
celatim guidance generate --output out/detector-scrub-guidance.md
celatim guidance windows-capture --output out/windows-pktmon-etw-guidance.md
celatim detector rules --output-dir out/detector-rules --output out/detector-rules-manifest.json
celatim testbed requirements --profile netns-afpacket --profile qemu-cross-stack --output out/testbed-requirements.json
celatim testbed qemu-preflight --disk-image receiver.qcow2 --no-kvm --output out/qemu-preflight.json
celatim lab up --dry-run --output out/lab-plan.json
celatim evidence run --scenario-id http2-ping-opaque-real-pdu-smoke --pcap-dir out/pcaps --log-dir out/logs --run-id api-smoke-run
celatim evidence run --scenario-id api-random-control --mechanism http2-ping-opaque --hex "00 ff" --control-random-bytes 16
celatim send --scenario-id ecdsa-nonce-local-crypto-transcript --transcript-json out/transcripts/ecdsa.json
celatim recv --scenario-id ecdsa-nonce-local-crypto-transcript --transcript-json out/transcripts/ecdsa.json
celatim send --scenario-id tcp-reserved-bits-afpacket-netns --output out/afpacket-send.json
celatim recv --scenario-id tcp-reserved-bits-afpacket-netns --expected-frames 17 --output out/afpacket-recv.json
celatim roundtrip --scenario-id tcp-reserved-bits-afpacket-netns --capture-pcap out/pcaps/tcp-reserved.pcap
celatim send --scenario-id edns0-padding-dnsmasq-dig-real-daemon --output out/dns-send.json
celatim recv --scenario-id edns0-padding-dnsmasq-dig-real-daemon --expected-frames 17 --capture-pcap out/pcaps/edns0-padding.pcap --output out/dns-recv.json
celatim roundtrip --scenario-id edns0-padding-dnsmasq-dig-real-daemon --capture-pcap out/pcaps/edns0-padding.pcap
celatim roundtrip --scenario-id http2-ping-opaque-hyper-h2 --transcript-json out/transcripts/{scenario_id}-{case}.json
celatim roundtrip --scenario-id http3-reserved-settings-aioquic --transcript-json out/transcripts/{scenario_id}-{case}.json
celatim roundtrip --scenario-id quic-connection-id-aioquic --transcript-json out/transcripts/{scenario_id}-{case}.json
celatim mechanism list --usable-only --output out/mechanisms.json
celatim mechanism show http2-ping-opaque --output out/http2-ping-opaque.json
celatim evidence run --scenario-id api-smoke --mechanism http2-ping-opaque --hex "00 ff" --pcap-dir out/pcaps --log-dir out/logs --run-id api-smoke-run
```

`celatim` owns the endpoint send/recv/roundtrip surface. Its endpoint commands can load packaged scenario defaults with
`--scenario-id` and then apply explicit payload or local-transport overrides. For
receiver-side assertions, `recv` and `roundtrip` accept `--expect`, `--expect-hex`,
or `--expect-file`; successful JSON records the expected payload hash and
`expected_matches`, and mismatches fail with `ControlFailureError`.
`mechanism list` and `mechanism show` expose catalog mechanism ids, adapter status,
transport kinds, and default scenario ids so callers can discover runnable endpoint
paths without reading source files. Python callers can use the same metadata through
`list_mechanism_summaries()` and `get_mechanism_detail()`. For
crypto transcript scenarios, `send --transcript-json ...` writes the transcript and
`recv --transcript-json ...` replays that persisted artifact through the receiver. Use
`roundtrip --capture-pcap ...` for live AF_PACKET packet-path scenarios, where the
receiver must be armed before the sender transmits. Split AF_PACKET `send`/`recv` is
available when the caller supplies `recv --expected-frames`; `send` includes that count
in its JSON output for coordination. The same endpoint `roundtrip` shape can run the
EDNS(0) `dig`/`dnsmasq` real-daemon scenario and records the query pcap, daemon
readiness, answers, and tool-version metadata. Split EDNS(0) daemon `send`/`recv` is
also available for that scenario: `send` emits `dig` queries and reports the expected
query count, while `recv --expected-frames ... --capture-pcap ...` starts `dnsmasq`,
waits for tcpdump, decodes the pcap, and records daemon/tool metadata. The HTTP/2
`hyper-h2` scenario is a non-privileged roundtrip-only path that validates PING ACK
opaque bytes and writes transcript artifacts with `--transcript-json`. The HTTP/3 and
QUIC `aioquic` scenarios are also non-privileged and roundtrip-only; they use
controlled hooks before aioquic serializes the H3 control stream or QUIC Initial
datagram and record those hooks in private transcript metadata. Use
`celatim` for the broader reviewer/artifact commands;
evidence-producing commands record the executable name in their command provenance.
Pass `--catalog` to use a checkout-specific catalog.
Without it, commands use the packaged catalog resource.
