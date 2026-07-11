# Reviewer Quickstart

These commands exercise the non-privileged artifact path. They do not create network
namespaces, open raw sockets, or require daemon containers.

## Setup

```bash
cd measurement
uv sync
uv sync --extra packet --extra crypto
uv run pytest
uv run ruff check .
uv run ty check
cd ..
make package-smoke
```

The default catalog, schemas, and smoke scenarios are packaged resources. Commands work
outside the checkout unless you pass explicit `--catalog`, `--scenario-dir`, or
`--scenario` paths.
`package-smoke` proves that boundary by building the wheel, installing it into a fresh
virtual environment, changing into an outside-checkout work directory, and running the
installed console scripts against packaged defaults.

## Inspect docs and schemas

```bash
uv run celatim docs list
uv run celatim docs show --name api-guide
uv run celatim schema show --name evidence-run-v1
uv run celatim schema show --name scenario-v1
```

## Run smoke evidence

From the repository root:

```bash
make reviewer-doctor
make reviewer-scenarios
make reviewer-plan
make reviewer-testbed
make reviewer-smoke
make reviewer-full
make reviewer-afpacket-tcp
make reviewer-dns-daemon
make public-bundle
```

`reviewer-smoke` runs one pcap-backed real-PDU scenario. `reviewer-full` runs the
execution-plan default-included non-privileged scenarios, including the TCP
reserved-bit minimal-header case, and skips manual privileged scenarios. Both
produce evidence JSON, carrier
artifacts, pcap records, bundle-local scenario and doctor JSON, a generated table copy,
an evidence index, `bundle-manifest.json`, and `bundle-verify.json` under
`artifacts/reviewer/`. Their evidence indexes use paths relative to each bundle
directory.
`reviewer-afpacket-tcp` is an explicit manual target for the privileged TCP
reserved-bit AF_PACKET scenario. It requires the `netns-afpacket` testbed profile,
creates and tears down the `snd`/`rcv` lab, writes tcpdump pcaps/logs/carriers under
`artifacts/reviewer/afpacket-tcp/`, and verifies a private reviewer bundle for that
single scenario.
`reviewer-dns-daemon` is an explicit manual target for the privileged EDNS(0)
`dig`/`dnsmasq` scenario. It requires the `dns-daemon-netns` testbed profile, creates
and tears down the `snd`/`rcv` lab, stores pcaps/logs/carriers under
`artifacts/reviewer/dns-daemon/`, and verifies a private reviewer bundle for that
single scenario.
Use `celatim pcap decode --mechanism ... --pcap ...` to decode a standalone
classic pcap/tap artifact through the registered carrier parser and write a
`pcap-decode-v1` report. The report includes optional tshark/Wireshark parser
provenance through `--tshark-binary`, is useful for capture recovery checks, and
carries the same-code parser claim label; it is not independent parser validation
unless the external parser record executed successfully.
DNS transport metadata records daemon readiness, answers, and best-effort
`dnsmasq --version` / `dig -v` command provenance with output hashes and bounded
excerpts.
`reviewer-scenarios` writes `artifacts/reviewer/scenarios.json`, a versioned scenario
inventory with scenario ids, evidence-tier and privilege counts, expected runtime, and
required tools/extras.
`reviewer-plan` writes `artifacts/reviewer/execution-plan.json`, a versioned execution
plan with default-run inclusion, manual-review counts, execution-mode counts,
per-scenario reviewer commands, and skip reasons for scenarios that need tools,
extras, or privilege.
`reviewer-testbed` writes `artifacts/reviewer/testbed-requirements.json`, a versioned
manifest for live AF_PACKET, real-daemon, Docker, middlebox, and QEMU/KVM testbed
requirements.
For manual QEMU/KVM preparation, `make reviewer-qemu-preflight
QEMU_GUEST_IMAGE=<guest.qcow2>` or `celatim testbed qemu-preflight
--disk-image <guest.qcow2> --output qemu-preflight.json` writes a non-mutating
readiness report and command plan. It checks disk/tool/KVM access and renders TAP/QEMU
commands, but it does not create a TAP device, start a VM, or claim cross-stack
evidence.
The preflight report validates against the packaged `qemu-tap-preflight-v1` schema.
Private reviewer manifests can hash schema-backed readiness reports with
`celatim bundle manifest --testbed-preflight qemu-preflight.json`; public
bundles retain only hash-only private-bundle references.
`reviewer-doctor` writes package, Python, platform, kernel, resource, scenario, tool,
and artifact-directory preflight metadata before the evidence runs. Installed external
tools include binary paths and known version-command output. For optional packet or
crypto experiments, run `celatim doctor --optional-extra packet
--optional-extra crypto`; use `--require-extra` when that support is mandatory for a
specific scenario set.
`celatim scenario list` reports each scenario's evidence tier, privilege
requirement, expected runtime, required tools, and required Python extras, and its
output validates against `scenario-inventory-v1`. `celatim scenario plan`
emits the reviewer execution plan and validates against `scenario-execution-plan-v1`.
`doctor` enforces the declared tool and extra requirements for the scenario directory
it checks. For privileged or manual paths, pass `--require-testbed-profile
netns-afpacket`, `--require-testbed-profile dns-daemon-netns`, or another profile from
`celatim testbed requirements` to make that profile's tools, extras, and
privileges mandatory.

## Run one scenario directly

```bash
cd measurement
uv run celatim scenario run \
  --scenario-id http2-ping-opaque-real-pdu-smoke \
  --pcap-dir out/pcaps \
  --artifact-dir out/carriers \
  --log-dir out/logs \
  --run-id reviewer-smoke \
  --output out/evidence.json
uv run celatim evidence index out --output out/evidence-index.json
```

The single `celatim` wheel owns `celatim send`, `celatim recv`, packaged scenario
list/run, support-matrix generation, documentation display, and lab topology
setup/teardown. Evidence-producing commands record `celatim` as their executable.
Python callers import endpoint, session, survey, and reviewer helpers from `celatim`.

The local Class G crypto scenarios require the `crypto` extra and write private
transcript artifacts:

```bash
uv run celatim scenario run \
  --scenario-id ecdsa-nonce-local-crypto-transcript \
  --transport-transcript-json out/transcripts/{scenario_id}-{case}.json \
  --output out/ecdsa-evidence.json
uv run celatim scenario run \
  --scenario-id rsa-pss-salt-local-crypto-transcript \
  --transport-transcript-json out/transcripts/{scenario_id}-{case}.json \
  --output out/rsa-pss-evidence.json
```

The non-privileged daemon-extra library-stack scenarios also write private transcript
artifacts:

```bash
uv run --group daemon celatim scenario run \
  --scenario-id http2-ping-opaque-hyper-h2 \
  --transport-transcript-json out/transcripts/{scenario_id}-{case}.json \
  --output out/http2-hyper-h2-evidence.json
uv run --group daemon celatim scenario run \
  --scenario-id http3-reserved-settings-aioquic \
  --transport-transcript-json out/transcripts/{scenario_id}-{case}.json \
  --output out/http3-aioquic-evidence.json
uv run --group daemon celatim scenario run \
  --scenario-id quic-connection-id-aioquic \
  --transport-transcript-json out/transcripts/{scenario_id}-{case}.json \
  --output out/quic-aioquic-evidence.json
```

The OpenSSH scenario requires a reachable production `sshd` on the host and port in
the scenario specification (localhost port 22 by default):

```bash
uv run --group ssh celatim scenario run \
  --scenario-id ssh-kexinit-openssh-real-daemon \
  --transport-transcript-json out/transcripts/{scenario_id}-{case}.json \
  --output out/ssh-openssh-evidence.json
```

Its transcript records the OpenSSH version and host-key hash but does not authenticate
the host key; run it only against a controlled server whose address is independently
known.

Inspect `out/evidence.json` for payload hashes, recovered bytes, parser validation,
parser provenance, detector provenance, observer validation, mutation controls,
transport metadata, transport artifact hashes, structured run-log artifact hashes,
scenario metadata, environment metadata, and the per-case `endpoint_os` block. Current
local and netns scenarios should report `same_process`, `same_host_artifact`, or
`same_kernel_netns`; `cross_stack_vm` is reserved for future VM evidence with an
independent receiver OS.
For pcap-backed marquee cases, parser provenance includes optional tshark/Wireshark
field-export metadata. If tshark is absent, the record is `tool_missing`; this is a
preflight gap, not a scenario failure.
For the pcap-backed TCP reserved-bit scenario, detector provenance includes
tcpdump/libpcap BPF execution metadata when tcpdump is installed. Generated
BPF/nft/iptables-u32 rules that are not executed are marked separately.
To write those generated rule artifacts for review, run
`celatim detector rules --output-dir detector-rules --output
detector-rules-manifest.json`; this includes stateless files plus a stateful plan and
Zeek/Suricata-style templates. The manifest separates stateless
`generated_not_executed_no_false_positive_estimate` artifacts from stateful
`generated_not_executed_requires_trace_baseline` templates.
For Windows capture planning, run
`celatim detector windows-guidance --output windows-pktmon-etw-guidance.md`.
This guidance uses pktmon/ETW for trace collection and explicitly avoids claiming
Windows firewall arbitrary header-bit matching.
To replay generated BPF rules over an external benign trace, run
`celatim detector replay --pcap TRACE.pcap --source-kind public_benign_trace
--output detector-replay.json`. The `detector-replay-v1` report records trace
provenance, filtering assumptions, per-rule tcpdump/libpcap command/output hashes,
and aggregate checked/matched packet-rule counts. It only reports an aggregate
false-positive rate when the trace is public or authorized benign traffic and every
selected detector ran successfully. FP estimates also require complete trace
provenance: trace name, license/access policy, filtering assumptions, and a source URL
or citation for public traces. Reports include `false_positive_claim_status` and
`false_positive_claim_blockers` so reviewers can see why a replay did or did not
become a false-positive estimate. Use `local_generated_control` or
`scenario_control_fixture` for generated captures; those reports are smoke controls and
do not claim false-positive estimates.
The default replay backend is `--backend bpf` through tcpdump/libpcap. For supported
mechanisms, `--backend tshark_display_filter` runs an independent Wireshark/tshark
display filter instead; the checked-in support currently covers the TCP reserved-bit
marquee detector as `tcp.flags.res != 0`.
`--backend suricata_rule` is another external-tool path for the same marquee detector:
it runs a generated Suricata `tcp.hdr`/`byte_test` IDS rule over the pcap and counts
matching `eve.json` alerts when Suricata is installed. Missing Suricata is recorded as
`tool_missing` and does not produce an FP estimate.
For a trace campaign, write a `detector-trace-manifest-v1` JSON file and run
`celatim detector replay-corpus --trace-manifest detector-traces.json
--output detector-replay-corpus.json`. The corpus report aggregates checked/matched
packet-rule counts across traces and only reports a corpus false-positive rate when
all included traces and detector executions satisfy the same public/authorized benign
criteria; corpus reports carry the same claim status and blocker fields.
For a same-code scrubber smoke check, run `celatim scrub pcap --mechanism
tcp-reserved-bits --input-pcap dirty.pcap --output-pcap scrubbed.pcap --output
scrub-report.json`. The report is `scrub-report-v1` and carries claim status
`same_code_offline_pcap_scrub_smoke_not_live_middlebox`, so it does not substitute for
live normalizer evidence.
Private reviewer manifests can hash replay and scrub reports with
`celatim bundle manifest --detector-replay detector-replay.json
--scrub-report scrub-report.json`; public bundles keep only the private
manifest/verifier hashes unless a report is
separately approved for publication.
For local timing discipline checks, run
`celatim timing sweep --mechanism dns-timing --hex 00ff --unit-rate-hz 100
--quantum-s 0.010 --quantum-s 0.005 --output timing-sweep.json`. The report records
a baseline control run, one trial per quantum, SNR, symbol-error rate,
payload-error rate, local goodput, and a local capacity-model upper bound, but remains
labeled as a local scheme demonstration.
For externally captured timing paths, use `celatim timing observed-sweep`
with a trace JSON file containing `baseline`, `trials`, `observed_offsets_s`, and
`recovered_hex`. This ingests netns/daemon/VM tap timestamps into the same
`timing-sweep-v1` shape while keeping the observed-trace claim label conservative
until trace provenance is reviewed.
Daemon scenarios use `transport_metadata` for daemon readiness, production-client
answer summaries, and daemon/client version-command provenance. Crypto transcript
scenarios use `transport_metadata` for ECDSA/RSA-PSS settings, signature verification
counts, recovered-symbol counts, transcript hashes, and honest-random control
summaries. HTTP/2 `hyper-h2` and QUIC `aioquic` transcript scenarios use
`transport_metadata` for library implementation, validation counts, transcript schema,
and controlled-hook status where applicable. Inspect `out/evidence-index.json` for the
same run's evidence hash,
package/runtime metadata,
scenario metadata, scenario spec path, endpoint topology summary, transport artifact hashes,
detector/observer/mutation-control counts, carrier-structure/control-strength
classifications, and top-level evidence-tier, privilege, expected-runtime, tool, and
Python-extra summaries.
For portable bundles, pass `--path-root` to `evidence index` so evidence/run-log/pcap
paths are written relative to that root.
For Alice/Bob home-lab runs, use `celatim crosshost public-index
--run-dir artifacts/alice-bob/<run-id> --output docs/crosshost/alice-bob-public-index.json`
to project raw run directories into a public-safe index. It preserves payload hashes,
suite counts, per-method efficiency/timing summaries, and artifact hashes while
excluding raw `payload.bin` and private carrier artifacts. Use `celatim
claims subliminal-controls --transcript-json TRANSCRIPT.json --min-control-signatures
100 --output docs/subliminal-control-report.json` for Class-G transcript controls,
then `celatim claims ledger --crosshost-index ... --subliminal-control-report
... --output docs/claim-ledger.json` so paper counts distinguish adapter capability
from run-backed evidence.
Before building a public bundle, run `celatim evidence public-index` to
derive a hash-only `public-evidence-index-v1` projection that drops reviewer-only
commands and evidence, pcap, run-log, carrier, and scenario-spec paths while keeping
the carrier-structure/control-strength classifications.
Use `celatim bundle manifest` to bind a scenario inventory, doctor report,
evidence index, generated paper table, and optional Celatim package artifacts
(`celatim` wheel plus `uv.lock`), raw scenario TOML specs, and testbed packaging
files into a hash-stamped `reviewer-bundle-v1` manifest.
Use `celatim bundle verify --manifest bundle-manifest.json` to
re-hash those files and emit a `reviewer-bundle-verify-v1` report; verification also
checks that manifest summaries still match the referenced inputs and follows the
evidence index to check nested evidence, run-log, pcap, and carrier artifacts.
`make public-bundle` copies only public-safe catalog, support-matrix,
detector/scrub-guidance, generated detector rule artifacts, Windows capture guidance,
scenario inventory, execution-plan, testbed-requirements, public evidence-index,
generated-table, and hash-manifest files under
`artifacts/reviewer/public/`; it does not copy evidence JSON, pcap records, run logs,
carrier dumps, or a duplicate of the source code, which is published separately in the
release repository and distributions. The resulting
`public-bundle-manifest.json` validates against `public-bundle-v1` and records the
private reviewer bundle by hash.
`public-bundle-verify.json` re-hashes those public files and checks the public evidence
directory for sensitive classes such as pcap, JSONL run-log, carrier, evidence, or
experiment paths. This evidence-bundle separation is not a source-code embargo.

## Privileged paths

`celatim lab up`, `send --afpacket-ipv4`, and `recv --afpacket-ipv4` require
appropriate Linux capabilities and live interfaces. Use
`doctor --require-testbed-profile netns-afpacket` or
`doctor --require-testbed-profile dns-daemon-netns` before running privileged
scenarios. The repository-level `make reviewer-dns-daemon` target performs the DNS
daemon preflight and lab lifecycle for the EDNS(0) scenario.
The repository-level `make reviewer-afpacket-tcp` target performs the AF_PACKET
preflight and lab lifecycle for the TCP reserved-bit scenario.
The `tcp-reserved-bits` AF_PACKET path is covered by the `netns-afpacket` profile; it
places the carrier in the TCP header's three Reserved bits, not in the L4 payload.
