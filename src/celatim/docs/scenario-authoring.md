# Scenario Authoring Guide

Scenario specs make reviewer runs data-driven. The current format is TOML with
`schema_version = "celatim.scenario.v1"`. The checked JSON Schema is available with:

```bash
celatim schema show --name scenario-v1
```

## Minimal scenario

```toml
schema_version = "celatim.scenario.v1"
scenario_id = "http2-ping-opaque-real-pdu-smoke"
mechanism_id = "http2-ping-opaque"
description = "Non-privileged HTTP/2 PING smoke scenario."
evidence_tier = "real_pdu_packet_path"
privilege = "none"
expected_runtime_s = 5.0
requires_tools = []
requires_extras = []
payload_hex = "00 ff 80 41"
control_message = "control"
log_dir = "artifacts/logs"

[transport]
kind = "pcap"
root = "artifacts/pcaps"
```

Payloads may be set as text, hex, or a binary file path. Control payloads use the same
forms. Keep controls explicit: a benign control should fail under wrong offsets,
all-zero carrier shortcuts, or self-consistent decoder bugs.

Use metadata fields to make reviewer bundles auditable before execution:
`evidence_tier` names the expected evidence class, `privilege` states the highest
privilege requirement, `expected_runtime_s` gives the per-scenario runtime budget, and
`requires_tools` / `requires_extras` list external commands and Python extras needed by
that scenario. `scenario list` surfaces these fields in JSON, `scenario plan` turns
them into a reviewer execution plan, and `doctor` treats declared tools/extras as
required preflight checks for the selected scenario set.

`run_id` may be set by a CLI override for deterministic artifact names. If `log_dir`
is set, each run writes a JSONL run log and records it as `run_log` in the evidence
JSON. If `artifact_dir` is set and `log_dir` is not, logs are written under
`artifact_dir/run-logs`.

## Transport kinds

- `memory`: local in-process regression path.
- `file`: JSON carrier records under `root`.
- `pcap`: classic Ethernet/IPv4 pcap records under `root`; requires parser-visible
  carrier bytes and supports external tcpdump inspection for stateless TCP fields.
- `timed_memory`: local timing smoke path with per-symbol timestamp evidence.
- `afpacket_ipv4`: privileged Ethernet/IPv4 packet path for live netns or interface
  runs. Parser-visible payload carriers are wrapped as TCP or UDP payload bytes; the
  `tcp-reserved-bits` adapter uses a header-field path that writes and recovers the
  TCP header's three Reserved bits instead of payload bytes.
- `dns_edns0_padding`: privileged EDNS(0) Padding path using real `dig`, `dnsmasq`,
  netns, and tcpdump capture.
- `crypto_ecdsa_nonce`: non-privileged local ECDSA signing/verification transcript for
  the `ecdsa-nonce` Class G mechanism. It writes a sensitive JSON transcript artifact
  when `transcript_json` is set. It creates an ephemeral key for each transcript;
  explicit nonce construction is research-only and must not be used with production
  or long-lived signing keys.
- `crypto_rsa_pss_salt`: non-privileged local RSA-PSS signing/verification transcript
  for the `rsa-pss-salt` Class G mechanism. It writes a sensitive JSON transcript
  artifact when `transcript_json` is set.

`afpacket_ipv4` scenarios can configure sender and receiver interfaces, MAC addresses,
IP addresses, ports, protocol, timeout, expected frame count, and optional live
`tcpdump` capture settings.
`dns_edns0_padding` scenarios configure sender/resolver namespaces, sender/resolver
IP addresses, query name, answer address, EDNS option code, dig timeout/tries, and
the tcpdump capture path/filter. Scenarios that need tools, extras, or privileges are
listed in `scenario plan` but excluded from the default non-privileged run.
`crypto_ecdsa_nonce` scenarios configure `transcript_json`, `curve`, `hash_name`,
`nonce_payload_bits`, `honest_random_control_signatures`, and `message_prefix`. Use
`--transport-transcript-json` to override transcript placement from the CLI.
`crypto_rsa_pss_salt` scenarios configure `transcript_json`, `key_bits`,
`public_exponent`, `hash_name`, `mgf_hash_name`, `salt_payload_bits`,
`honest_random_control_signatures`, and `message_prefix`. The same
`--transport-transcript-json` override applies.

## Pacing and reliability

Use `[pacing]` for caller-visible rate and timing controls:

```toml
[pacing]
unit_rate_hz = 20.0
timing_quantum_s = 0.005
decode_tolerance_s = 0.002
timeout_s = 2.0
```

Use `[reliability]` for receive attempts and duplicate handling:

```toml
[reliability]
max_receive_attempts = 3
retry_backoff_s = 0.1
suppress_duplicate_chunks = true
max_retransmissions = 1
```

## Preflight and execution

```bash
celatim doctor --scenario-dir scenarios --artifact-dir artifacts/reviewer/doctor
celatim scenario list --scenario-dir scenarios
celatim scenario plan --scenario-dir scenarios
celatim scenario run --scenario scenarios/http2-ping-opaque.toml --output out/evidence.json
celatim scenario run --scenario scenarios/http2-ping-opaque.toml --file payload.bin --output out/evidence.json
celatim scenario run --scenario-id ecdsa-nonce-local-crypto-transcript --transport-transcript-json out/transcripts/{scenario_id}-{case}.json --output out/ecdsa-evidence.json
celatim scenario run --scenario-id rsa-pss-salt-local-crypto-transcript --transport-transcript-json out/transcripts/{scenario_id}-{case}.json --output out/rsa-pss-evidence.json
```

`scenario run` accepts `--message`, `--hex`, or `--file` to replace the scenario's
covert payload without changing its benign control or checked-in specification. Use an
explicit override for payload-size sweeps and retain the invocation recorded in the
evidence document.

Unknown top-level keys or malformed transport knobs fail schema validation in
`doctor`, before a reviewer run starts.
