# Troubleshooting

## A command cannot find the catalog or scenarios

By default, CLI commands load packaged resources. If you want checkout files, pass
explicit paths:

```bash
celatim --catalog data/mechanisms.jsonl scenario list --scenario-dir scenarios
```

Use `celatim doctor --scenario-dir scenarios` to validate local scenario
files against the packaged schema.

The doctor report also includes an `environment` check with the installed package
version, Python version, executable path, platform, kernel release, and machine type.
Compare that block with an evidence run's `reproducibility` block when a result differs
across hosts.

## Scenario validation fails

Run:

```bash
celatim schema show --name scenario-v1
celatim doctor --scenario-dir scenarios --output out/doctor.json
```

The doctor report lists the file path and validation error. Unknown keys are treated as
drift, not ignored.

## Evidence run failed but the JSON was still written

Check the top-level `run_id` and `run_log` fields. When `--log-dir` is set, or when
`--artifact-dir` is set and `--log-dir` is omitted, the run log is a JSONL file with a
`run_started` event, one `case_finished` event for each case, and a `run_finished`
event. The `case_finished` records include transport kind, parser-validation status,
elapsed time, and any structured error string.

## Pcap transport fails

`PcapTransport` only works for mechanisms whose adapter can build parser-visible
carrier bytes. If the mechanism is only codec-only or offset-represented, use
`--transport-dir` for local endpoint tests or upgrade the adapter to a real/minimal PDU
fixture before claiming pcap evidence.

## AF_PACKET or lab commands fail

`celatim lab up` and `--afpacket-ipv4` need Linux capabilities such as
`CAP_NET_ADMIN` and raw packet access. Check tools first:

```bash
celatim doctor --require-tool ip --require-tool ethtool --require-tool tcpdump
celatim doctor --require-testbed-profile netns-afpacket
celatim testbed requirements
```

For known tools such as `ip`, `tcpdump`, `ethtool`, `dig`, `dnsmasq`, `docker`,
`tshark`, and `qemu-system-x86_64`, the doctor report includes the binary path and
captured version-command output. Testbed profiles also make required Linux
capabilities, Docker access, or `/dev/kvm` access explicit before a privileged run
starts.

If captures are empty, verify namespace names, interface names, BPF filter, expected
frame count, MTU, and offload settings. Veth offloads should normally be disabled.

## QEMU cross-stack preflight fails

The QEMU/TAP helpers are packaged for manual or nightly cross-stack scenarios, but no
default VM image ships with the public reviewer bundle. Check the host profile first:

```bash
celatim doctor --require-testbed-profile qemu-cross-stack
```

`QemuTapVm` needs permission to create host TAP devices and access `/dev/kvm` when KVM
acceleration is enabled. `HostTcpdumpCapture` captures on the host TAP interface, so
verify the TAP name, pcap output directory, and BPF filter separately from any guest
boot issue.

## Optional Python extras are missing

The core package intentionally has no Python runtime dependencies. Packet and crypto
experiment paths use install extras:

```bash
uv sync --extra packet --extra crypto
celatim doctor --optional-extra packet --optional-extra crypto
```

Use `--require-extra packet` or `--require-extra crypto` when a scenario set depends on
those modules and should fail preflight if they are unavailable.

## Timing evidence looks too good

Local `timed_memory` evidence is a scheme demonstration. It records pacing and timing
metadata, but it is not a production-path capacity measurement. Netns or daemon timing
claims need a measured noise floor, jitter distribution, SNR, symbol-error rate, and
goodput label.
`celatim timing sweep` records the local baseline/noise-floor and quantum
sweep in a checked `timing-sweep-v1` schema, including payload-error rate and a local
capacity-model upper bound. The report is still labeled
`local_timed_memory_scheme_demonstration_not_capacity` until the same sweep runs on a
production transport.

## Storage throughput is null

Current storage-channel packet paths are sender-bound demonstrations, not production
throughput measurements. Evidence therefore sets `throughput_profile.claim_status` to
`sender_bound_no_bits_per_second_claim` and keeps `payload_rate_bps` null until a
batched, compiled, or daemon-backed sender records a real measurement window.

## Type checks include experiment scripts

The default `uv run ty check` gate covers the reusable package and tests. Legacy
experiment scripts keep optional Scapy/ECDSA dependencies and are excluded from the
library type gate until those paths are extracted into optional extras.
