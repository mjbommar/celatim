# File-Transfer Operations

## State and files

Transfer state defaults to `$XDG_DATA_HOME/celatim` or
`~/.local/share/celatim`. State, offer, identity, and spool directories are mode 0700;
private files are mode 0600. `celatim transfer status` redacts source paths,
destination paths, access tokens, and provider secrets.

Bob should place `--output-dir` on the filesystem that will hold the final file. Celatim
writes a hidden destination-local spool, synchronizes each acknowledged chunk,
verifies the complete SHA-256 digest, links it to an unused destination name, syncs the
directory, and removes the spool. The default collision policy is `fail`; `rename`
selects an unused numbered name.

## Recovery

- `network_failed`, `timeout`, `storage_failed`, and `cancelled` may be resumable when
  the structured error says so.
- Run `celatim transfer status` on both peers before recovery.
- Resume on Alice with `celatim transfer resume TRANSFER_ID`. The receiver must be
  listening with the original home, TLS identity, offer state, and port.
- Never edit state JSON manually. A changed source, manifest, offer, provider key, or
  destination state is rejected.
- A `quarantined` receiver spool failed whole-file integrity and must not be promoted.

## Packet service

Generate, inspect, and install a unit explicitly:

```console
celatim transfer packet-service unit \
  --socket /run/user/1000/celatim-packet.sock \
  --allow-provider afpacket-carrier \
  --allow-interface eth0 \
  --allow-uid 1000 \
  --user celatim-packet \
  --executable /usr/bin/celatim
```

The generated service has `CAP_NET_RAW` but no file, key, encryption, manifest, or
destination responsibilities. Keep provider and interface allowlists narrow. The
application CLI and SDK remain unprivileged.

## Diagnostics and cleanup

Use `--format json` for receipts and status or `--format jsonl` for ordered events.
Default output excludes payloads, keys, raw carrier frames, pcaps, and full private
paths. Preserve redacted errors and version information for support. Remove abandoned
spools only after confirming that neither peer will resume the transfer.
