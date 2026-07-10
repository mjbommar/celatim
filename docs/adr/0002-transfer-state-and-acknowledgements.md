# ADR 0002: Atomic State And Durable Receiver Acknowledgements

## Status

Accepted.

## Context

A sender cannot claim completion merely because it wrote bytes to a local socket. File
transfer also needs secure resume after process or host interruption without publishing
partial destination files or trusting contradictory local state.

## Decision

Each transfer has a versioned manifest and an explicit state machine. Sender and
receiver state are stored under the Celatim home using owner-only directories, atomic
same-directory temporary writes, file synchronization, atomic replacement, and parent
directory synchronization.

The receiver writes chunks into an owner-only spool file at deterministic offsets. It
acknowledges a chunk only after the bytes and updated state have been flushed to durable
storage. Duplicate chunks are idempotent if their digest matches and fail closed if they
differ.

After all chunks arrive, the receiver synchronizes the spool, verifies size and the
whole-file SHA-256 commitment, chooses a policy-compliant destination, atomically moves
the file into place, synchronizes the destination directory, records completion, and
sends an authenticated final acknowledgement over TLS.

The sender reports completion only after receiving that final acknowledgement. Carrier
delivery, chunk acknowledgement, file verification, and final completion remain
separate states.

## Consequences

- Acknowledgement latency includes receiver persistence cost.
- The first implementation favors correctness over maximum throughput; batching may be
  introduced only if crash tests preserve the same durable-acknowledgement invariant.
- Resume state contains sensitive local paths and is `local_private`.
- A unidirectional provider without a real feedback path cannot claim resumability or
  acknowledged completion.
