# Celatim 0.2.8

Celatim 0.2.8 corrects the SSH KEXINIT carrier bound and adds production OpenSSH
daemon evidence.

## Corrected semantics

- `ssh-kexinit-cookie` now exposes only the 16-byte random cookie as carrier space
  (128 bits per key exchange).
- The trailing RFC 4253 `uint32 0 (reserved for future extension)` is always encoded
  as zero and rejected by the parser when nonzero.
- The existing in-process Paramiko message build/parse scenario is classified as a
  real-PDU path, not a daemon path.

## Production-daemon path

- `ssh_kexinit_openssh` substitutes the 16-byte client cookie before Paramiko packet
  framing and completes the cryptographic key exchange with a production OpenSSH
  daemon.
- Transcripts record the emitted KEXINIT payload hash, zero reserved word, OpenSSH
  version, negotiated ciphers, host-key type and hash, elapsed time, and whether every
  key exchange completed.
- `ssh-kexinit-openssh-real-daemon` provides the corresponding explicit reviewer
  scenario for a reachable OpenSSH server.
