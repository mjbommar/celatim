"""Negative-result contrast cases: fields that are NOT usable covert channels, shown
with running code rather than asserted.

The catalog marks four mechanisms `negative_result` — the field is cryptographically
protected (integrity-covered, signed, or encrypted), so using it as a storage channel is
either rejected by the receiver or unrecoverable. This harness demonstrates each with the
real primitive and a positive control: the *unmodified* message passes, the *covert*
message fails. A mechanism "passes as a negative" iff control-verifies AND covert-fails.

  ah-reserved-external-neg : AH ICV covers the field (HMAC-SHA256). Covert -> ICV mismatch.
  oscore-reserved-neg      : OSCORE AEAD tag covers the field (HMAC stands in for the AEAD
                             integrity tag). Covert -> tag mismatch -> AEAD reject.
  bgpsec-signed-neg        : BGPsec signs the attribute (real ECDSA P-256). Covert ->
                             signature verification fails.
  quic-hdr-protected-neg   : QUIC header protection masks the bits with a key-derived
                             keystream. A receiver without the HP key recovers field^mask,
                             not the covert value -> unrecoverable.

Usage: python run_negatives.py
"""

from __future__ import annotations

import hashlib
import hmac
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def integrity_negative(key: bytes) -> tuple[bool, bool]:
    """A field covered by a MAC: control (field=0) verifies; covert (field set) is rejected."""
    header = bytearray(16)  # protocol header incl. the reserved field at byte 1
    icv = hmac.new(key, bytes(header), hashlib.sha256).digest()  # sender signs field=0
    control_ok = hmac.compare_digest(icv, hmac.new(key, bytes(header), hashlib.sha256).digest())
    header[1] = 0xAB  # embed covert bits in the covered field
    covert_icv = hmac.new(key, bytes(header), hashlib.sha256).digest()
    covert_rejected = not hmac.compare_digest(icv, covert_icv)
    return control_ok, covert_rejected


def signature_negative() -> tuple[bool, bool]:
    """A signed attribute (real ECDSA): control verifies; covert breaks the signature."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    msg0 = bytes(16)
    signature = private_key.sign(msg0, ec.ECDSA(hashes.SHA256()))
    public_key.verify(signature, msg0, ec.ECDSA(hashes.SHA256()))
    control_ok = True
    covert = b"\x00\xab" + bytes(14)
    try:
        public_key.verify(signature, covert, ec.ECDSA(hashes.SHA256()))
        covert_rejected = False
    except InvalidSignature:
        covert_rejected = True
    return control_ok, covert_rejected


def encryption_negative() -> tuple[bool, bool]:
    """Header-protected bits: the cooperating (keyed) receiver recovers them; a receiver
    WITHOUT the HP key recovers field^keystream, i.e. not the covert value."""
    hp_key = b"header-protection-key"
    keystream = hmac.new(hp_key, b"packet-number-sample", hashlib.sha256).digest()[0]
    covert = 0xAB
    on_wire = covert ^ keystream  # sender applies header protection
    keyed_ok = (on_wire ^ keystream) == covert  # control: keyed receiver recovers it
    keyless_fails = on_wire != covert  # an unwitting/keyless receiver cannot recover it
    return keyed_ok, keyless_fails


def main() -> None:
    results = {
        "ah-reserved-external-neg": integrity_negative(b"ah-integrity-key"),
        "oscore-reserved-neg": integrity_negative(b"oscore-aead-key"),
        "bgpsec-signed-neg": signature_negative(),
        "quic-hdr-protected-neg": encryption_negative(),
    }
    all_ok = True
    print("=== NEGATIVE-RESULT CONTRAST CASES (real primitives; not usable channels) ===")
    for mid, (control_ok, covert_fails) in results.items():
        ok = control_ok and covert_fails  # control passes AND covert is rejected/unrecoverable
        all_ok = all_ok and ok
        print(
            f"  {'CONFIRMED-NEG' if ok else 'UNEXPECTED':14} {mid}  "
            f"control_verifies={control_ok} covert_rejected={covert_fails}"
        )
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
