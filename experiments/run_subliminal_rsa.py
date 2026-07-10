"""Class G subliminal channel #2: the RSA-PSS salt (RFC 8017 EMSA-PSS).

Unlike the ECDSA nonce channel (which needs the signer's *private* key to recover), the
PSS salt is extracted by *any verifier* during normal signature verification: it falls
out of EMSA-PSS-VERIFY. So a signer who chooses the salt instead of randomizing it emits
a broadcast subliminal channel readable by every holder of the public key.

This is real working code, host-local, stdlib only: pure-Python RSA keygen + a full RSA
signature (s = EM^d mod n), then real PSS salt recovery from EM' = s^e mod n. It
round-trips or it fails; there is no model.

  COVERT  : salt = the covert symbol -> verifier recovers the payload.
  CONTROL : salt = os.urandom (an honest signer) -> verifier recovers random bytes, NOT
            the payload. Proves the channel is the *chosen* salt, not PSS itself.

Usage: python run_subliminal_rsa.py [payload]
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sys

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

HLEN = 32  # SHA-256


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += _h(seed + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def pss_encode(mhash: bytes, salt: bytes, em_bits: int) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 §9.1.1)."""
    em_len = (em_bits + 7) // 8
    slen = len(salt)
    if em_len < HLEN + slen + 2:
        raise ValueError("encoding error: modulus too small for salt")
    mprime = b"\x00" * 8 + mhash + salt
    h = _h(mprime)
    ps = b"\x00" * (em_len - slen - HLEN - 2)
    db = ps + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, _mgf1(h, em_len - HLEN - 1), strict=True))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)  # zero the leftmost unused bits
    return bytes(masked) + h + b"\xbc"


def pss_recover_salt(mhash: bytes, em: bytes, em_bits: int, slen: int) -> bytes:
    """The salt-recovery half of EMSA-PSS-VERIFY (RFC 8017 §9.1.2)."""
    em_len = (em_bits + 7) // 8
    if em[-1] != 0xBC:
        raise ValueError("inconsistent: bad trailer")
    masked = em[: em_len - HLEN - 1]
    h = em[em_len - HLEN - 1 : -1]
    db = bytearray(a ^ b for a, b in zip(masked, _mgf1(h, em_len - HLEN - 1), strict=True))
    db[0] &= 0xFF >> (8 * em_len - em_bits)
    salt = bytes(db[-slen:])
    if _h(b"\x00" * 8 + mhash + salt) != h:  # the real verification step
        raise ValueError("inconsistent: H mismatch")
    return salt


def _is_prime(n: int, k: int = 40) -> bool:
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        if all(pow(x, 2 << i, n) != n - 1 for i in range(r - 1)):
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


def keygen(bits: int = 1024) -> tuple[int, int, int]:
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        return p * q, e, pow(e, -1, phi)


def main() -> None:
    payload = (sys.argv[1] if len(sys.argv) > 1 else "subliminal-rsa").encode()
    m = next(x for x in load_mechanisms(lab.CATALOG) if x.id == "rsa-pss-salt")
    framer = Framer(codec_for(m))  # VariableLengthCodec(32) -> 32-byte salts

    n, e, d = keygen(1024)
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    mhash = _h(b"any cover document")

    def sign_recover(salt: bytes) -> bytes:
        em = pss_encode(mhash, salt, em_bits)
        sig = pow(int.from_bytes(em, "big"), d, n)  # real RSA signature
        em2 = pow(sig, e, n).to_bytes(em_len, "big")  # verifier: s^e mod n
        return pss_recover_salt(mhash, em2, em_bits, len(salt))

    salts = framer.encode(payload)  # each 32-byte symbol becomes one signature's salt
    recovered = framer.decode([sign_recover(s) for s in salts])
    ok_covert = recovered == payload

    # control: an honest signer randomizes the salt -> the verifier recovers noise
    control = framer.decode([sign_recover(os.urandom(len(s))) for s in salts])
    ok_control = control != payload

    print(
        f"SUBLIMINAL mechanism=rsa-pss-salt modbits={n.bit_length()} signatures={len(salts)} "
        f"sent={payload!r} recovered={recovered!r} control={control!r} "
        f"{'PASS' if (ok_covert and ok_control) else 'FAIL'}"
    )
    sys.exit(0 if (ok_covert and ok_control) else 1)


if __name__ == "__main__":
    main()
