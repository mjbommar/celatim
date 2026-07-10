"""Class G subliminal channel, for real (Simmons broadband channel in ECDSA).

The signer embeds covert bits in the per-signature nonce k; a cooperating receiver who
shares the signer's private key recovers k from (r, s) and reads the bits. This is host-
local crypto — no network — so it is unambiguous real working code: it round-trips or it
does not. Uses the catalog's codec/framer unchanged.

Usage: python run_subliminal.py [payload]
"""

from __future__ import annotations

import hashlib
import sys

import lab
from ecdsa import NIST256p, SigningKey
from ecdsa.numbertheory import inverse_mod
from ecdsa.util import string_to_number

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for


def main() -> None:
    payload = (sys.argv[1] if len(sys.argv) > 1 else "subliminal!").encode()
    m = next(x for x in load_mechanisms(lab.CATALOG) if x.id == "ecdsa-nonce")
    framer = Framer(codec_for(m))  # VariableLengthCodec(32) -> 256-bit symbols

    sk = SigningKey.generate(curve=NIST256p)
    d = sk.privkey.secret_multiplier  # shared with the cooperating receiver
    n = NIST256p.order
    z = string_to_number(hashlib.sha256(b"any cover message").digest())

    symbols = framer.encode(payload)  # each is 32 bytes of covert data
    recovered = []
    for sym in symbols:
        k = int.from_bytes(sym, "big")
        if not 1 <= k < n:
            raise SystemExit("symbol exceeds curve order; use a shorter payload per signature")
        sig = sk.privkey.sign(z, k)  # k carries the covert bits
        # receiver, knowing d, recovers the nonce: k = s^-1 (z + r*d) mod n
        k_rec = ((z + sig.r * d) * inverse_mod(sig.s, n)) % n
        recovered.append(k_rec.to_bytes(32, "big"))

    out = framer.decode(recovered)
    ok = out == payload
    print(
        f"SUBLIMINAL mechanism=ecdsa-nonce signatures={len(symbols)} "
        f"sent={payload!r} recovered={out!r} {'PASS' if ok else 'FAIL'}"
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
