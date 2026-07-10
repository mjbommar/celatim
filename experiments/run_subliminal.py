"""Class G subliminal channel, for real (Simmons broadband channel in ECDSA).

The signer embeds covert bits in the per-signature nonce k; a cooperating receiver who
shares the signer's private key recovers k from (r, s) and reads the bits. This is host-
local crypto — no network — so it is unambiguous real working code: it round-trips or it
does not. Uses the catalog's codec/framer unchanged.

Usage: python run_subliminal.py [payload]
"""

from __future__ import annotations

import sys

import lab

from celatim.crypto_transcript import EcdsaNonceTranscriptTransport
from celatim.session import ChannelSession, MechanismProfile


def main() -> None:
    payload = (sys.argv[1] if len(sys.argv) > 1 else "subliminal!").encode()
    profile = MechanismProfile.from_catalog("ecdsa-nonce", lab.CATALOG)
    result = ChannelSession(profile, EcdsaNonceTranscriptTransport(profile)).run_roundtrip(
        payload,
        session_id="standalone-subliminal",
    )
    ok = result.payload == payload
    print(
        f"SUBLIMINAL mechanism=ecdsa-nonce signatures={result.evidence.carrier_units} "
        f"sent={payload!r} recovered={result.payload!r} {'PASS' if ok else 'FAIL'}"
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
