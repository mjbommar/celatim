"""CoAP elective-option carrier primitives (build/parse a real CoAP message).

An unknown elective option is ignored by a receiver that does not understand it under
RFC 7252. These helpers use option 65000, an even-numbered experimental-use option,
through aiocoap's opaque-option codec, so the measured bytes occupy an option rather
than ordinary message payload. The paired client/server harness lives in
:mod:`celatim.testbed.coap_message`. aiocoap is the optional ``iot`` extra, imported
lazily, so this module is safe to import without it.

aiocoap deprecates manually setting the message id (its network ``Context`` manages it),
but a deliberate wire-codec round-trip must set one, so that specific warning is
suppressed locally.
"""

from __future__ import annotations

import warnings
from typing import Any

COAP_CLAIM_STATUS = "local_aiocoap_client_server_elective_option_path"
_COAP_MID = 0x4242
_COAP_ELECTIVE_OPTION_NUMBER = 65000


def _aiocoap() -> Any:
    import aiocoap
    from aiocoap.numbers.types import Type

    return aiocoap, Type


def build_coap_message(payload: bytes) -> bytes:
    """Build a CoAP message carrying bytes in experimental elective option 65000."""

    aiocoap, type_enum = _aiocoap()
    from aiocoap.optiontypes import OpaqueOption

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        message = aiocoap.Message(
            code=aiocoap.Code.POST,
            payload=b"",
            mid=_COAP_MID,
            token=b"ct",
        )
        message.mtype = type_enum.CON
        message.opt.add_option(OpaqueOption(_COAP_ELECTIVE_OPTION_NUMBER, payload))
        return bytes(message.encode())


def parse_coap_message(wire: bytes) -> bytes:
    """Recover bytes from the unknown elective option in CoAP wire bytes."""

    aiocoap, _ = _aiocoap()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        message = aiocoap.Message.decode(wire)
        options = message.opt.get_option(_COAP_ELECTIVE_OPTION_NUMBER)
        if len(options) != 1:
            raise ValueError("CoAP elective carrier option is missing or duplicated")
        return bytes(options[0].value)


__all__ = [
    "COAP_CLAIM_STATUS",
    "build_coap_message",
    "parse_coap_message",
]
