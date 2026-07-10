"""CoAP payload-tunnel carrier primitives (build/parse a real CoAP message).

A CoAP message payload (RFC 7252) is arbitrary application data, so covert bytes are
conforming. These build/parse the message with aiocoap's own wire codec; the paired
client/server harness lives in :mod:`celatim.testbed.coap_message`. aiocoap is the
optional ``iot`` extra, imported lazily, so this module is safe to import without it.

aiocoap deprecates manually setting the message id (its network ``Context`` manages it),
but a deliberate wire-codec round-trip must set one, so that specific warning is
suppressed locally.
"""

from __future__ import annotations

import warnings
from typing import Any

COAP_CLAIM_STATUS = "local_aiocoap_client_server_payload_message_path"
_COAP_MID = 0x4242


def _aiocoap() -> Any:
    import aiocoap
    from aiocoap.numbers.types import Type

    return aiocoap, Type


def build_coap_message(payload: bytes) -> bytes:
    """Client role: build a real CoAP CONTENT message carrying ``payload``; return wire bytes."""

    aiocoap, type_enum = _aiocoap()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        message = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=payload, mid=_COAP_MID)
        message.mtype = type_enum.NON
        return bytes(message.encode())


def parse_coap_message(wire: bytes) -> bytes:
    """Server role / independent validator: recover the covert payload from CoAP wire bytes."""

    aiocoap, _ = _aiocoap()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return bytes(aiocoap.Message.decode(wire).payload)


__all__ = [
    "COAP_CLAIM_STATUS",
    "build_coap_message",
    "parse_coap_message",
]
