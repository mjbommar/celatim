"""Scapy field-name carriers: set the covert value in a *named* protocol field.

Some catalog locators are coarse (they point at a protocol boundary rather than the
precise reserved field), so placing covert bits at the raw byte offset would land in
the wrong field. For these, the rigorous carrier sets the value in the real field *by
name* via Scapy's field API (e.g. ``MPLS(cos=...)``), then recovers it by reading the
same named field after an independent dissect. Locator precision becomes irrelevant.

Scapy is the optional ``packet`` extra, imported lazily; ``supports`` is a static,
Scapy-free function of the registry so the generated matrix stays deterministic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class _FieldCarrier:
    """How to build/parse a real PDU carrying the covert value in a named field."""

    build: Callable[[Any, int], Any]  # (scapy_ns, value) -> full scapy packet
    base_layer: str  # attribute name of the carrier (and dissect) layer in the namespace
    field: str  # the named field that carries the covert value
    bit_width: int


def _scapy() -> Any:
    from types import SimpleNamespace

    from scapy.contrib.mpls import MPLS
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    return SimpleNamespace(Ether=Ether, IP=IP, MPLS=MPLS)


def _registry() -> dict[str, _FieldCarrier]:
    return {
        # MPLS EXP/TC ("cos") bits live at label-entry bits 20-22; the catalog locator is
        # coarse (offset 0), so we set the real `cos` field by name.
        "mpls-exp-tc": _FieldCarrier(
            build=lambda s, v: (
                s.Ether(type=0x8847)
                / s.MPLS(label=42, cos=v, s=1, ttl=64)
                / s.IP(src="10.0.0.1", dst="10.0.0.2")
            ),
            base_layer="MPLS",
            field="cos",
            bit_width=3,
        ),
    }


_FIELD_CARRIER_IDS = frozenset(_registry())


def supports(mechanism_id: str) -> bool:
    """True if a named-field Scapy carrier is registered for this mechanism."""

    return mechanism_id in _FIELD_CARRIER_IDS


def build_field_pdu(mechanism_id: str, value: int) -> bytes:
    """Build a real PDU carrying ``value`` in the registered named field; return base bytes."""

    s = _scapy()
    spec = _registry()[mechanism_id]
    if value < 0 or value >= (1 << spec.bit_width):
        raise ValueError(f"{mechanism_id}: value does not fit in {spec.bit_width} bits")
    frame = spec.build(s, value)
    return bytes(frame[getattr(s, spec.base_layer)])


def extract_field_value(mechanism_id: str, carrier: bytes) -> int:
    """Independently dissect the carrier and read the covert value from the named field."""

    s = _scapy()
    spec = _registry()[mechanism_id]
    layer = getattr(s, spec.base_layer)(carrier)
    if not layer.haslayer(getattr(s, spec.base_layer)):
        raise ValueError(f"{mechanism_id}: carrier did not dissect as {spec.base_layer}")
    return int(getattr(layer, spec.field))


__all__ = [
    "build_field_pdu",
    "extract_field_value",
    "supports",
]
