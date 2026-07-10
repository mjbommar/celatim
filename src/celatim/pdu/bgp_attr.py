"""BGP optional-transitive attribute carrier primitives (build/parse a real UPDATE).

RFC 4271 §5: a router that does not recognize an optional-transitive path attribute
passes it on unchanged, so an unknown optional-transitive attribute is a multi-hop
covert carrier. These build/parse a real BGP UPDATE with scapy's BGP codec; the paired
speaker/peer harness lives in :mod:`celatim.testbed.bgp_message`. scapy is the optional
``packet`` extra, imported lazily, so this module is safe to import without it.
"""

from __future__ import annotations

from typing import Any

BGP_CLAIM_STATUS = "local_scapy_speaker_peer_optional_transitive_attr_path"
_COVERT_ATTR_TYPE = 99  # an unallocated optional-transitive path attribute type code
_FLAG_OPTIONAL = 0x80
_FLAG_TRANSITIVE = 0x40
_FLAG_EXTENDED_LEN = 0x10


def _bgp() -> Any:
    from scapy.contrib.bgp import BGPHeader, BGPPathAttr, BGPUpdate

    return BGPHeader, BGPUpdate, BGPPathAttr


def build_bgp_update(value: bytes) -> bytes:
    """Speaker role: build a real BGP UPDATE carrying ``value`` in an unknown attribute."""

    header, update, path_attr = _bgp()
    flags = _FLAG_OPTIONAL | _FLAG_TRANSITIVE
    if len(value) > 0xFF:
        flags |= _FLAG_EXTENDED_LEN
    attr = path_attr(type_flags=flags, type_code=_COVERT_ATTR_TYPE, attribute=value)
    return bytes(header(type=2) / update(path_attr=[attr]))


def parse_bgp_update(wire: bytes) -> bytes:
    """Peer role / independent validator: recover the covert attribute value from a UPDATE."""

    header, update, _ = _bgp()
    message = header(wire)
    attributes = message[update].path_attr
    for attr in attributes:
        if int(attr.type_code) == _COVERT_ATTR_TYPE:
            return bytes(attr.attribute)
    raise ValueError("covert optional-transitive attribute not found in BGP UPDATE")


__all__ = [
    "BGP_CLAIM_STATUS",
    "build_bgp_update",
    "parse_bgp_update",
]
