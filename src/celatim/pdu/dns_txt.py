"""DNS TXT-tunnel carrier primitives (build/parse real DNS wire bytes).

A TXT record's character-strings carry arbitrary bytes by spec (RFC 1035 §3.3.14),
so answering with covert bytes is standards-conforming. These build/parse a real DNS
message with dnspython; the paired client/server exchange harness lives in
:mod:`celatim.testbed.dns_message`. dnspython is the optional ``dns`` extra, imported
lazily, so this module is safe to import without it.
"""

from __future__ import annotations

from typing import Any

from ..errors import TransportError

DNS_TXT_CLAIM_STATUS = "local_dnspython_client_server_txt_message_path"
_TXT_STRING_MAX = 255  # one TXT character-string is length-prefixed by a single byte


def _dns() -> Any:
    """Return the dnspython modules used here, raising clearly if the extra is absent."""

    import dns.message
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset
    from dns.rdtypes.ANY.TXT import TXT

    return dns, TXT


def _txt_strings(covert: bytes) -> list[bytes]:
    if not covert:
        return [b""]
    return [covert[i : i + _TXT_STRING_MAX] for i in range(0, len(covert), _TXT_STRING_MAX)]


def build_txt_response(qname: str, covert: bytes) -> bytes:
    """Server role: build a real DNS TXT response carrying ``covert`` and return wire bytes."""

    dns, txt_cls = _dns()
    name = dns.name.from_text(qname)
    rdata = txt_cls(dns.rdataclass.IN, dns.rdatatype.TXT, _txt_strings(covert))
    query = dns.message.make_query(name, dns.rdatatype.TXT)
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_rdata(name, 0, rdata))
    return bytes(response.to_wire())


def parse_txt_response(wire: bytes) -> bytes:
    """Client role / independent validator: recover covert TXT bytes from wire."""

    dns, _ = _dns()
    message = dns.message.from_wire(wire)
    for rrset in message.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            return b"".join(rrset[0].strings)
    raise TransportError("no TXT answer found in DNS response")


def build_null_response(qname: str, covert: bytes) -> bytes:
    """Server role: build a real DNS NULL (RR type 10) response carrying ``covert``.

    A NULL record's RDATA is "anything at all" (RFC 1035 §3.3.10), so arbitrary bytes
    are conforming.
    """

    import dns.message
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset

    name = dns.name.from_text(qname)
    rdata = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.NULL, covert, 0, len(covert))
    query = dns.message.make_query(name, dns.rdatatype.NULL)
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_rdata(name, 0, rdata))
    return bytes(response.to_wire())


def parse_null_response(wire: bytes) -> bytes:
    """Client role / independent validator: recover covert NULL RDATA bytes from wire."""

    dns, _ = _dns()
    message = dns.message.from_wire(wire)
    for rrset in message.answer:
        if rrset.rdtype == dns.rdatatype.NULL:
            return bytes(rrset[0].data)
    raise TransportError("no NULL answer found in DNS response")


def build_caa_flags_response(qname: str, flags: int) -> bytes:
    """Server role: build a real DNS CAA response whose flags byte carries ``flags``.

    dnspython sets the *actual* CAA flags field by name (RFC 8659), so this places the
    covert value in the real protocol field rather than at a guessed byte offset.
    """

    import dns.message
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset
    from dns.rdtypes.ANY.CAA import CAA

    name = dns.name.from_text(qname)
    rdata = CAA(dns.rdataclass.IN, dns.rdatatype.CAA, flags & 0xFF, b"issue", b"ca.example.org")
    query = dns.message.make_query(name, dns.rdatatype.CAA)
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_rdata(name, 0, rdata))
    return bytes(response.to_wire())


def parse_caa_flags(wire: bytes) -> int:
    """Client role / independent validator: recover the real CAA flags field from wire."""

    dns, _ = _dns()
    message = dns.message.from_wire(wire)
    for rrset in message.answer:
        if rrset.rdtype == dns.rdatatype.CAA:
            return int(rrset[0].flags)
    raise TransportError("no CAA answer found in DNS response")


__all__ = [
    "DNS_TXT_CLAIM_STATUS",
    "build_caa_flags_response",
    "build_null_response",
    "build_txt_response",
    "parse_caa_flags",
    "parse_null_response",
    "parse_txt_response",
]
