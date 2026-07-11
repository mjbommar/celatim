"""Generic paired message-carrier transport for real-codec covert channels.

Several covert channels share one shape: a client/speaker builds a real protocol
message carrying the covert symbol with a real library's wire codec, and a
server/peer re-parses it with the same codec as the independent validator. Rather
than a bespoke ``Transport`` and ``scenario.py`` dispatch branch per protocol, this
registers each ``(build, parse)`` pair under its transport kind and exposes one
:class:`MessageCarrierTransport` that plugs into ``ChannelSession``. Scenarios and the
``celatim`` CLI drive every registered protocol through the same path.

All carrier libraries are optional extras imported lazily inside the build/parse
primitives, so importing this module never requires them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..pdu.bgp_attr import build_bgp_update, parse_bgp_update
from ..pdu.coap_msg import build_coap_message, parse_coap_message
from ..pdu.dns_txt import (
    build_null_response,
    build_txt_response,
    parse_null_response,
    parse_txt_response,
)
from ..pdu.ssh_kex import build_kexinit, parse_kexinit
from ..pdu.ws_frame import build_ws_frame, parse_ws_frame


@dataclass(frozen=True)
class MessageCarrierSpec:
    """How one protocol builds/parses a covert message and labels its roles."""

    build: Callable[[bytes, str], bytes]  # (symbol, qname) -> wire; qname used only by DNS
    parse: Callable[[bytes], bytes]
    claim_status: str
    client_role: str
    server_role: str
    independent_validator: str
    endpoint_note: str
    required_extra: str


def _ignore_qname(build_no_qname: Callable[[bytes], bytes]) -> Callable[[bytes, str], bytes]:
    return lambda symbol, _qname: build_no_qname(symbol)


MESSAGE_CARRIER_KINDS: dict[str, MessageCarrierSpec] = {
    "dns_txt_dnspython": MessageCarrierSpec(
        build=lambda symbol, qname: build_txt_response(qname, symbol),
        parse=parse_txt_response,
        claim_status="local_dnspython_client_server_txt_message_path",
        client_role="dns.message.make_query",
        server_role="dns.message.make_response",
        independent_validator="dnspython_from_wire",
        endpoint_note=(
            "server builds a real DNS TXT response and the client re-parses it with "
            "dnspython in one Python process"
        ),
        required_extra="dns",
    ),
    "dns_null_dnspython": MessageCarrierSpec(
        build=lambda symbol, qname: build_null_response(qname, symbol),
        parse=parse_null_response,
        claim_status="local_dnspython_client_server_null_message_path",
        client_role="dns.message.make_query",
        server_role="dns.message.make_response",
        independent_validator="dnspython_from_wire",
        endpoint_note=(
            "server builds a real DNS NULL response and the client re-parses it with "
            "dnspython in one Python process"
        ),
        required_extra="dns",
    ),
    "ssh_kexinit_paramiko": MessageCarrierSpec(
        build=_ignore_qname(build_kexinit),
        parse=parse_kexinit,
        claim_status="local_paramiko_client_server_kexinit_message_path",
        client_role="paramiko.Message(KEXINIT)",
        server_role="paramiko.Message.parse",
        independent_validator="paramiko_message_codec",
        endpoint_note=(
            "client builds a real SSH_MSG_KEXINIT and the server re-parses it with the "
            "paramiko Message codec in one Python process"
        ),
        required_extra="ssh",
    ),
    "coap_aiocoap": MessageCarrierSpec(
        build=_ignore_qname(build_coap_message),
        parse=parse_coap_message,
        claim_status="local_aiocoap_client_server_elective_option_path",
        client_role="aiocoap.Message.encode",
        server_role="aiocoap.Message.decode",
        independent_validator="aiocoap_message_codec",
        endpoint_note=(
            "client encodes a real CoAP message and the server decodes it with the "
            "aiocoap codec in one Python process"
        ),
        required_extra="iot",
    ),
    "websocket_websockets": MessageCarrierSpec(
        build=_ignore_qname(build_ws_frame),
        parse=parse_ws_frame,
        claim_status="local_websockets_client_server_frame_path",
        client_role="websockets.Frame.serialize(mask=True)",
        server_role="websockets.Frame.parse",
        independent_validator="websockets_frame_codec",
        endpoint_note=(
            "client serializes a real client-masked WebSocket frame and the server "
            "parses it with the websockets codec in one Python process"
        ),
        required_extra="realtime",
    ),
    "bgp_scapy": MessageCarrierSpec(
        build=_ignore_qname(build_bgp_update),
        parse=parse_bgp_update,
        claim_status="local_scapy_speaker_peer_optional_transitive_attr_path",
        client_role="scapy.BGPUpdate(optional-transitive)",
        server_role="scapy.BGPHeader.parse",
        independent_validator="scapy_bgp_codec",
        endpoint_note=(
            "speaker builds a real BGP UPDATE and the peer re-parses it with the scapy "
            "BGP codec in one Python process"
        ),
        required_extra="packet",
    ),
}


def _symbol_bytes(symbol: Any) -> bytes:
    if isinstance(symbol, bytes):
        return symbol
    raise TypeError("message-carrier transport expects bytes-valued carrier symbols")


class MessageCarrierTransport:
    """A ``Transport``/``Tap`` that carries symbols through a registered protocol codec."""

    def __init__(self, kind: str, qname: str = "covert.example.") -> None:
        if kind not in MESSAGE_CARRIER_KINDS:
            raise ValueError(f"unknown message-carrier transport kind: {kind}")
        self.kind = kind
        self.qname = qname
        self._wires: dict[str, list[bytes]] = {}

    @property
    def spec(self) -> MessageCarrierSpec:
        return MESSAGE_CARRIER_KINDS[self.kind]

    def send_symbols(self, session_id: str, symbols: list[Any], pacing: Any | None = None) -> None:
        build = self.spec.build
        self._wires[session_id] = [build(_symbol_bytes(s), self.qname) for s in symbols]

    def receive_symbols(self, session_id: str) -> list[Any]:
        parse = self.spec.parse
        return [parse(wire) for wire in self._wires.get(session_id, [])]

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        spec = self.spec
        wires = self._wires.get(session_id, [])
        return {
            "transport": self.kind,
            "claim_status": spec.claim_status,
            "message_count": len(wires),
            "wire_sha256": [hashlib.sha256(wire).hexdigest() for wire in wires],
            "client_role": spec.client_role,
            "server_role": spec.server_role,
            "independent_validator": spec.independent_validator,
        }


__all__ = [
    "MESSAGE_CARRIER_KINDS",
    "MessageCarrierSpec",
    "MessageCarrierTransport",
]
