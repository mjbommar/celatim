"""SSH KEXINIT carrier primitives (build/parse a real SSH_MSG_KEXINIT).

RFC 4253 §7.1: SSH_MSG_KEXINIT carries a 16-byte random cookie and ends with a
``uint32 0`` reserved field. Only the cookie is a carrier: the reserved word is fixed
at zero by the message grammar. These helpers build and parse the message with
paramiko's own ``Message`` wire codec. paramiko is the optional ``ssh`` extra, imported
lazily, so this module is safe to import without it.
"""

from __future__ import annotations

from typing import Any

SSH_MSG_KEXINIT = 20
KEXINIT_COOKIE_LEN = 16
KEXINIT_RESERVED_LEN = 4
KEXINIT_CARRIER_LEN = KEXINIT_COOKIE_LEN
SSH_KEXINIT_CLAIM_STATUS = "local_paramiko_client_server_kexinit_message_path"

# Ten name-lists in KEXINIT order (RFC 4253 §7.1); realistic modern algorithm names so
# the carrier is a conforming KEXINIT rather than a stripped blob.
_NAME_LISTS: tuple[list[str], ...] = (
    ["curve25519-sha256", "diffie-hellman-group14-sha256"],
    ["ssh-ed25519", "rsa-sha2-256"],
    ["aes256-gcm@openssh.com", "aes256-ctr"],
    ["aes256-gcm@openssh.com", "aes256-ctr"],
    ["hmac-sha2-256", "hmac-sha2-512"],
    ["hmac-sha2-256", "hmac-sha2-512"],
    ["none", "zlib@openssh.com"],
    ["none", "zlib@openssh.com"],
    [],
    [],
)


def _message() -> Any:
    from paramiko.message import Message

    return Message


def _carrier_bytes(symbol: bytes) -> bytes:
    if len(symbol) != KEXINIT_CARRIER_LEN:
        raise ValueError(f"ssh-kexinit-cookie carrier symbol must be {KEXINIT_CARRIER_LEN} bytes")
    return symbol


def build_kexinit(symbol: bytes) -> bytes:
    """Client role: build a real SSH_MSG_KEXINIT carrying ``symbol`` and return wire bytes."""

    carrier = _carrier_bytes(symbol)
    message = _message()()
    message.add_byte(bytes([SSH_MSG_KEXINIT]))
    message.add_bytes(carrier[:KEXINIT_COOKIE_LEN])
    for name_list in _NAME_LISTS:
        message.add_list(name_list)
    message.add_boolean(False)  # first_kex_packet_follows
    message.add_int(0)  # RFC 4253: uint32 0, reserved for future extension
    return bytes(message.asbytes())


def parse_kexinit(wire: bytes) -> bytes:
    """Server role / independent validator: recover the cookie from conforming wire."""

    message = _message()(wire)
    msg_type = message.get_bytes(1)
    if msg_type[0] != SSH_MSG_KEXINIT:
        raise ValueError("not an SSH_MSG_KEXINIT message")
    cookie = message.get_bytes(KEXINIT_COOKIE_LEN)
    for _ in _NAME_LISTS:
        message.get_list()
    message.get_boolean()
    reserved = int(message.get_int())
    if reserved != 0:
        raise ValueError("SSH_MSG_KEXINIT reserved uint32 must be zero")
    return bytes(cookie)


__all__ = [
    "KEXINIT_CARRIER_LEN",
    "KEXINIT_COOKIE_LEN",
    "KEXINIT_RESERVED_LEN",
    "SSH_KEXINIT_CLAIM_STATUS",
    "SSH_MSG_KEXINIT",
    "build_kexinit",
    "parse_kexinit",
]
