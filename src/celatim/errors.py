"""Typed exceptions for library-facing failure modes."""

from __future__ import annotations


class CelatimError(Exception):
    """Base class for errors that callers can handle as library failures."""


class ConfigurationError(CelatimError, ValueError):
    """Invalid caller configuration or incompatible API arguments."""


class UnsupportedMechanismError(CelatimError, KeyError):
    """Requested mechanism id is not present in the loaded catalog."""


class TransportError(CelatimError, RuntimeError):
    """Transport or tap could not provide carrier symbols."""


class ReceiveTimeoutError(TransportError):
    """Transport or tap timed out waiting for receiver-visible carrier symbols."""


class EncodeError(CelatimError, ValueError):
    """Payload could not be encoded into carrier symbols."""


class DecodeError(CelatimError, ValueError):
    """Carrier symbols were present but could not be decoded into a payload."""


class EnvelopeValidationError(CelatimError, ValueError):
    """JSON envelope is malformed or carrier bytes do not match its symbols."""


class ControlFailureError(CelatimError, AssertionError):
    """Covert or benign-control case failed a required check."""


__all__ = [
    "CelatimError",
    "ConfigurationError",
    "ControlFailureError",
    "DecodeError",
    "EncodeError",
    "EnvelopeValidationError",
    "ReceiveTimeoutError",
    "TransportError",
    "UnsupportedMechanismError",
]
