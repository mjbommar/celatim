"""Local cryptographic transcript transports for Class G channels."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import TransportError
from .session import MechanismProfile, PacingConfig, Symbol

ECDSA_NONCE_TRANSPORT_KIND = "crypto_ecdsa_nonce"
ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION = "celatim.crypto_transcript.ecdsa_nonce.v1"
ECDSA_NONCE_TRANSPORT_METADATA_SCHEMA_VERSION = "celatim.transport_metadata.crypto_ecdsa_nonce.v1"
ECDSA_NONCE_CLAIM_STATUS = "real_ecdsa_sign_verify_local_transcript_nonce_recovery"
ECDSA_NONCE_SIGNING_BACKEND = "cryptography_openssl_with_explicit_research_nonce"
RSA_PSS_SALT_TRANSPORT_KIND = "crypto_rsa_pss_salt"
RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION = "celatim.crypto_transcript.rsa_pss_salt.v1"
RSA_PSS_SALT_TRANSPORT_METADATA_SCHEMA_VERSION = "celatim.transport_metadata.crypto_rsa_pss_salt.v1"
RSA_PSS_SALT_CLAIM_STATUS = "real_rsa_pss_sign_verify_local_transcript_salt_recovery"
RSA_PSS_SALT_SIGNING_BACKEND = "cryptography_openssl_with_explicit_rfc8017_pss_salt"
CRYPTO_TRANSCRIPT_KEY_SCOPE = "ephemeral_per_transcript"


@dataclass(frozen=True)
class EcdsaNonceTranscriptConfig:
    """Controls for the local ECDSA nonce transcript path."""

    transcript_path: Path | None = None
    curve: str = "NIST521p"
    hash_name: str = "sha256"
    nonce_payload_bits: int = 256
    honest_random_control_signatures: int = 2
    message_prefix: str = "celatim/ecdsa-nonce"

    def __post_init__(self) -> None:
        if self.nonce_payload_bits <= 0 or self.nonce_payload_bits % 8:
            raise TransportError("nonce_payload_bits must be a positive multiple of 8")
        if self.honest_random_control_signatures < 0:
            raise TransportError("honest_random_control_signatures must be >= 0")
        if not self.message_prefix:
            raise TransportError("message_prefix must be non-empty")


@dataclass(frozen=True)
class _EcdsaCurveSpec:
    curve: Any
    order: int

    @property
    def baselen(self) -> int:
        return (self.order.bit_length() + 7) // 8


@dataclass(frozen=True)
class RsaPssSaltTranscriptConfig:
    """Controls for the local RSA-PSS salt transcript path."""

    transcript_path: Path | None = None
    key_bits: int = 2048
    public_exponent: int = 65537
    hash_name: str = "sha256"
    mgf_hash_name: str = "sha256"
    salt_payload_bits: int = 256
    honest_random_control_signatures: int = 2
    message_prefix: str = "celatim/rsa-pss-salt"

    def __post_init__(self) -> None:
        if self.key_bits < 1024:
            raise TransportError("key_bits must be >= 1024")
        if self.public_exponent not in {3, 65537}:
            raise TransportError("public_exponent must be 3 or 65537")
        if self.salt_payload_bits <= 0 or self.salt_payload_bits % 8:
            raise TransportError("salt_payload_bits must be a positive multiple of 8")
        if self.honest_random_control_signatures < 0:
            raise TransportError("honest_random_control_signatures must be >= 0")
        if not self.message_prefix:
            raise TransportError("message_prefix must be non-empty")


class EcdsaNonceTranscriptTransport:
    """Sign and verify ECDSA signatures while recovering embedded nonce symbols.

    This transport is deliberately local: it creates a fresh signing key for one
    run, signs one message per carrier symbol with an explicit ECDSA nonce, verifies
    every signature with the public key, and recovers the nonce from the transcript
    using the signing scalar. The transcript artifact records the verifiable public
    evidence and hash references; the reusable channel framing still decides the
    payload bytes. This is not a general-purpose signer: explicit nonce construction
    is restricted to fresh per-transcript research keys and must never be used with a
    production or long-lived signing key.
    """

    def __init__(
        self,
        profile: MechanismProfile,
        config: EcdsaNonceTranscriptConfig | None = None,
    ) -> None:
        if profile.id != "ecdsa-nonce":
            raise TransportError("crypto_ecdsa_nonce transport only supports ecdsa-nonce")
        self.profile = profile
        self.config = config or EcdsaNonceTranscriptConfig()
        self._sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        crypto = _cryptography_modules()
        curve = _ecdsa_curve_by_name(crypto["ec"], self.config.curve)
        hashfunc = _hash_constructor(self.config.hash_name)
        hash_algorithm = _cryptography_hash_algorithm(crypto["hashes"], self.config.hash_name)
        order = curve.order
        if (1 << self.config.nonce_payload_bits) >= order:
            raise TransportError(
                f"{self.config.curve}: order is too small for "
                f"{self.config.nonce_payload_bits}-bit embedded nonce payloads"
            )

        signing_key = crypto["ec"].generate_private_key(curve.curve)
        verifying_key = signing_key.public_key()
        private_scalar = int(signing_key.private_numbers().private_value)
        symbol_bytes = self.config.nonce_payload_bits // 8
        recovered_symbols: list[Symbol] = []
        signature_entries: list[dict[str, Any]] = []

        for index, symbol in enumerate(symbols):
            symbol_value = _require_symbol_bytes(
                symbol,
                symbol_bytes,
                ECDSA_NONCE_TRANSPORT_KIND,
            )
            message = _message_bytes(self.config.message_prefix, session_id, index)
            digest = hashfunc(message).digest()
            nonce = int.from_bytes(symbol_value, "big") + 1
            signature, r, s = _sign_ecdsa_digest_with_nonce(
                crypto=crypto,
                curve=curve,
                private_scalar=private_scalar,
                digest=digest,
                nonce=nonce,
            )
            verified = _verify_ecdsa_digest(
                crypto,
                verifying_key,
                signature,
                digest,
                hash_algorithm,
            )
            recovered_nonce = _recover_ecdsa_nonce(
                digest=digest,
                r=r,
                s=s,
                private_scalar=private_scalar,
                order=order,
            )
            recovered_symbol = _nonce_to_symbol(
                recovered_nonce,
                self.config.nonce_payload_bits,
            )
            if not verified:
                raise TransportError(f"{session_id}: ECDSA signature {index} did not verify")
            if recovered_symbol != symbol_value:
                raise TransportError(
                    f"{session_id}: ECDSA nonce recovery mismatch at symbol {index}"
                )
            recovered_symbols.append(recovered_symbol)
            signature_entries.append(
                _signature_entry(
                    index=index,
                    message=message,
                    digest=digest,
                    signature=signature,
                    r=r,
                    s=s,
                    verified=verified,
                    recovered_symbol=recovered_symbol,
                    recovered_nonce=recovered_nonce,
                )
            )

        honest_control = _honest_random_control(
            crypto=crypto,
            signing_key=signing_key,
            verifying_key=verifying_key,
            private_scalar=private_scalar,
            order=order,
            hashfunc=hashfunc,
            hash_algorithm=hash_algorithm,
            message_prefix=self.config.message_prefix,
            session_id=session_id,
            count=self.config.honest_random_control_signatures,
            nonce_payload_bits=self.config.nonce_payload_bits,
        )
        transcript = {
            "schema_version": ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION,
            "session_id": session_id,
            "mechanism_id": self.profile.id,
            "curve": self.config.curve,
            "hash_name": self.config.hash_name,
            "nonce_payload_bits": self.config.nonce_payload_bits,
            "embedded_nonce_mapping": "k = int(symbol_bytes) + 1",
            "signing_backend": ECDSA_NONCE_SIGNING_BACKEND,
            "key_scope": CRYPTO_TRANSCRIPT_KEY_SCOPE,
            "signature_count": len(signature_entries),
            "verified_signature_count": sum(1 for entry in signature_entries if entry["verified"]),
            "recovered_symbol_count": len(recovered_symbols),
            "public_key_sha256": _hash_bytes(_ecdsa_public_key_bytes(verifying_key, curve.baselen)),
            "public_key_hex": _ecdsa_public_key_bytes(verifying_key, curve.baselen).hex(),
            "claim_status": ECDSA_NONCE_CLAIM_STATUS,
            "honest_random_control": honest_control,
            "signatures": signature_entries,
        }
        self._sessions[session_id] = recovered_symbols
        self._pacing[session_id] = pacing
        if self.config.transcript_path is not None:
            self.config.transcript_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.transcript_path.write_text(
                json.dumps(transcript, indent=2, sort_keys=True) + "\n"
            )
        self._metadata[session_id] = _ecdsa_transport_metadata(
            transcript,
            self.config.transcript_path,
        )

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        try:
            return list(self._sessions[session_id])
        except KeyError as exc:
            raise TransportError(f"no crypto transcript symbols for session: {session_id}") from exc

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        try:
            return dict(self._metadata[session_id])
        except KeyError as exc:
            raise TransportError(
                f"no crypto transcript metadata for session: {session_id}"
            ) from exc

    def path_for(self, session_id: str) -> Path:
        if self.config.transcript_path is None:
            raise TransportError(f"no transcript path configured for session: {session_id}")
        return self.config.transcript_path


class EcdsaNonceTranscriptReplayTransport:
    """Read recovered ECDSA nonce symbols from a persisted transcript artifact."""

    def __init__(self, profile: MechanismProfile, transcript_path: Path | str) -> None:
        if profile.id != "ecdsa-nonce":
            raise TransportError("crypto_ecdsa_nonce replay only supports ecdsa-nonce")
        self.profile = profile
        self.transcript_path = Path(transcript_path)

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        raise TransportError("crypto transcript replay transport is receive-only")

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        transcript = _load_transcript(self.transcript_path)
        _validate_transcript_header(
            transcript,
            path=self.transcript_path,
            schema_version=ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION,
            session_id=session_id,
            mechanism_id=self.profile.id,
        )
        signatures = _signature_list(transcript, self.transcript_path)
        if transcript.get("verified_signature_count") != len(signatures):
            raise TransportError(f"{self.transcript_path}: not all ECDSA signatures verified")
        if transcript.get("recovered_symbol_count") != len(signatures):
            raise TransportError(f"{self.transcript_path}: recovered symbol count mismatch")
        symbols: list[Symbol] = []
        for index, entry in enumerate(signatures):
            if entry.get("verified") is not True:
                raise TransportError(
                    f"{self.transcript_path}: ECDSA signature {index} is not verified"
                )
            raw = entry.get("recovered_symbol_hex")
            if not isinstance(raw, str):
                raise TransportError(
                    f"{self.transcript_path}: ECDSA signature {index} missing recovered_symbol_hex"
                )
            try:
                symbols.append(bytes.fromhex(raw))
            except ValueError as exc:
                raise TransportError(
                    f"{self.transcript_path}: invalid recovered_symbol_hex at signature {index}"
                ) from exc
        return symbols

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return None

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        transcript = _load_transcript(self.transcript_path)
        _validate_transcript_header(
            transcript,
            path=self.transcript_path,
            schema_version=ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION,
            session_id=session_id,
            mechanism_id=self.profile.id,
        )
        return _ecdsa_transport_metadata(transcript, self.transcript_path)

    def path_for(self, session_id: str) -> Path:
        return self.transcript_path


class RsaPssSaltTranscriptTransport:
    """Sign and verify RSA-PSS signatures while recovering embedded salt symbols.

    ``cryptography`` verifies every signature using the normal public RSA-PSS API. The
    sender side builds the RFC 8017 EMSA-PSS encoded message with caller-controlled
    salt, then performs the RSA private operation so the transcript can carry known
    salt bytes. This is the practical interface needed for a subliminal-channel
    measurement: standard PSS verification accepts the signature, while the cooperating
    receiver can recover the salt from the public RSA operation.
    """

    def __init__(
        self,
        profile: MechanismProfile,
        config: RsaPssSaltTranscriptConfig | None = None,
    ) -> None:
        if profile.id != "rsa-pss-salt":
            raise TransportError("crypto_rsa_pss_salt transport only supports rsa-pss-salt")
        self.profile = profile
        self.config = config or RsaPssSaltTranscriptConfig()
        self._sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        crypto = _cryptography_modules()
        hashfunc = _hash_constructor(self.config.hash_name)
        mgf_hashfunc = _hash_constructor(self.config.mgf_hash_name)
        hash_algorithm = _cryptography_hash_algorithm(crypto["hashes"], self.config.hash_name)
        mgf_hash_algorithm = _cryptography_hash_algorithm(
            crypto["hashes"],
            self.config.mgf_hash_name,
        )
        salt_bytes = self.config.salt_payload_bits // 8
        private_key = crypto["rsa"].generate_private_key(
            public_exponent=self.config.public_exponent,
            key_size=self.config.key_bits,
        )
        public_key = private_key.public_key()
        private_numbers = private_key.private_numbers()
        public_numbers = private_numbers.public_numbers
        modulus = int(public_numbers.n)
        public_exponent = int(public_numbers.e)
        private_exponent = int(private_numbers.d)
        modulus_bits = modulus.bit_length()
        em_bits = modulus_bits - 1
        if _rsa_pss_em_len(em_bits) < hashfunc().digest_size + salt_bytes + 2:
            raise TransportError(
                f"{self.config.key_bits}-bit RSA key is too small for "
                f"{self.config.hash_name} with {salt_bytes}-byte PSS salt"
            )

        recovered_symbols: list[Symbol] = []
        signature_entries: list[dict[str, Any]] = []
        embedded_salt_hashes: set[str] = set()

        for index, symbol in enumerate(symbols):
            salt = _require_symbol_bytes(symbol, salt_bytes, RSA_PSS_SALT_TRANSPORT_KIND)
            embedded_salt_hashes.add(_hash_bytes(salt))
            message = _message_bytes(self.config.message_prefix, session_id, index)
            signature = _rsa_pss_sign_with_salt(
                message=message,
                salt=salt,
                modulus=modulus,
                private_exponent=private_exponent,
                em_bits=em_bits,
                hashfunc=hashfunc,
                mgf_hashfunc=mgf_hashfunc,
            )
            verified = _verify_rsa_pss_signature(
                crypto=crypto,
                public_key=public_key,
                signature=signature,
                message=message,
                hash_algorithm=hash_algorithm,
                mgf_hash_algorithm=mgf_hash_algorithm,
                salt_len=salt_bytes,
            )
            recovered_salt = _recover_rsa_pss_salt(
                signature=signature,
                modulus=modulus,
                public_exponent=public_exponent,
                em_bits=em_bits,
                salt_len=salt_bytes,
                hashfunc=hashfunc,
                mgf_hashfunc=mgf_hashfunc,
            )
            if not verified:
                raise TransportError(f"{session_id}: RSA-PSS signature {index} did not verify")
            if recovered_salt != salt:
                raise TransportError(
                    f"{session_id}: RSA-PSS salt recovery mismatch at symbol {index}"
                )
            recovered_symbols.append(recovered_salt)
            signature_entries.append(
                _rsa_pss_signature_entry(
                    index=index,
                    message=message,
                    signature=signature,
                    verified=verified,
                    recovered_salt=recovered_salt,
                )
            )

        honest_control = _rsa_pss_honest_random_control(
            crypto=crypto,
            private_key=private_key,
            public_key=public_key,
            modulus=modulus,
            public_exponent=public_exponent,
            em_bits=em_bits,
            hash_algorithm=hash_algorithm,
            mgf_hash_algorithm=mgf_hash_algorithm,
            hashfunc=hashfunc,
            mgf_hashfunc=mgf_hashfunc,
            message_prefix=self.config.message_prefix,
            session_id=session_id,
            count=self.config.honest_random_control_signatures,
            salt_len=salt_bytes,
            embedded_salt_hashes=embedded_salt_hashes,
        )
        public_key_der = public_key.public_bytes(
            crypto["serialization"].Encoding.DER,
            crypto["serialization"].PublicFormat.SubjectPublicKeyInfo,
        )
        transcript = {
            "schema_version": RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION,
            "session_id": session_id,
            "mechanism_id": self.profile.id,
            "key_bits": self.config.key_bits,
            "public_exponent": self.config.public_exponent,
            "hash_name": self.config.hash_name,
            "mgf_hash_name": self.config.mgf_hash_name,
            "salt_payload_bits": self.config.salt_payload_bits,
            "embedded_salt_mapping": "salt = symbol_bytes",
            "signing_backend": RSA_PSS_SALT_SIGNING_BACKEND,
            "key_scope": CRYPTO_TRANSCRIPT_KEY_SCOPE,
            "signature_count": len(signature_entries),
            "verified_signature_count": sum(1 for entry in signature_entries if entry["verified"]),
            "recovered_symbol_count": len(recovered_symbols),
            "public_key_sha256": _hash_bytes(public_key_der),
            "modulus_sha256": _hash_bytes(modulus.to_bytes((modulus_bits + 7) // 8, "big")),
            "claim_status": RSA_PSS_SALT_CLAIM_STATUS,
            "honest_random_control": honest_control,
            "signatures": signature_entries,
        }
        self._sessions[session_id] = recovered_symbols
        self._pacing[session_id] = pacing
        if self.config.transcript_path is not None:
            self.config.transcript_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.transcript_path.write_text(
                json.dumps(transcript, indent=2, sort_keys=True) + "\n"
            )
        self._metadata[session_id] = _rsa_pss_transport_metadata(
            transcript,
            self.config.transcript_path,
        )

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        try:
            return list(self._sessions[session_id])
        except KeyError as exc:
            raise TransportError(f"no crypto transcript symbols for session: {session_id}") from exc

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        try:
            return dict(self._metadata[session_id])
        except KeyError as exc:
            raise TransportError(
                f"no crypto transcript metadata for session: {session_id}"
            ) from exc

    def path_for(self, session_id: str) -> Path:
        if self.config.transcript_path is None:
            raise TransportError(f"no transcript path configured for session: {session_id}")
        return self.config.transcript_path


class RsaPssSaltTranscriptReplayTransport:
    """Read recovered RSA-PSS salt symbols from a persisted transcript artifact."""

    def __init__(self, profile: MechanismProfile, transcript_path: Path | str) -> None:
        if profile.id != "rsa-pss-salt":
            raise TransportError("crypto_rsa_pss_salt replay only supports rsa-pss-salt")
        self.profile = profile
        self.transcript_path = Path(transcript_path)

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        raise TransportError("crypto transcript replay transport is receive-only")

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        transcript = _load_transcript(self.transcript_path)
        _validate_transcript_header(
            transcript,
            path=self.transcript_path,
            schema_version=RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION,
            session_id=session_id,
            mechanism_id=self.profile.id,
        )
        signatures = _signature_list(transcript, self.transcript_path)
        if transcript.get("verified_signature_count") != len(signatures):
            raise TransportError(f"{self.transcript_path}: not all RSA-PSS signatures verified")
        if transcript.get("recovered_symbol_count") != len(signatures):
            raise TransportError(f"{self.transcript_path}: recovered symbol count mismatch")
        symbols: list[Symbol] = []
        for index, entry in enumerate(signatures):
            if entry.get("verified") is not True:
                raise TransportError(
                    f"{self.transcript_path}: RSA-PSS signature {index} is not verified"
                )
            raw = entry.get("recovered_salt_hex")
            if not isinstance(raw, str):
                raise TransportError(
                    f"{self.transcript_path}: RSA-PSS signature {index} missing recovered_salt_hex"
                )
            try:
                symbols.append(bytes.fromhex(raw))
            except ValueError as exc:
                raise TransportError(
                    f"{self.transcript_path}: invalid recovered_salt_hex at signature {index}"
                ) from exc
        return symbols

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return None

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        transcript = _load_transcript(self.transcript_path)
        _validate_transcript_header(
            transcript,
            path=self.transcript_path,
            schema_version=RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION,
            session_id=session_id,
            mechanism_id=self.profile.id,
        )
        return _rsa_pss_transport_metadata(transcript, self.transcript_path)

    def path_for(self, session_id: str) -> Path:
        return self.transcript_path


def _load_transcript(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise TransportError(f"{path}: transcript file not found") from exc
    except json.JSONDecodeError as exc:
        raise TransportError(f"{path}: invalid transcript JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise TransportError(f"{path}: transcript must be a JSON object")
    return raw


def _validate_transcript_header(
    transcript: dict[str, Any],
    *,
    path: Path,
    schema_version: str,
    session_id: str,
    mechanism_id: str,
) -> None:
    if transcript.get("schema_version") != schema_version:
        raise TransportError(f"{path}: unsupported transcript schema")
    if transcript.get("session_id") != session_id:
        raise TransportError(f"{path}: session id mismatch")
    if transcript.get("mechanism_id") != mechanism_id:
        raise TransportError(f"{path}: mechanism id mismatch")


def _signature_list(transcript: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    signatures = transcript.get("signatures")
    if not isinstance(signatures, list):
        raise TransportError(f"{path}: signatures must be an array")
    for index, entry in enumerate(signatures):
        if not isinstance(entry, dict):
            raise TransportError(f"{path}: signature {index} must be an object")
    return signatures


def _cryptography_modules() -> dict[str, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError as exc:  # pragma: no cover - depends on optional extra installation
        raise TransportError(
            "crypto transcript transports require optional extra 'crypto' (cryptography>=46.0.3)"
        ) from exc
    return {
        "InvalidSignature": InvalidSignature,
        "ec": ec,
        "hashes": hashes,
        "padding": padding,
        "rsa": rsa,
        "serialization": serialization,
        "utils": utils,
    }


def _ecdsa_curve_by_name(ec: Any, curve: str) -> _EcdsaCurveSpec:
    curves = {
        "NIST256p": _EcdsaCurveSpec(
            ec.SECP256R1(),
            int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
        ),
        "NIST384p": _EcdsaCurveSpec(
            ec.SECP384R1(),
            int(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
                "581A0DB248B0A77AECEC196ACCC52973",
                16,
            ),
        ),
        "NIST521p": _EcdsaCurveSpec(
            ec.SECP521R1(),
            int(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
                16,
            ),
        ),
        "SECP256k1": _EcdsaCurveSpec(
            ec.SECP256K1(),
            int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),
        ),
    }
    try:
        return curves[curve]
    except KeyError as exc:
        raise TransportError(f"unsupported ECDSA curve: {curve}") from exc


def _hash_constructor(hash_name: str) -> Any:
    try:
        hashlib.new(hash_name)
    except ValueError as exc:
        raise TransportError(f"unsupported hash function: {hash_name}") from exc

    def build(data: bytes = b"") -> Any:
        return hashlib.new(hash_name, data)

    return build


def _cryptography_hash_algorithm(hashes: Any, hash_name: str) -> Any:
    algorithms = {
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    normalized = hash_name.lower().replace("-", "")
    try:
        return algorithms[normalized]()
    except KeyError as exc:
        raise TransportError(f"unsupported cryptography hash function: {hash_name}") from exc


def _require_symbol_bytes(symbol: Symbol, expected_len: int, transport_kind: str) -> bytes:
    if not isinstance(symbol, bytes):
        raise TransportError(f"{transport_kind} requires bytes-valued carrier symbols")
    if len(symbol) != expected_len:
        raise TransportError(
            f"{transport_kind} expected {expected_len} symbol bytes, got {len(symbol)}"
        )
    return symbol


def _message_bytes(prefix: str, session_id: str, index: int) -> bytes:
    return f"{prefix}/{session_id}/{index}".encode()


def _verify_ecdsa_digest(
    crypto: dict[str, Any],
    verifying_key: Any,
    signature: bytes,
    digest: bytes,
    hash_algorithm: Any,
) -> bool:
    try:
        verifying_key.verify(
            signature,
            digest,
            crypto["ec"].ECDSA(crypto["utils"].Prehashed(hash_algorithm)),
        )
        return True
    except crypto["InvalidSignature"]:
        return False


def _digest_to_ecdsa_scalar(digest: bytes, order: int) -> int:
    value = int.from_bytes(digest, "big")
    excess_bits = len(digest) * 8 - order.bit_length()
    return value >> max(0, excess_bits)


def _sign_ecdsa_digest_with_nonce(
    *,
    crypto: dict[str, Any],
    curve: _EcdsaCurveSpec,
    private_scalar: int,
    digest: bytes,
    nonce: int,
) -> tuple[bytes, int, int]:
    if not 1 <= nonce < curve.order:
        raise TransportError("ECDSA nonce must be in the curve scalar range")
    nonce_point = crypto["ec"].derive_private_key(nonce, curve.curve).public_key()
    r = int(nonce_point.public_numbers().x) % curve.order
    z = _digest_to_ecdsa_scalar(digest, curve.order)
    s = (pow(nonce, -1, curve.order) * (z + r * private_scalar)) % curve.order
    if r == 0 or s == 0:
        raise TransportError("explicit ECDSA nonce produced an invalid zero signature scalar")
    return crypto["utils"].encode_dss_signature(r, s), r, s


def _ecdsa_public_key_bytes(public_key: Any, baselen: int) -> bytes:
    numbers = public_key.public_numbers()
    return int(numbers.x).to_bytes(baselen, "big") + int(numbers.y).to_bytes(baselen, "big")


def _recover_ecdsa_nonce(
    *,
    digest: bytes,
    r: int,
    s: int,
    private_scalar: int,
    order: int,
) -> int:
    z = _digest_to_ecdsa_scalar(digest, order)
    return ((z + r * private_scalar) * pow(s, -1, order)) % order


def _nonce_to_symbol(nonce: int, nonce_payload_bits: int) -> bytes:
    symbol = nonce - 1
    if not 0 <= symbol < (1 << nonce_payload_bits):
        raise TransportError("recovered ECDSA nonce is outside the embedded symbol range")
    return symbol.to_bytes(nonce_payload_bits // 8, "big")


def _signature_entry(
    *,
    index: int,
    message: bytes,
    digest: bytes,
    signature: bytes,
    r: int,
    s: int,
    verified: bool,
    recovered_symbol: bytes,
    recovered_nonce: int,
) -> dict[str, Any]:
    return {
        "index": index,
        "message_sha256": _hash_bytes(message),
        "digest_hex": digest.hex(),
        "signature_sha256": _hash_bytes(signature),
        "signature_bit_count": len(signature) * 8,
        "signature_bit_one_count": _bit_one_count(signature),
        "r_hex": f"{r:x}",
        "s_hex": f"{s:x}",
        "verified": verified,
        "recovered_nonce_bit_length": recovered_nonce.bit_length(),
        "recovered_symbol_hex": recovered_symbol.hex(),
        "recovered_symbol_sha256": _hash_bytes(recovered_symbol),
    }


def _rsa_pss_em_len(em_bits: int) -> int:
    return (em_bits + 7) // 8


def _rsa_pss_sign_with_salt(
    *,
    message: bytes,
    salt: bytes,
    modulus: int,
    private_exponent: int,
    em_bits: int,
    hashfunc: Any,
    mgf_hashfunc: Any,
) -> bytes:
    em = _rsa_pss_encode(
        message=message,
        em_bits=em_bits,
        salt=salt,
        hashfunc=hashfunc,
        mgf_hashfunc=mgf_hashfunc,
    )
    signature_int = pow(int.from_bytes(em, "big"), private_exponent, modulus)
    return signature_int.to_bytes((modulus.bit_length() + 7) // 8, "big")


def _rsa_pss_encode(
    *,
    message: bytes,
    em_bits: int,
    salt: bytes,
    hashfunc: Any,
    mgf_hashfunc: Any,
) -> bytes:
    message_hash = hashfunc(message).digest()
    h_len = len(message_hash)
    em_len = _rsa_pss_em_len(em_bits)
    salt_len = len(salt)
    if em_len < h_len + salt_len + 2:
        raise TransportError("encoded RSA-PSS message is too short for hash and salt")
    m_prime = b"\x00" * 8 + message_hash + salt
    h = hashfunc(m_prime).digest()
    ps = b"\x00" * (em_len - salt_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1(h, em_len - h_len - 1, mgf_hashfunc)
    masked_db = bytes(left ^ right for left, right in zip(db, db_mask, strict=True))
    unused_bits = 8 * em_len - em_bits
    if unused_bits:
        masked_db = bytes([masked_db[0] & (0xFF >> unused_bits)]) + masked_db[1:]
    return masked_db + h + b"\xbc"


def _mgf1(seed: bytes, mask_len: int, hashfunc: Any) -> bytes:
    if mask_len < 0:
        raise TransportError("MGF1 mask length must be >= 0")
    output = bytearray()
    counter = 0
    while len(output) < mask_len:
        output.extend(hashfunc(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:mask_len])


def _verify_rsa_pss_signature(
    *,
    crypto: dict[str, Any],
    public_key: Any,
    signature: bytes,
    message: bytes,
    hash_algorithm: Any,
    mgf_hash_algorithm: Any,
    salt_len: int,
) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            crypto["padding"].PSS(
                mgf=crypto["padding"].MGF1(mgf_hash_algorithm),
                salt_length=salt_len,
            ),
            hash_algorithm,
        )
    except crypto["InvalidSignature"]:
        return False
    return True


def _recover_rsa_pss_salt(
    *,
    signature: bytes,
    modulus: int,
    public_exponent: int,
    em_bits: int,
    salt_len: int,
    hashfunc: Any,
    mgf_hashfunc: Any,
) -> bytes:
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        raise TransportError("RSA-PSS signature representative is out of range")
    encoded_int = pow(signature_int, public_exponent, modulus)
    em = encoded_int.to_bytes(_rsa_pss_em_len(em_bits), "big")
    return _rsa_pss_decode_salt(
        em=em,
        em_bits=em_bits,
        salt_len=salt_len,
        hashfunc=hashfunc,
        mgf_hashfunc=mgf_hashfunc,
    )


def _rsa_pss_decode_salt(
    *,
    em: bytes,
    em_bits: int,
    salt_len: int,
    hashfunc: Any,
    mgf_hashfunc: Any,
) -> bytes:
    h_len = hashfunc().digest_size
    em_len = len(em)
    if em_len < h_len + salt_len + 2:
        raise TransportError("encoded RSA-PSS message is too short")
    if em[-1] != 0xBC:
        raise TransportError("encoded RSA-PSS message has an invalid trailer field")
    masked_db = em[: em_len - h_len - 1]
    h = em[em_len - h_len - 1 : -1]
    unused_bits = 8 * em_len - em_bits
    if unused_bits and masked_db[0] & (0xFF << (8 - unused_bits)):
        raise TransportError("encoded RSA-PSS message has non-zero unused bits")
    db_mask = _mgf1(h, em_len - h_len - 1, mgf_hashfunc)
    db = bytes(left ^ right for left, right in zip(masked_db, db_mask, strict=True))
    if unused_bits:
        db = bytes([db[0] & (0xFF >> unused_bits)]) + db[1:]
    ps_len = em_len - h_len - salt_len - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len] != 0x01:
        raise TransportError("encoded RSA-PSS message has an invalid DB separator")
    return db[-salt_len:]


def _rsa_pss_signature_entry(
    *,
    index: int,
    message: bytes,
    signature: bytes,
    verified: bool,
    recovered_salt: bytes,
) -> dict[str, Any]:
    return {
        "index": index,
        "message_sha256": _hash_bytes(message),
        "signature_sha256": _hash_bytes(signature),
        "signature_bit_count": len(signature) * 8,
        "signature_bit_one_count": _bit_one_count(signature),
        "signature_size_bytes": len(signature),
        "verified": verified,
        "recovered_salt_hex": recovered_salt.hex(),
        "recovered_salt_sha256": _hash_bytes(recovered_salt),
        "recovered_salt_size_bytes": len(recovered_salt),
    }


def _rsa_pss_honest_random_control(
    *,
    crypto: dict[str, Any],
    private_key: Any,
    public_key: Any,
    modulus: int,
    public_exponent: int,
    em_bits: int,
    hash_algorithm: Any,
    mgf_hash_algorithm: Any,
    hashfunc: Any,
    mgf_hashfunc: Any,
    message_prefix: str,
    session_id: str,
    count: int,
    salt_len: int,
    embedded_salt_hashes: set[str],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    recovered_salt_hashes: set[str] = set()
    for index in range(count):
        message = _message_bytes(message_prefix, f"{session_id}:honest-random-control", index)
        signature = private_key.sign(
            message,
            crypto["padding"].PSS(
                mgf=crypto["padding"].MGF1(mgf_hash_algorithm),
                salt_length=salt_len,
            ),
            hash_algorithm,
        )
        verified = _verify_rsa_pss_signature(
            crypto=crypto,
            public_key=public_key,
            signature=signature,
            message=message,
            hash_algorithm=hash_algorithm,
            mgf_hash_algorithm=mgf_hash_algorithm,
            salt_len=salt_len,
        )
        recovered_salt = _recover_rsa_pss_salt(
            signature=signature,
            modulus=modulus,
            public_exponent=public_exponent,
            em_bits=em_bits,
            salt_len=salt_len,
            hashfunc=hashfunc,
            mgf_hashfunc=mgf_hashfunc,
        )
        salt_hash = _hash_bytes(recovered_salt)
        recovered_salt_hashes.add(salt_hash)
        records.append(
            {
                "index": index,
                "message_sha256": _hash_bytes(message),
                "signature_sha256": _hash_bytes(signature),
                "signature_bit_count": len(signature) * 8,
                "signature_bit_one_count": _bit_one_count(signature),
                "verified": verified,
                "recovered_salt_sha256": salt_hash,
                "recovered_salt_size_bytes": len(recovered_salt),
                "embedded_payload_match": salt_hash in embedded_salt_hashes,
            }
        )
    return {
        "signature_count": len(records),
        "verified_signature_count": sum(1 for record in records if record["verified"]),
        "recovered_salt_count": len(records),
        "distinct_recovered_salt_sha256_count": len(recovered_salt_hashes),
        "embedded_payload_match_count": sum(
            1 for record in records if record["embedded_payload_match"]
        ),
        "records": records,
    }


def _honest_random_control(
    *,
    crypto: dict[str, Any],
    signing_key: Any,
    verifying_key: Any,
    private_scalar: int,
    order: int,
    hashfunc: Any,
    hash_algorithm: Any,
    message_prefix: str,
    session_id: str,
    count: int,
    nonce_payload_bits: int,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for index in range(count):
        message = _message_bytes(message_prefix, f"{session_id}:honest-random-control", index)
        digest = hashfunc(message).digest()
        signature = signing_key.sign(
            digest,
            crypto["ec"].ECDSA(crypto["utils"].Prehashed(hash_algorithm)),
        )
        r, s = crypto["utils"].decode_dss_signature(signature)
        verified = _verify_ecdsa_digest(
            crypto,
            verifying_key,
            signature,
            digest,
            hash_algorithm,
        )
        recovered_nonce = _recover_ecdsa_nonce(
            digest=digest,
            r=r,
            s=s,
            private_scalar=private_scalar,
            order=order,
        )
        records.append(
            {
                "index": index,
                "message_sha256": _hash_bytes(message),
                "signature_sha256": _hash_bytes(signature),
                "signature_bit_count": len(signature) * 8,
                "signature_bit_one_count": _bit_one_count(signature),
                "verified": verified,
                "recovered_nonce_bit_length": recovered_nonce.bit_length(),
                "embedded_symbol_like": 1 <= recovered_nonce <= (1 << nonce_payload_bits),
            }
        )
    return {
        "signature_count": len(records),
        "verified_signature_count": sum(1 for record in records if record["verified"]),
        "embedded_symbol_like_count": sum(
            1 for record in records if record["embedded_symbol_like"]
        ),
        "records": records,
    }


def _ecdsa_transport_metadata(
    transcript: dict[str, Any],
    transcript_path: Path | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "schema_version": ECDSA_NONCE_TRANSPORT_METADATA_SCHEMA_VERSION,
        "transcript_schema_version": transcript["schema_version"],
        "curve": transcript["curve"],
        "hash_name": transcript["hash_name"],
        "nonce_payload_bits": transcript["nonce_payload_bits"],
        "signature_count": transcript["signature_count"],
        "verified_signature_count": transcript["verified_signature_count"],
        "recovered_symbol_count": transcript["recovered_symbol_count"],
        "public_key_sha256": transcript["public_key_sha256"],
        "claim_status": transcript["claim_status"],
        "honest_random_control": {
            "signature_count": transcript["honest_random_control"]["signature_count"],
            "verified_signature_count": transcript["honest_random_control"][
                "verified_signature_count"
            ],
            "embedded_symbol_like_count": transcript["honest_random_control"][
                "embedded_symbol_like_count"
            ],
        },
        "transcript_sha256": None,
        "transcript_size_bytes": None,
    }
    if transcript_path is not None and transcript_path.is_file():
        raw = transcript_path.read_bytes()
        metadata["transcript_sha256"] = _hash_bytes(raw)
        metadata["transcript_size_bytes"] = len(raw)
    return metadata


def _rsa_pss_transport_metadata(
    transcript: dict[str, Any],
    transcript_path: Path | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "schema_version": RSA_PSS_SALT_TRANSPORT_METADATA_SCHEMA_VERSION,
        "transcript_schema_version": transcript["schema_version"],
        "key_bits": transcript["key_bits"],
        "public_exponent": transcript["public_exponent"],
        "hash_name": transcript["hash_name"],
        "mgf_hash_name": transcript["mgf_hash_name"],
        "salt_payload_bits": transcript["salt_payload_bits"],
        "signature_count": transcript["signature_count"],
        "verified_signature_count": transcript["verified_signature_count"],
        "recovered_symbol_count": transcript["recovered_symbol_count"],
        "public_key_sha256": transcript["public_key_sha256"],
        "modulus_sha256": transcript["modulus_sha256"],
        "claim_status": transcript["claim_status"],
        "honest_random_control": {
            "signature_count": transcript["honest_random_control"]["signature_count"],
            "verified_signature_count": transcript["honest_random_control"][
                "verified_signature_count"
            ],
            "recovered_salt_count": transcript["honest_random_control"]["recovered_salt_count"],
            "distinct_recovered_salt_sha256_count": transcript["honest_random_control"][
                "distinct_recovered_salt_sha256_count"
            ],
            "embedded_payload_match_count": transcript["honest_random_control"][
                "embedded_payload_match_count"
            ],
        },
        "transcript_sha256": None,
        "transcript_size_bytes": None,
    }
    if transcript_path is not None and transcript_path.is_file():
        raw = transcript_path.read_bytes()
        metadata["transcript_sha256"] = _hash_bytes(raw)
        metadata["transcript_size_bytes"] = len(raw)
    return metadata


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bit_one_count(value: bytes) -> int:
    return sum(byte.bit_count() for byte in value)


__all__ = [
    "ECDSA_NONCE_CLAIM_STATUS",
    "ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION",
    "ECDSA_NONCE_TRANSPORT_KIND",
    "ECDSA_NONCE_TRANSPORT_METADATA_SCHEMA_VERSION",
    "RSA_PSS_SALT_CLAIM_STATUS",
    "RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION",
    "RSA_PSS_SALT_TRANSPORT_KIND",
    "RSA_PSS_SALT_TRANSPORT_METADATA_SCHEMA_VERSION",
    "EcdsaNonceTranscriptConfig",
    "EcdsaNonceTranscriptReplayTransport",
    "EcdsaNonceTranscriptTransport",
    "RsaPssSaltTranscriptConfig",
    "RsaPssSaltTranscriptReplayTransport",
    "RsaPssSaltTranscriptTransport",
]
