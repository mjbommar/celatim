"""TLS 1.3 identity and context helpers for the direct transfer provider."""

from __future__ import annotations

import hashlib
import os
import ssl
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .errors import TransferErrorCode, transfer_failure


@dataclass(frozen=True)
class TlsIdentity:
    certificate_path: Path
    private_key_path: Path
    certificate_sha256: str


def ensure_tls_identity(directory: Path) -> TlsIdentity:
    """Load or create an owner-only Ed25519 certificate for a transfer listener."""

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    certificate_path = directory / "transfer-server.crt.pem"
    private_key_path = directory / "transfer-server.key.pem"
    if certificate_path.is_file() and private_key_path.is_file():
        return TlsIdentity(
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            certificate_sha256=_certificate_fingerprint(certificate_path),
        )
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise transfer_failure(
            TransferErrorCode.CRYPTO_UNAVAILABLE,
            "TLS identity generation requires the celatim transfer extra",
        ) from exc

    private_key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Celatim transfer listener")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, algorithm=None)
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _atomic_write_private(private_key_path, private_key_pem)
    _atomic_write_private(certificate_path, certificate_pem)
    return TlsIdentity(
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        certificate_sha256=hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
    )


def server_ssl_context(identity: TlsIdentity) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(identity.certificate_path, identity.private_key_path)
    return context


def client_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def peer_certificate_sha256(ssl_object: ssl.SSLObject | ssl.SSLSocket) -> str:
    certificate = ssl_object.getpeercert(binary_form=True)
    if not certificate:
        raise transfer_failure(
            TransferErrorCode.TRUST_FAILED,
            "receiver did not present a TLS certificate",
        )
    return hashlib.sha256(certificate).hexdigest()


def _certificate_fingerprint(path: Path) -> str:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise transfer_failure(
            TransferErrorCode.CRYPTO_UNAVAILABLE,
            "TLS identity loading requires the celatim transfer extra",
        ) from exc
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise transfer_failure(
            TransferErrorCode.CRYPTO_FAILED,
            "stored transfer TLS certificate is invalid",
        ) from exc
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


def _atomic_write_private(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


__all__ = [
    "TlsIdentity",
    "client_ssl_context",
    "ensure_tls_identity",
    "peer_certificate_sha256",
    "server_ssl_context",
]
