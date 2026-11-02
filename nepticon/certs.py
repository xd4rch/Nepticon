"""TLS certificate helpers for Nepticon.

For a local or lab deployment Nepticon can mint a private root CA and a
server certificate signed by it.  Production deployments should instead use
certificates issued by the organisation's PKI; the rest of the application
only needs PEM files.

The generator intentionally has no interactive prompts and never embeds a
passphrase: private keys are written with restrictive permissions and are
expected to be protected by the host operating system or a secrets manager.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import os
import socket
from pathlib import Path
from typing import Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LOCAL_CA_CN = "Nepticon Local Root CA"
SERVER_ORG = "Nepticon Fleet Operations"
SERVER_VALIDITY_DAYS = 825
CA_VALIDITY_DAYS = 3650


def _utcnow() -> _dt.datetime:
    # cryptography expects naive UTC datetimes.
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def _new_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_certificate(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass


def _domain_names(hostname: str, extra: Iterable[str]) -> list[str]:
    names = {"localhost", hostname or "localhost"}
    try:
        host = socket.gethostname()
        if host:
            names.add(host)
            if "." in host:
                names.add(host.split(".")[0])
    except OSError:
        pass
    for candidate in extra:
        value = str(candidate).strip()
        if value:
            names.add(value)
    return sorted({name for name in names if name and not _is_ip(name)})


def _ip_addresses(extra: Iterable[str]) -> list[ipaddress._BaseAddress]:
    values: set[ipaddress._BaseAddress] = {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    }
    candidates = list(extra)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            candidates.append(info[4][0])
    except OSError:
        pass
    for candidate in candidates:
        value = str(candidate).strip().strip("[]")
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        values.add(address)
    return sorted(values, key=lambda item: (item.version, str(item)))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def certificate_fingerprint(path: os.PathLike[str] | str) -> str:
    """Return the SHA-256 fingerprint of a PEM certificate, OpenSSL style."""

    cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def generate_certificates(
    directory: os.PathLike[str] | str,
    *,
    hostname: Optional[str] = None,
    extra_sans: Iterable[str] = (),
    cert_name: str = "server.crt",
    key_name: str = "server.key",
    ca_name: str = "ca.crt",
    ca_key_name: str = "ca.key",
    force: bool = False,
    key_size: int = 2048,
) -> dict[str, Path]:
    """Create a private CA and a server certificate.

    Existing files are left untouched unless ``force`` is true.  Returns a
    mapping with ``ca``, ``ca_key``, ``cert`` and ``key`` paths.
    """

    directory = Path(directory).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "ca": directory / ca_name,
        "ca_key": directory / ca_key_name,
        "cert": directory / cert_name,
        "key": directory / key_name,
    }

    existing = [path for path in paths.values() if path.exists()]
    if existing and not force:
        if all(path.is_file() for path in paths.values()):
            return paths
        raise FileExistsError(
            "the certificate directory contains a partial set; "
            "use --force-certs to regenerate it"
        )

    hostname = hostname or socket.gethostname() or "localhost"
    now = _utcnow()
    ca_key = _new_key(max(2048, key_size))
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, LOCAL_CA_CN),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, SERVER_ORG),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Local Development"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = _new_key(max(2048, key_size))
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, SERVER_ORG),
        ]
    )
    san_entries: list[x509.GeneralName] = []
    for name in _domain_names(hostname, extra_sans):
        san_entries.append(x509.DNSName(name))
    for address in _ip_addresses(extra_sans):
        san_entries.append(x509.IPAddress(address))
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=SERVER_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_private_key(paths["ca_key"], ca_key)
    _write_certificate(paths["ca"], ca_cert)
    _write_private_key(paths["key"], server_key)
    _write_certificate(paths["cert"], server_cert)
    return paths


def certificates_present(paths: Iterable[os.PathLike[str] | str]) -> bool:
    return all(Path(path).is_file() for path in paths)
