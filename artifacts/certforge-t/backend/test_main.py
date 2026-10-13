from __future__ import annotations

import base64
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

import main
import crypto_operations

client = TestClient(main.app)


@pytest.fixture()
def issued_certificate() -> Iterator[tuple[bytes, bytes]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertForge tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "workbench.example.test"),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("workbench.example.test"),
                    x509.DNSName("www.example.test"),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    yield certificate_pem, key_pem


def _decode_file_response(payload: dict[str, object]) -> bytes:
    return base64.b64decode(str(payload["content_base64"]), validate=True)


def test_health_reports_openssl() -> None:
    response = client.get("/certforge-api/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["openssl_version"].startswith("OpenSSL ")


def test_inspection_returns_real_certificate_fields(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, _ = issued_certificate

    response = client.post(
        "/certforge-api/certificates/inspect",
        files={"certificate_file": ("certificate.pem", certificate_pem)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert "workbench.example.test" in payload["subject"]
    assert payload["is_valid_now"] is True
    assert payload["public_key_algorithm"] == "RSA"
    assert payload["public_key_size"] == 2048
    assert "SHA256" in payload["signature_algorithm"]
    assert payload["sans"] == ["DNS:workbench.example.test", "DNS:www.example.test"]
    assert len(payload["sha256_fingerprint"].split(":")) == 32


def test_inspection_accepts_der_certificate(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, _ = issued_certificate
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)

    response = client.post(
        "/certforge-api/certificates/inspect",
        files={"certificate_file": ("certificate.der", certificate_der)},
    )

    assert response.status_code == 200
    assert response.json()["serial_number"] == format(certificate.serial_number, "X")


def test_match_reports_matching_and_non_matching_keys(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, key_pem = issued_certificate
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key_pem = wrong_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    matching_response = client.post(
        "/certforge-api/certificates/match",
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "private_key_file": ("private-key.pem", key_pem),
        },
    )
    mismatched_response = client.post(
        "/certforge-api/certificates/match",
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "private_key_file": ("private-key.pem", wrong_key_pem),
        },
    )

    assert matching_response.status_code == 200
    assert matching_response.json()["matches"] is True
    assert mismatched_response.status_code == 200
    assert mismatched_response.json()["matches"] is False


def test_match_accepts_a_public_key_file(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, _ = issued_certificate
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    public_key_pem = certificate.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    response = client.post(
        "/certforge-api/certificates/match",
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "public_key_file": ("public-key.pem", public_key_pem),
        },
    )

    assert response.status_code == 200
    assert response.json()["matches"] is True
    assert response.json()["key_kind"] == "public"
    assert response.json()["uploaded_key_algorithm"] == "RSA"


def test_match_accepts_an_encrypted_private_key(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, key_pem = issued_certificate
    private_key = serialization.load_pem_private_key(key_pem, password=None)
    passphrase = b"test-private-key-passphrase"
    encrypted_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )

    response = client.post(
        "/certforge-api/certificates/match",
        data={"private_key_passphrase": passphrase.decode()},
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "private_key_file": ("private-key.pem", encrypted_key_pem),
        },
    )

    assert response.status_code == 200
    assert response.json()["matches"] is True
    assert response.json()["key_kind"] == "private"


def test_wrong_private_key_passphrase_is_not_returned(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, key_pem = issued_certificate
    private_key = serialization.load_pem_private_key(key_pem, password=None)
    encrypted_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"correct-passphrase"),
    )
    wrong_passphrase = "do-not-reflect-this-value"

    response = client.post(
        "/certforge-api/certificates/match",
        data={"private_key_passphrase": wrong_passphrase},
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "private_key_file": ("private-key.pem", encrypted_key_pem),
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "private_key_invalid"
    assert wrong_passphrase not in response.text


@pytest.mark.parametrize(
    ("input_format", "target_format", "expected_encoding"),
    [("PEM", "DER", serialization.Encoding.DER), ("DER", "PEM", serialization.Encoding.PEM)],
)
def test_certificate_format_conversion(
    issued_certificate: tuple[bytes, bytes],
    input_format: str,
    target_format: str,
    expected_encoding: serialization.Encoding,
) -> None:
    certificate_pem, _ = issued_certificate
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    input_bytes = certificate_pem
    if input_format == "DER":
        input_bytes = certificate.public_bytes(serialization.Encoding.DER)

    response = client.post(
        "/certforge-api/certificates/convert",
        data={"input_format": input_format, "target_format": target_format},
        files={"certificate_file": (f"certificate.{input_format.lower()}", input_bytes)},
    )

    assert response.status_code == 200
    payload = response.json()
    converted = _decode_file_response(payload)
    parsed = (
        x509.load_der_x509_certificate(converted)
        if expected_encoding == serialization.Encoding.DER
        else x509.load_pem_x509_certificate(converted)
    )
    assert parsed.fingerprint(hashes.SHA256()) == certificate.fingerprint(hashes.SHA256())


def test_pkcs12_export_and_import_round_trip(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, key_pem = issued_certificate
    exported = client.post(
        "/certforge-api/pkcs12/export",
        data={"pfx_passphrase": "protected-test-passphrase"},
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "private_key_file": ("private-key.pem", key_pem),
        },
    )

    assert exported.status_code == 200
    bundle = _decode_file_response(exported.json())
    imported = client.post(
        "/certforge-api/pkcs12/import",
        data={
            "pfx_passphrase": "protected-test-passphrase",
            "private_key_passphrase": "output-key-passphrase",
        },
        files={"pfx_file": ("bundle.p12", bundle)},
    )

    assert imported.status_code == 200
    payload = imported.json()
    assert payload["certificate_count"] == 1
    files = {item["filename"]: _decode_file_response(item) for item in payload["files"]}
    assert x509.load_pem_x509_certificate(files["certificate.pem"])
    restored_key = serialization.load_pem_private_key(
        files["private-key.pem"], password=b"output-key-passphrase"
    )
    original_key = serialization.load_pem_private_key(key_pem, password=None)
    assert crypto_operations.public_key_bytes(restored_key.public_key()) == crypto_operations.public_key_bytes(
        original_key.public_key()
    )


def test_pkcs12_rejects_wrong_passphrase(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, key_pem = issued_certificate
    exported = client.post(
        "/certforge-api/pkcs12/export",
        data={"pfx_passphrase": "correct-passphrase"},
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "private_key_file": ("private-key.pem", key_pem),
        },
    )
    bundle = _decode_file_response(exported.json())

    response = client.post(
        "/certforge-api/pkcs12/import",
        data={"pfx_passphrase": "incorrect-passphrase"},
        files={"pfx_file": ("bundle.p12", bundle)},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "pkcs12_invalid"
    assert "incorrect-passphrase" not in response.text


def test_invalid_certificate_returns_structured_error() -> None:
    response = client.post(
        "/certforge-api/certificates/inspect",
        files={"certificate_file": ("bad.pem", b"not a certificate")},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "certificate_invalid"


def test_pkcs12_export_refuses_mismatched_key(
    issued_certificate: tuple[bytes, bytes],
) -> None:
    certificate_pem, _ = issued_certificate
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key_pem = wrong_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    response = client.post(
        "/certforge-api/pkcs12/export",
        files={
            "certificate_file": ("certificate.pem", certificate_pem),
            "private_key_file": ("private-key.pem", wrong_key_pem),
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "key_mismatch"


def test_uploaded_files_are_removed_after_openssl_work(
    issued_certificate: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate_pem, _ = issued_certificate
    observed_paths: list[Path] = []
    original_run = crypto_operations.run_openssl

    def capture_paths(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        for value in args:
            if isinstance(value, list):
                observed_paths.extend(
                    Path(item) for item in value if isinstance(item, str) and item.startswith("/tmp/certforge-")
                )
        return original_run(*args, **kwargs)

    monkeypatch.setattr(crypto_operations, "run_openssl", capture_paths)
    response = client.post(
        "/certforge-api/certificates/convert",
        data={"input_format": "PEM", "target_format": "DER"},
        files={"certificate_file": ("certificate.pem", certificate_pem)},
    )

    assert response.status_code == 200
    assert observed_paths
    assert all(not path.exists() for path in observed_paths)
