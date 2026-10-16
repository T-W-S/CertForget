from __future__ import annotations

import base64
import hashlib
import ipaddress
import io
import json
import logging
import shutil
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from api_errors import WorkbenchError
from creation_operations import verify_certificate_key_pair
import main
from crypto_operations import public_key_bytes

client = TestClient(main.app)
_OUTPUT_PASSPHRASE = "test-only-output-passphrase"


def _self_signed_request(
    *,
    algorithm: str = "RSA-3072",
    certificate_format: str = "PEM",
    purpose: str = "tls-server",
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "subject": {
            "common_name": "service.example.test",
            "organization": "CertForge Test",
            "organizational_unit": None,
            "country": "GB",
            "state_or_province": None,
            "locality": None,
            "email_address": None,
        },
        "sans": [
            {"type": "DNS", "value": "service.example.test"},
            {"type": "IP", "value": "192.0.2.10"},
            {"type": "EMAIL", "value": "cert@example.test"},
            {"type": "URI", "value": "spiffe://example.test/service"},
        ],
        "key": {"source": "generate", "algorithm": algorithm},
        "purpose": purpose,
        "private_key_export_passphrase": _OUTPUT_PASSPHRASE,
        "not_before": (now - timedelta(minutes=5)).isoformat(),
        "not_after": (now + timedelta(days=365)).isoformat(),
        "certificate_format": certificate_format,
    }


def _csr_request(
    *,
    algorithm: str = "RSA-3072",
    csr_format: str = "PEM",
    purpose: str = "tls-server",
) -> dict[str, Any]:
    body = _self_signed_request(algorithm=algorithm, purpose=purpose)
    body.pop("not_before")
    body.pop("not_after")
    body.pop("certificate_format")
    body["csr_format"] = csr_format
    return body


def _decode_file(payload: dict[str, Any]) -> bytes:
    return base64.b64decode(payload["content_base64"], validate=True)


def _load_certificate(payload: dict[str, Any]) -> x509.Certificate:
    contents = _decode_file(payload)
    if payload["filename"].endswith(".der"):
        return x509.load_der_x509_certificate(contents)
    return x509.load_pem_x509_certificate(contents)


def _load_csr(payload: dict[str, Any]) -> x509.CertificateSigningRequest:
    contents = _decode_file(payload)
    if payload["filename"].endswith(".der"):
        return x509.load_der_x509_csr(contents)
    return x509.load_pem_x509_csr(contents)


@pytest.mark.parametrize(
    ("algorithm", "expected_key_type"),
    [
        ("RSA-2048", rsa.RSAPublicKey),
        ("RSA-3072", rsa.RSAPublicKey),
        ("RSA-4096", rsa.RSAPublicKey),
        ("ECDSA-P256", ec.EllipticCurvePublicKey),
        ("ECDSA-P384", ec.EllipticCurvePublicKey),
        ("Ed25519", ed25519.Ed25519PublicKey),
    ],
)
def test_self_signed_certificate_profiles_and_encrypted_keys(
    algorithm: str, expected_key_type: type[object]
) -> None:
    response = client.post(
        "/certforge-api/certificates/self-signed",
        json=_self_signed_request(algorithm=algorithm),
    )
    assert response.status_code == 200, response.text
    result = response.json()
    certificate = _load_certificate(result["certificate"])
    private_key_bytes = _decode_file(result["private_key"])
    private_key = serialization.load_pem_private_key(
        private_key_bytes, password=_OUTPUT_PASSPHRASE.encode()
    )

    assert isinstance(certificate.public_key(), expected_key_type)
    assert certificate.subject == certificate.issuer
    certificate.verify_directly_issued_by(certificate)
    assert certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key_bytes(private_key.public_key())
    assert result["self_signature_verified"] is True
    assert result["private_key"]["filename"] == "private-key.encrypted.pem"
    assert "private_key_export_passphrase" not in json.dumps(result)
    assert _OUTPUT_PASSPHRASE not in json.dumps(result)

    subject = certificate.subject
    assert subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "service.example.test"
    )
    assert subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == (
        "CertForge Test"
    )
    sans = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert set(sans.get_values_for_type(x509.DNSName)) == {"service.example.test"}
    assert set(sans.get_values_for_type(x509.IPAddress)) == {
        ipaddress.ip_address("192.0.2.10")
    }
    constraints = certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    assert constraints.ca is False
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature is True
    assert usage.key_encipherment is isinstance(private_key, rsa.RSAPrivateKey)
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert result["inspection"]["extensions"]["basic_constraints"] == "CA:FALSE"
    assert result["inspection"]["sans"] == [
        "DNS:service.example.test",
        "EMAIL:cert@example.test",
        "IP:192.0.2.10",
        "URI:spiffe://example.test/service",
    ]
    assert result["inspection"]["not_before"] == certificate.not_valid_before_utc.isoformat()
    assert result["inspection"]["not_after"] == certificate.not_valid_after_utc.isoformat()


def test_certificate_zip_contains_pem_certificate_and_encrypted_matching_key() -> None:
    response = client.post(
        "/certforge-api/certificates/self-signed",
        json=_self_signed_request(),
    )
    assert response.status_code == 200, response.text
    result = response.json()
    archive_bytes = _decode_file(result["archive"])

    assert result["archive"]["filename"] == "certificate-and-private-key.zip"
    assert result["archive"]["media_type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        assert archive.namelist() == [
            "certificate.pem",
            "private-key.encrypted.pem",
        ]
        certificate_pem = archive.read("certificate.pem")
        encrypted_private_key = archive.read("private-key.encrypted.pem")

    assert certificate_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    assert encrypted_private_key.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password=_OUTPUT_PASSPHRASE.encode(),
    )
    assert public_key_bytes(certificate.public_key()) == public_key_bytes(
        private_key.public_key()
    )
    with pytest.raises(ValueError):
        serialization.load_pem_private_key(
            encrypted_private_key,
            password=b"incorrect-output-passphrase",
        )
    assert _OUTPUT_PASSPHRASE.encode() not in archive_bytes

    inspected_response = client.post(
        "/certforge-api/certificates/inspect",
        files={"certificate_file": ("certificate.pem", certificate_pem, "application/x-pem-file")},
    )
    assert inspected_response.status_code == 200, inspected_response.text
    inspected = inspected_response.json()
    for field in (
        "subject",
        "issuer",
        "serial_number",
        "not_before",
        "not_after",
        "sha256_fingerprint",
    ):
        assert inspected[field] == result["inspection"][field]

    openssl = shutil.which("openssl")
    if openssl:
        openssl_result = subprocess.run(
            [openssl, "x509", "-noout", "-subject", "-issuer", "-dates"],
            input=certificate_pem,
            capture_output=True,
            check=True,
        )
        assert b"subject=" in openssl_result.stdout
        assert b"issuer=" in openssl_result.stdout


def test_der_certificate_generation_also_returns_pem_for_download_and_zip() -> None:
    response = client.post(
        "/certforge-api/certificates/self-signed",
        json=_self_signed_request(certificate_format="DER"),
    )
    assert response.status_code == 200, response.text
    result = response.json()

    assert result["certificate"]["filename"] == "certificate.der"
    assert result["certificate_pem"]["filename"] == "certificate.pem"
    certificate_der = _decode_file(result["certificate"])
    certificate_pem = _decode_file(result["certificate_pem"])
    assert not certificate_der.startswith(b"-----BEGIN")
    assert certificate_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    der_certificate = x509.load_der_x509_certificate(certificate_der)
    pem_certificate = x509.load_pem_x509_certificate(certificate_pem)
    assert der_certificate.fingerprint(hashes.SHA256()) == pem_certificate.fingerprint(
        hashes.SHA256()
    )

    with zipfile.ZipFile(io.BytesIO(_decode_file(result["archive"]))) as archive:
        assert archive.read("certificate.pem") == certificate_pem


def test_certificate_private_key_mismatch_raises_structured_error() -> None:
    certificate_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    unrelated_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mismatch.example.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(certificate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(certificate_key, hashes.SHA256())
    )

    with pytest.raises(WorkbenchError) as error:
        verify_certificate_key_pair(certificate, unrelated_key)

    assert error.value.status_code == 500
    assert error.value.code == "certificate_key_mismatch"
    assert "private key" in error.value.message


def test_certificate_generation_does_not_log_key_artifacts_or_passphrase(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/certforge-api/certificates/self-signed",
            json=_self_signed_request(),
        )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["private_key"]["content_base64"] not in caplog.text
    assert result["archive"]["content_base64"] not in caplog.text
    assert _OUTPUT_PASSPHRASE not in caplog.text


@pytest.mark.parametrize(("algorithm", "output_format"), [("RSA-2048", "DER"), ("Ed25519", "PEM")])
def test_self_signed_certificate_supports_pem_and_der(
    algorithm: str, output_format: str
) -> None:
    response = client.post(
        "/certforge-api/certificates/self-signed",
        json=_self_signed_request(
            algorithm=algorithm, certificate_format=output_format
        ),
    )
    assert response.status_code == 200, response.text
    assert response.json()["certificate"]["filename"].endswith(
        f".{output_format.lower()}"
    )
    assert _load_certificate(response.json()["certificate"]).issuer == (
        _load_certificate(response.json()["certificate"]).subject
    )


@pytest.mark.parametrize(
    ("purpose", "expected_eku", "rsa_key_encipherment"),
    [
        ("tls-client", ExtendedKeyUsageOID.CLIENT_AUTH, False),
        ("smime", ExtendedKeyUsageOID.EMAIL_PROTECTION, True),
        ("general", None, False),
    ],
)
def test_certificate_purpose_profiles_set_usage_and_eku(
    purpose: str,
    expected_eku: x509.ObjectIdentifier | None,
    rsa_key_encipherment: bool,
) -> None:
    response = client.post(
        "/certforge-api/certificates/self-signed",
        json=_self_signed_request(algorithm="RSA-2048", purpose=purpose),
    )
    assert response.status_code == 200, response.text
    result = response.json()
    certificate = _load_certificate(result["certificate"])
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature is True
    assert usage.key_encipherment is rsa_key_encipherment
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    try:
        extended_key_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        extended_key_usage = None
    if expected_eku is None:
        assert extended_key_usage is None
    else:
        assert extended_key_usage is not None
        assert expected_eku in extended_key_usage
    assert result["self_signature_verified"] is True


@pytest.mark.parametrize(
    "algorithm",
    ["RSA-3072", "ECDSA-P256", "Ed25519"],
)
def test_csr_signature_extensions_and_matching_private_key(algorithm: str) -> None:
    response = client.post(
        "/certforge-api/csrs/generate",
        json=_csr_request(algorithm=algorithm),
    )
    assert response.status_code == 200, response.text
    result = response.json()
    csr = _load_csr(result["csr"])
    private_key = serialization.load_pem_private_key(
        _decode_file(result["private_key"]),
        password=_OUTPUT_PASSPHRASE.encode(),
    )

    assert csr.is_signature_valid is True
    assert public_key_bytes(csr.public_key()) == public_key_bytes(
        private_key.public_key()
    )
    assert result["signature_verified"] is True
    assert result["subject"] == (
        "countryName=GB, organizationName=CertForge Test, "
        "commonName=service.example.test"
    )
    assert result["public_key_fingerprint"] == ":".join(
        f"{value:02X}"
        for value in hashlib.sha256(public_key_bytes(csr.public_key())).digest()
    )
    sans = csr.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert "service.example.test" in sans.get_values_for_type(x509.DNSName)
    assert "issuer" not in result
    assert "not_before" not in result
    assert result["requested_extensions"]["basic_constraints"] == "CA:FALSE"
    assert "private-key" not in result["csr"]["filename"]


def test_csr_supports_der_output() -> None:
    response = client.post(
        "/certforge-api/csrs/generate",
        json=_csr_request(algorithm="ECDSA-P256", csr_format="DER"),
    )
    assert response.status_code == 200, response.text
    assert response.json()["csr"]["filename"].endswith(".der")
    assert _load_csr(response.json()["csr"]).is_signature_valid


def test_imported_private_key_is_reexported_encrypted_and_used() -> None:
    original_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    source_password = b"test-only-source-passphrase"
    source_pem = original_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(source_password),
    )
    body = _self_signed_request()
    body["key"] = {
        "source": "import",
        "algorithm": None,
        "private_key_base64": base64.b64encode(source_pem).decode("ascii"),
        "private_key_passphrase": source_password.decode("ascii"),
    }
    response = client.post(
        "/certforge-api/certificates/self-signed",
        json=body,
    )
    assert response.status_code == 200, response.text
    result = response.json()
    certificate = _load_certificate(result["certificate"])
    restored_key = serialization.load_pem_private_key(
        _decode_file(result["private_key"]),
        password=_OUTPUT_PASSPHRASE.encode(),
    )
    assert public_key_bytes(certificate.public_key()) == public_key_bytes(
        restored_key.public_key()
    )
    assert public_key_bytes(certificate.public_key()) == public_key_bytes(
        original_key.public_key()
    )


@pytest.mark.parametrize(
    "body",
    [
        _self_signed_request(purpose="tls-server")
        | {"sans": [{"type": "EMAIL", "value": "person@example.test"}]},
        _self_signed_request()
        | {"sans": [{"type": "DNS", "value": "not a DNS name"}]},
        _self_signed_request()
        | {"subject": {"common_name": "bad\nname", "country": "GB"}},
        _self_signed_request()
        | {"subject": {"common_name": "service.example.test", "country": "gb"}},
    ],
)
def test_invalid_subject_and_sans_are_rejected_without_echoing_inputs(
    body: dict[str, Any],
) -> None:
    response = client.post("/certforge-api/certificates/self-signed", json=body)
    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "validation_error"
    assert body["private_key_export_passphrase"] not in response.text
    assert "bad\nname" not in response.text


def test_certificate_rejects_invalid_validity_period() -> None:
    body = _self_signed_request()
    body["not_after"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    response = client.post("/certforge-api/certificates/self-signed", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_certificate_requires_long_export_passphrase() -> None:
    body = _self_signed_request()
    body["private_key_export_passphrase"] = "too-short"
    response = client.post("/certforge-api/certificates/self-signed", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "too-short" not in response.text


def test_csr_rejects_invalid_base64_and_wrong_import_passphrase() -> None:
    bad_base64 = _csr_request()
    bad_base64["key"] = {
        "source": "import",
        "algorithm": None,
        "private_key_base64": "not base64!",
    }
    response = client.post("/certforge-api/csrs/generate", json=bad_base64)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "private_key_invalid"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"test-only-source-passphrase"),
    )
    wrong_passphrase = _csr_request()
    wrong_passphrase["key"] = {
        "source": "import",
        "algorithm": None,
        "private_key_base64": base64.b64encode(encrypted_key).decode("ascii"),
        "private_key_passphrase": "incorrect-test-passphrase",
    }
    response = client.post("/certforge-api/csrs/generate", json=wrong_passphrase)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "private_key_invalid"
    assert "incorrect-test-passphrase" not in response.text


def test_openapi_declares_named_creation_request_and_response_schemas() -> None:
    openapi = client.get("/certforge-api/openapi.json").json()
    components = openapi["components"]["schemas"]
    assert "SelfSignedCertificateRequest" in components
    assert "GenerateCsrRequest" in components
    assert "GeneratedCertificateResponse" in components
    assert "GeneratedCsrResponse" in components
    assert (
        "/certforge-api/certificates/self-signed" in openapi["paths"]
    )
    assert "/certforge-api/csrs/generate" in openapi["paths"]
