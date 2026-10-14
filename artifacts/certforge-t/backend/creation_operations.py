from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from api_errors import WorkbenchError
from crypto_operations import (
    MAX_UPLOAD_BYTES,
    file_response,
    format_fingerprint,
    format_name,
    format_sans,
    inspect_certificate_content,
    load_private_key,
    public_key_bytes,
    summarize_extensions,
)
from schemas import (
    CertificateCreationRequest,
    GeneratedCertificateResponse,
    GeneratedCsrResponse,
    GenerateCsrRequest,
    KeySourceRequest,
    SelfSignedCertificateRequest,
    SubjectAltNameRequest,
    CertificateSubjectRequest,
)


_PURPOSE_EKU = {
    "tls-server": ExtendedKeyUsageOID.SERVER_AUTH,
    "tls-client": ExtendedKeyUsageOID.CLIENT_AUTH,
    "smime": ExtendedKeyUsageOID.EMAIL_PROTECTION,
}


def _generate_private_key(algorithm: str) -> Any:
    if algorithm == "RSA-2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algorithm == "RSA-3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if algorithm == "RSA-4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if algorithm == "ECDSA-P256":
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == "ECDSA-P384":
        return ec.generate_private_key(ec.SECP384R1())
    if algorithm == "Ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise WorkbenchError(400, "key_algorithm_unsupported", "Choose a supported key algorithm.")


def _import_private_key(key_source: KeySourceRequest) -> Any:
    encoded = key_source.private_key_base64
    if not encoded:
        raise WorkbenchError(400, "private_key_required", "Choose a private-key file.")
    max_encoded_size = ((MAX_UPLOAD_BYTES + 2) // 3) * 4
    if len(encoded) > max_encoded_size:
        raise WorkbenchError(413, "file_too_large", "The private-key file exceeds the upload limit.")
    try:
        private_key_bytes = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise WorkbenchError(
            400, "private_key_invalid", "The imported private-key file is not valid base64."
        ) from None
    if len(private_key_bytes) > MAX_UPLOAD_BYTES:
        raise WorkbenchError(413, "file_too_large", "The private-key file exceeds the upload limit.")
    passphrase = (
        key_source.private_key_passphrase.get_secret_value().encode("utf-8")
        if key_source.private_key_passphrase is not None
        else None
    )
    return load_private_key(private_key_bytes, passphrase)


def _validate_private_key(private_key: Any) -> str:
    if isinstance(private_key, rsa.RSAPrivateKey):
        if private_key.key_size not in {2048, 3072, 4096}:
            raise WorkbenchError(
                400,
                "key_algorithm_unsupported",
                "Imported RSA keys must be 2048, 3072, or 4096 bits.",
            )
        return f"RSA-{private_key.key_size}"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve_names = {
            "secp256r1": "ECDSA P-256",
            "secp384r1": "ECDSA P-384",
        }
        label = curve_names.get(private_key.curve.name)
        if label is None:
            raise WorkbenchError(
                400,
                "key_algorithm_unsupported",
                "Imported ECDSA keys must use P-256 or P-384.",
            )
        return label
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    raise WorkbenchError(
        400,
        "key_algorithm_unsupported",
        "Use an RSA 2048/3072/4096, ECDSA P-256/P-384, or Ed25519 private key.",
    )


def _private_key_for_request(key_source: KeySourceRequest) -> tuple[Any, str]:
    if key_source.source == "generate":
        if key_source.algorithm is None:
            raise WorkbenchError(400, "key_algorithm_required", "Select a key algorithm.")
        private_key = _generate_private_key(key_source.algorithm)
    else:
        private_key = _import_private_key(key_source)
    return private_key, _validate_private_key(private_key)


def _subject_name(subject: CertificateSubjectRequest) -> x509.Name:
    attributes: list[x509.NameAttribute] = []
    fields = (
        (NameOID.COUNTRY_NAME, subject.country),
        (NameOID.STATE_OR_PROVINCE_NAME, subject.state_or_province),
        (NameOID.LOCALITY_NAME, subject.locality),
        (NameOID.ORGANIZATION_NAME, subject.organization),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizational_unit),
        (NameOID.COMMON_NAME, subject.common_name),
        (NameOID.EMAIL_ADDRESS, subject.email_address),
    )
    for oid, value in fields:
        if value is not None:
            attributes.append(x509.NameAttribute(oid, value))
    return x509.Name(attributes)


def _san_extension(sans: list[SubjectAltNameRequest]) -> x509.SubjectAlternativeName:
    general_names: list[x509.GeneralName] = []
    for san in sans:
        if san.type == "DNS":
            general_names.append(x509.DNSName(san.value))
        elif san.type == "IP":
            general_names.append(x509.IPAddress(ipaddress.ip_address(san.value)))
        elif san.type == "EMAIL":
            general_names.append(x509.RFC822Name(san.value))
        else:
            general_names.append(x509.UniformResourceIdentifier(san.value))
    return x509.SubjectAlternativeName(general_names)


def _requested_key_usage(
    private_key: Any, purpose: str
) -> x509.KeyUsage:
    is_rsa = isinstance(private_key, rsa.RSAPrivateKey)
    key_encipherment = is_rsa and purpose in {"tls-server", "smime"}
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=key_encipherment,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=None,
        decipher_only=None,
    )


def _signing_hash(private_key: Any) -> hashes.HashAlgorithm | None:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return None
    return hashes.SHA256()


def _signature_algorithm_label(signed_object: Any) -> str:
    name = signed_object.signature_algorithm_oid._name or (
        signed_object.signature_algorithm_oid.dotted_string
    )
    try:
        signature_hash = signed_object.signature_hash_algorithm
    except UnsupportedAlgorithm:
        signature_hash = None
    return (
        f"{name} with {signature_hash.name.upper()}"
        if signature_hash is not None
        else name
    )


def _add_request_extensions(
    builder: Any,
    request: CertificateCreationRequest,
    private_key: Any,
) -> Any:
    if request.sans:
        builder = builder.add_extension(
            _san_extension(request.sans),
            critical=not bool(request.subject.model_dump(exclude_none=True)),
        )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        _requested_key_usage(private_key, request.purpose),
        critical=True,
    )
    extended_key_usage = _PURPOSE_EKU.get(request.purpose)
    if extended_key_usage is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([extended_key_usage]),
            critical=False,
        )
    return builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )


def _encrypt_private_key(private_key: Any, passphrase: bytes) -> bytes:
    try:
        return private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise WorkbenchError(
            500,
            "private_key_export_failed",
            "The encrypted private key could not be prepared for download.",
        ) from None


def _export_passphrase(request: CertificateCreationRequest) -> bytes:
    return request.private_key_export_passphrase.get_secret_value().encode("utf-8")


def create_self_signed_certificate(
    request: SelfSignedCertificateRequest,
) -> GeneratedCertificateResponse:
    private_key, _ = _private_key_for_request(request.key)
    subject = _subject_name(request.subject)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(request.not_before.replace(tzinfo=None))
        .not_valid_after(request.not_after.replace(tzinfo=None))
    )
    builder = _add_request_extensions(builder, request, private_key)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            private_key.public_key()
        ),
        critical=False,
    )
    try:
        certificate = builder.sign(private_key, _signing_hash(private_key))
        certificate.verify_directly_issued_by(certificate)
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        raise WorkbenchError(
            500,
            "certificate_generation_failed",
            "The generated certificate could not be verified.",
        ) from None

    encoding = (
        serialization.Encoding.PEM
        if request.certificate_format == "PEM"
        else serialization.Encoding.DER
    )
    certificate_bytes = certificate.public_bytes(encoding)
    private_key_bytes = _encrypt_private_key(private_key, _export_passphrase(request))
    inspection = inspect_certificate_content(certificate_bytes)
    return GeneratedCertificateResponse(
        certificate=file_response(
            f"certificate.{request.certificate_format.lower()}",
            certificate_bytes,
        ),
        private_key=file_response("private-key.encrypted.pem", private_key_bytes),
        inspection=inspection,
        self_signature_verified=True,
    )


def generate_csr(request: GenerateCsrRequest) -> GeneratedCsrResponse:
    private_key, public_key_algorithm = _private_key_for_request(request.key)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        _subject_name(request.subject)
    )
    builder = _add_request_extensions(builder, request, private_key)
    try:
        csr = builder.sign(private_key, _signing_hash(private_key))
        signature_verified = csr.is_signature_valid
    except (ValueError, UnsupportedAlgorithm):
        raise WorkbenchError(
            500,
            "csr_generation_failed",
            "The CSR could not be generated with the selected key.",
        ) from None
    if not signature_verified:
        raise WorkbenchError(
            500,
            "csr_verification_failed",
            "The generated CSR signature could not be verified.",
        )

    encoding = (
        serialization.Encoding.PEM
        if request.csr_format == "PEM"
        else serialization.Encoding.DER
    )
    csr_bytes = csr.public_bytes(encoding)
    public_key_fingerprint = format_fingerprint(
        hashlib.sha256(public_key_bytes(private_key.public_key())).digest()
    )
    return GeneratedCsrResponse(
        csr=file_response(
            f"certificate-request.{request.csr_format.lower()}",
            csr_bytes,
        ),
        private_key=file_response(
            "private-key.encrypted.pem",
            _encrypt_private_key(private_key, _export_passphrase(request)),
        ),
        subject=format_name(csr.subject),
        public_key_algorithm=public_key_algorithm,
        public_key_fingerprint=public_key_fingerprint,
        signature_algorithm=_signature_algorithm_label(csr),
        sans=format_sans(csr.extensions),
        requested_extensions=summarize_extensions(csr.extensions),
        signature_verified=True,
    )
