from __future__ import annotations

import hmac
from typing import Literal

from cryptography.hazmat.primitives import hashes
from fastapi import APIRouter, File, Form, UploadFile
from starlette.concurrency import run_in_threadpool

from api_errors import WorkbenchError
from crypto_operations import (
    CERTIFICATE_MAX_BYTES,
    PASSPHRASE_MAX_BYTES,
    PRIVATE_KEY_MAX_BYTES,
    confirm_openssl_certificate_read,
    confirm_openssl_key_read,
    convert_certificate_with_openssl,
    file_response,
    inspect_certificate_content,
    key_details,
    load_certificate,
    load_private_key,
    load_public_key,
    public_key_bytes,
    read_upload,
    validated_passphrase,
)
from creation_operations import create_self_signed_certificate
from schemas import (
    CertificateInspectionResponse,
    FileOutput,
    GeneratedCertificateResponse,
    KeyMatchResponse,
    SelfSignedCertificateRequest,
)

router = APIRouter(prefix="/certforge-api/certificates", tags=["certificates"])


@router.post("/inspect", response_model=CertificateInspectionResponse)
async def inspect_certificate(
    certificate_file: UploadFile = File(...),
) -> CertificateInspectionResponse:
    certificate_bytes = await read_upload(
        certificate_file, "certificate_file", CERTIFICATE_MAX_BYTES
    )
    return inspect_certificate_content(certificate_bytes)


@router.post("/self-signed", response_model=GeneratedCertificateResponse)
async def create_self_signed(
    request: SelfSignedCertificateRequest,
) -> GeneratedCertificateResponse:
    return await run_in_threadpool(create_self_signed_certificate, request)


@router.post("/match", response_model=KeyMatchResponse)
async def match_certificate_and_key(
    certificate_file: UploadFile = File(...),
    private_key_file: UploadFile | None = File(default=None),
    public_key_file: UploadFile | None = File(default=None),
    private_key_passphrase: str | None = Form(
        default=None, max_length=PASSPHRASE_MAX_BYTES
    ),
) -> KeyMatchResponse:
    if (private_key_file is None) == (public_key_file is None):
        raise WorkbenchError(
            400,
            "key_file_required",
            "Upload either a private key or a public key, not both.",
        )
    certificate_bytes = await read_upload(
        certificate_file, "certificate_file", CERTIFICATE_MAX_BYTES
    )
    passphrase = validated_passphrase(private_key_passphrase)
    certificate = load_certificate(certificate_bytes)
    if private_key_file is not None:
        key_bytes = await read_upload(
            private_key_file, "private_key_file", PRIVATE_KEY_MAX_BYTES
        )
        key = load_private_key(key_bytes, passphrase)
        uploaded_public_key = key.public_key()
        key_kind: Literal["private", "public"] = "private"
    else:
        if passphrase is not None:
            raise WorkbenchError(
                400,
                "passphrase_not_applicable",
                "A passphrase is only used when uploading an encrypted private key.",
            )
        assert public_key_file is not None
        key_bytes = await read_upload(
            public_key_file, "public_key_file", PRIVATE_KEY_MAX_BYTES
        )
        uploaded_public_key = load_public_key(key_bytes)
        key_kind = "public"

    certificate_public_key = certificate.public_key()
    openssl_matches = confirm_openssl_key_read(
        certificate_bytes, key_bytes, passphrase, key_kind
    )
    matches = hmac.compare_digest(
        public_key_bytes(certificate_public_key),
        public_key_bytes(uploaded_public_key),
    ) and openssl_matches
    certificate_key_type, _ = key_details(certificate_public_key)
    uploaded_key_type, _ = key_details(uploaded_public_key)
    return KeyMatchResponse(
        matches=matches,
        key_kind=key_kind,
        certificate_fingerprint=":".join(
            f"{byte:02X}" for byte in certificate.fingerprint(hashes.SHA256())
        ),
        certificate_public_key_algorithm=certificate_key_type,
        uploaded_key_algorithm=uploaded_key_type,
        message=(
            "The certificate and private key match."
            if matches and key_kind == "private"
            else "The certificate and public key match."
            if matches
            else "The certificate and uploaded key do not match."
        ),
    )


@router.post("/convert", response_model=FileOutput)
async def convert_certificate(
    certificate_file: UploadFile = File(...),
    input_format: Literal["PEM", "DER"] = Form(...),
    target_format: Literal["PEM", "DER"] = Form(...),
) -> FileOutput:
    certificate_bytes = await read_upload(
        certificate_file, "certificate_file", CERTIFICATE_MAX_BYTES
    )
    load_certificate(certificate_bytes)
    output_bytes = convert_certificate_with_openssl(
        certificate_bytes, input_format, target_format
    )
    filename = f"certificate.{target_format.lower()}"
    return FileOutput(**file_response(filename, output_bytes))
