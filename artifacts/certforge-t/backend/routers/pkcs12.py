from __future__ import annotations

from fastapi import APIRouter, File, Form, UploadFile
from cryptography.hazmat.primitives import serialization

from api_errors import WorkbenchError
from crypto_operations import (
    CERTIFICATE_MAX_BYTES,
    MAX_UPLOAD_BYTES,
    PASSPHRASE_MAX_BYTES,
    PRIVATE_KEY_MAX_BYTES,
    export_pkcs12_with_openssl,
    extract_pkcs12_with_openssl,
    file_response,
    load_certificate,
    load_pkcs12,
    load_private_key,
    public_key_bytes,
    read_upload,
    validated_passphrase,
)
from schemas import FileOutput, Pkcs12ImportResponse

router = APIRouter(prefix="/certforge-api/pkcs12", tags=["pkcs12"])


@router.post("/export", response_model=FileOutput)
async def export_pkcs12(
    certificate_file: UploadFile = File(...),
    private_key_file: UploadFile = File(...),
    private_key_passphrase: str | None = Form(
        default=None, max_length=PASSPHRASE_MAX_BYTES
    ),
    pfx_passphrase: str | None = Form(
        default=None, max_length=PASSPHRASE_MAX_BYTES
    ),
) -> FileOutput:
    certificate_bytes = await read_upload(
        certificate_file, "certificate_file", CERTIFICATE_MAX_BYTES
    )
    private_key_bytes = await read_upload(
        private_key_file, "private_key_file", PRIVATE_KEY_MAX_BYTES
    )
    key_input_passphrase = validated_passphrase(private_key_passphrase)
    pfx_output_passphrase = validated_passphrase(pfx_passphrase)
    certificate = load_certificate(certificate_bytes)
    private_key = load_private_key(private_key_bytes, key_input_passphrase)
    if public_key_bytes(certificate.public_key()) != public_key_bytes(
        private_key.public_key()
    ):
        raise WorkbenchError(
            400,
            "key_mismatch",
            "The certificate does not match the supplied private key.",
        )

    pfx_bytes = export_pkcs12_with_openssl(
        certificate_bytes,
        private_key_bytes,
        key_input_passphrase,
        pfx_output_passphrase,
    )
    return FileOutput(**file_response("certificate-bundle.p12", pfx_bytes))


@router.post("/import", response_model=Pkcs12ImportResponse)
async def import_pkcs12(
    pfx_file: UploadFile = File(...),
    pfx_passphrase: str | None = Form(
        default=None, max_length=PASSPHRASE_MAX_BYTES
    ),
    private_key_passphrase: str | None = Form(
        default=None, max_length=PASSPHRASE_MAX_BYTES
    ),
) -> Pkcs12ImportResponse:
    pfx_bytes = await read_upload(pfx_file, "pfx_file", MAX_UPLOAD_BYTES)
    pfx_input_passphrase = validated_passphrase(pfx_passphrase)
    key_output_passphrase = validated_passphrase(private_key_passphrase)
    key, certificate, additional_certificates = load_pkcs12(
        pfx_bytes, pfx_input_passphrase
    )
    extract_pkcs12_with_openssl(pfx_bytes, pfx_input_passphrase)
    files: list[FileOutput] = []
    if certificate is not None:
        files.append(
            FileOutput(
                **file_response(
                    "certificate.pem",
                    certificate.public_bytes(serialization.Encoding.PEM),
                )
            )
        )
    for index, chain_certificate in enumerate(additional_certificates or [], start=1):
        files.append(
            FileOutput(
                **file_response(
                    f"chain-{index}.pem",
                    chain_certificate.public_bytes(serialization.Encoding.PEM),
                )
            )
        )
    if key is not None:
        encryption: serialization.KeySerializationEncryption
        if key_output_passphrase:
            encryption = serialization.BestAvailableEncryption(key_output_passphrase)
        else:
            encryption = serialization.NoEncryption()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
        files.append(FileOutput(**file_response("private-key.pem", key_pem)))
    if not files:
        raise WorkbenchError(
            400,
            "pkcs12_empty",
            "This PKCS#12 file does not contain a certificate or private key.",
        )
    return Pkcs12ImportResponse(
        files=files,
        certificate_count=(1 if certificate else 0) + len(additional_certificates or []),
    )
