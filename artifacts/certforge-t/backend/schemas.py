from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    openssl_version: str


class CertificateInspectionResponse(BaseModel):
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    is_valid_now: bool
    days_until_expiry: int
    sans: list[str]
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int | None
    sha256_fingerprint: str
    openssl_version: str


class KeyMatchResponse(BaseModel):
    matches: bool
    certificate_fingerprint: str
    certificate_public_key_algorithm: str
    key_kind: Literal["private", "public"]
    uploaded_key_algorithm: str
    message: str


class FileOutput(BaseModel):
    filename: str
    media_type: str
    content_base64: str
    size_bytes: int


class Pkcs12ImportResponse(BaseModel):
    files: list[FileOutput]
    certificate_count: int
