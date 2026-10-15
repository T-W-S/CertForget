import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


KeyAlgorithm = Literal[
    "RSA-2048",
    "RSA-3072",
    "RSA-4096",
    "ECDSA-P256",
    "ECDSA-P384",
    "Ed25519",
]
CertificatePurpose = Literal["tls-server", "tls-client", "smime", "general"]
OutputFormat = Literal["PEM", "DER"]


def _validate_dns_name(value: str, *, allow_wildcard: bool) -> None:
    if not value.isascii() or len(value) > 253 or value.endswith("."):
        raise ValueError("Enter a valid ASCII DNS name without a trailing dot.")
    name = value
    if value.startswith("*.") and allow_wildcard:
        name = value[2:]
    elif "*" in value:
        raise ValueError("A wildcard is only valid as the first DNS label.")
    labels = name.split(".")
    if not labels or any(
        not label
        or len(label) > 63
        or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label
        )
        for label in labels
    ):
        raise ValueError("Enter a valid DNS name; labels cannot start or end with a hyphen.")


def _validate_email(value: str) -> None:
    if not value.isascii() or len(value) > 254 or value.count("@") != 1:
        raise ValueError("Enter a valid ASCII email address.")
    local_part, domain = value.rsplit("@", 1)
    if (
        not local_part
        or len(local_part) > 64
        or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local_part)
    ):
        raise ValueError("Enter a valid email address.")
    _validate_dns_name(domain, allow_wildcard=False)


class CertificateSubjectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    common_name: str | None = Field(default=None, max_length=64)
    organization: str | None = Field(default=None, max_length=64)
    organizational_unit: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    state_or_province: str | None = Field(default=None, max_length=128)
    locality: str | None = Field(default=None, max_length=128)
    email_address: str | None = Field(default=None, max_length=254)

    @field_validator(
        "common_name",
        "organization",
        "organizational_unit",
        "country",
        "state_or_province",
        "locality",
        "email_address",
        mode="before",
    )
    @classmethod
    def validate_subject_text(cls, value: object) -> object:
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise ValueError("Subject values must be text.")
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("Remove leading, trailing, or control characters.")
        return value

    @field_validator("country")
    @classmethod
    def validate_country_code(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Z]{2}", value):
            raise ValueError("Use a two-letter uppercase country code.")
        return value

    @field_validator("email_address")
    @classmethod
    def validate_subject_email(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_email(value)
        return value


class SubjectAltNameRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["DNS", "IP", "EMAIL", "URI"]
    value: str = Field(min_length=1, max_length=2048)

    @field_validator("value")
    @classmethod
    def validate_value_characters(cls, value: str) -> str:
        if value != value.strip() or any(
            character.isspace() or ord(character) < 32 for character in value
        ):
            raise ValueError("SAN values cannot contain whitespace or control characters.")
        return value

    @model_validator(mode="after")
    def validate_san_value(self) -> "SubjectAltNameRequest":
        if self.type == "DNS":
            _validate_dns_name(self.value, allow_wildcard=True)
        elif self.type == "IP":
            try:
                ipaddress.ip_address(self.value)
            except ValueError:
                raise ValueError("Enter a valid IPv4 or IPv6 address.") from None
        elif self.type == "EMAIL":
            _validate_email(self.value)
        else:
            if not self.value.isascii() or not re.match(
                r"^[A-Za-z][A-Za-z0-9+.-]*:", self.value
            ):
                raise ValueError("Enter an absolute ASCII URI, including its scheme.")
            try:
                parsed = urlsplit(self.value)
                if not parsed.scheme:
                    raise ValueError("Enter an absolute URI, including its scheme.")
                _ = parsed.port
            except ValueError:
                raise ValueError("Enter a valid absolute URI.") from None
        return self


class KeySourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["generate", "import"] = "generate"
    algorithm: KeyAlgorithm | None = None
    private_key_base64: str | None = Field(default=None, max_length=14_000_000)
    private_key_passphrase: SecretStr | None = None

    @field_validator("private_key_passphrase")
    @classmethod
    def validate_source_passphrase(
        cls, value: SecretStr | None
    ) -> SecretStr | None:
        if value is not None:
            raw = value.get_secret_value()
            if (
                len(raw.encode("utf-8")) > 1024
                or any(ord(character) < 32 for character in raw)
            ):
                raise ValueError("The private-key passphrase is not valid.")
        return value

    @model_validator(mode="after")
    def validate_source(self) -> "KeySourceRequest":
        if self.source == "generate":
            if self.algorithm is None:
                raise ValueError("Select a key algorithm.")
            if self.private_key_base64 is not None or self.private_key_passphrase is not None:
                raise ValueError("Remove imported-key fields when generating a new key.")
        elif not self.private_key_base64:
            raise ValueError("Choose a private-key file to import.")
        elif self.algorithm is not None:
            raise ValueError("An imported key determines its own algorithm.")
        return self


class CertificateCreationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: CertificateSubjectRequest
    sans: list[SubjectAltNameRequest] = Field(default_factory=list, max_length=100)
    key: KeySourceRequest
    purpose: CertificatePurpose
    private_key_export_passphrase: SecretStr = Field(min_length=12, max_length=1024)

    @field_validator("private_key_export_passphrase")
    @classmethod
    def validate_export_passphrase(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if (
            len(raw.encode("utf-8")) > 1024
            or any(ord(character) < 32 for character in raw)
            or not raw.strip()
        ):
            raise ValueError("Use a valid passphrase of at least 12 characters.")
        character_classes = (
            any(character.islower() for character in raw),
            any(character.isupper() for character in raw),
            any(character.isdigit() for character in raw),
            any(not character.isalnum() for character in raw),
        )
        if len(raw) < 12 or (
            len(raw) < 16 and sum(character_classes) < 3
        ):
            raise ValueError(
                "Use at least 16 characters, or at least 12 with three character types."
            )
        return value

    @model_validator(mode="after")
    def validate_identity_and_purpose(self) -> "CertificateCreationRequest":
        subject_values = self.subject.model_dump(exclude_none=True)
        if not subject_values and not self.sans:
            raise ValueError("Provide at least one subject value or SAN.")
        if not self.subject.common_name and not self.sans:
            raise ValueError("Provide a Common Name or at least one SAN.")
        identities = {(san.type, san.value) for san in self.sans}
        if len(identities) != len(self.sans):
            raise ValueError("Remove duplicate SAN entries.")
        if self.purpose == "tls-server" and not any(
            san.type in {"DNS", "IP"} for san in self.sans
        ):
            raise ValueError("TLS server certificates need a DNS or IP SAN.")
        if self.purpose == "tls-client" and not self.sans:
            raise ValueError("TLS certificates need SANs; Common Name alone is not used for identity.")
        if self.purpose == "smime" and not (
            self.subject.email_address
            or any(san.type == "EMAIL" for san in self.sans)
        ):
            raise ValueError("S/MIME certificates need an email address in the subject or SANs.")
        return self


class SelfSignedCertificateRequest(CertificateCreationRequest):
    not_before: datetime
    not_after: datetime
    certificate_format: OutputFormat = "PEM"

    @field_validator("not_before", "not_after")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Certificate dates must include a timezone.")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_validity_window(self) -> "SelfSignedCertificateRequest":
        now = datetime.now(timezone.utc)
        if self.not_after <= now or self.not_after <= self.not_before:
            raise ValueError("Expiry must be in the future and after the start time.")
        if self.not_after - self.not_before > timedelta(days=3650):
            raise ValueError("Certificate validity cannot exceed 10 years.")
        return self


class GenerateCsrRequest(CertificateCreationRequest):
    csr_format: OutputFormat = "PEM"


class CertificateExtensionsResponse(BaseModel):
    key_usage: list[str]
    extended_key_usage: list[str]
    basic_constraints: str | None
    subject_key_identifier: str | None
    authority_key_identifier: str | None


class HealthResponse(BaseModel):
    status: str
    openssl_version: str


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
    extensions: CertificateExtensionsResponse


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


class GeneratedCertificateResponse(BaseModel):
    certificate: FileOutput
    private_key: FileOutput
    inspection: CertificateInspectionResponse
    self_signature_verified: bool


class GeneratedCsrResponse(BaseModel):
    csr: FileOutput
    private_key: FileOutput
    subject: str
    public_key_algorithm: str
    public_key_fingerprint: str
    signature_algorithm: str
    sans: list[str]
    requested_extensions: CertificateExtensionsResponse
    signature_verified: bool
