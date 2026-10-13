from __future__ import annotations

import base64
import hmac
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Literal

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.base import (
    load_der_private_key,
    load_pem_private_key,
)
from fastapi import UploadFile

from api_errors import WorkbenchError

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "10485760"))
OPENSSL_TIMEOUT_SECONDS = int(os.getenv("OPENSSL_TIMEOUT_SECONDS", "10"))
PASSPHRASE_MAX_BYTES = 1024
CERTIFICATE_MAX_BYTES = MAX_UPLOAD_BYTES
PRIVATE_KEY_MAX_BYTES = MAX_UPLOAD_BYTES
PEM_CERTIFICATE_MARKER = b"-----BEGIN CERTIFICATE-----"
OPENSSL_EXECUTABLE = shutil.which("openssl")


async def read_upload(
    upload: UploadFile, field_name: str, maximum_bytes: int
) -> bytes:
    try:
        contents = await upload.read(maximum_bytes + 1)
    finally:
        await upload.close()
    if not contents:
        raise WorkbenchError(400, "empty_file", f"{field_name} must not be empty.")
    if len(contents) > maximum_bytes:
        raise WorkbenchError(
            413,
            "file_too_large",
            f"{field_name} exceeds the {maximum_bytes // (1024 * 1024)} MB upload limit.",
        )
    return contents


def load_certificate(contents: bytes) -> x509.Certificate:
    try:
        if PEM_CERTIFICATE_MARKER in contents:
            return x509.load_pem_x509_certificate(contents)
        return x509.load_der_x509_certificate(contents)
    except (ValueError, UnsupportedAlgorithm):
        raise WorkbenchError(
            400,
            "certificate_invalid",
            "The uploaded file is not a valid PEM or DER X.509 certificate.",
        ) from None


def load_private_key(contents: bytes, passphrase: bytes | None) -> Any:
    try:
        if b"-----BEGIN" in contents:
            return load_pem_private_key(contents, password=passphrase)
        return load_der_private_key(contents, password=passphrase)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise WorkbenchError(
            400,
            "private_key_invalid",
            "The private key is invalid or its passphrase is incorrect.",
        ) from None


def load_public_key(contents: bytes) -> Any:
    try:
        if b"-----BEGIN" in contents:
            return serialization.load_pem_public_key(contents)
        return serialization.load_der_public_key(contents)
    except (ValueError, UnsupportedAlgorithm):
        raise WorkbenchError(
            400,
            "public_key_invalid",
            "The uploaded file is not a valid PEM or DER SubjectPublicKeyInfo public key.",
        ) from None


def load_pkcs12(
    contents: bytes, passphrase: bytes | None
) -> tuple[Any | None, x509.Certificate | None, list[x509.Certificate] | None]:
    try:
        return pkcs12.load_key_and_certificates(contents, passphrase)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise WorkbenchError(
            400,
            "pkcs12_invalid",
            "The PKCS#12 file is invalid or its passphrase is incorrect.",
        ) from None


def validated_passphrase(value: str | None) -> bytes | None:
    if value is None or value == "":
        return None
    encoded = value.encode("utf-8")
    if (
        len(encoded) > PASSPHRASE_MAX_BYTES
        or b"\n" in encoded
        or b"\r" in encoded
        or b"\0" in encoded
    ):
        raise WorkbenchError(
            400,
            "passphrase_invalid",
            "Passphrases must be at most 1024 bytes and must not contain line breaks.",
        )
    return encoded


def format_name(name: x509.Name) -> str:
    return ", ".join(
        f"{attribute.oid._name or attribute.oid.dotted_string}={attribute.value}"
        for attribute in name
    )


def key_details(public_key: object) -> tuple[str, int | None]:
    key_name = type(public_key).__name__
    if key_name == "_RSAPublicKey":
        return "RSA", getattr(public_key, "key_size", None)
    if key_name == "_DSAPublicKey":
        return "DSA", getattr(public_key, "key_size", None)
    if key_name == "_EllipticCurvePublicKey":
        return f"EC ({public_key.curve.name})", getattr(public_key, "key_size", None)
    if key_name == "_Ed25519PublicKey":
        return "Ed25519", None
    if key_name == "_Ed448PublicKey":
        return "Ed448", None
    if key_name == "_X25519PublicKey":
        return "X25519", None
    if key_name == "_X448PublicKey":
        return "X448", None
    return key_name.removeprefix("_").removesuffix("PublicKey"), getattr(
        public_key, "key_size", None
    )


def public_key_bytes(public_key: object) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def file_response(filename: str, contents: bytes) -> dict[str, object]:
    return {
        "filename": filename,
        "media_type": media_type_for(filename),
        "content_base64": base64.b64encode(contents).decode("ascii"),
        "size_bytes": len(contents),
    }


def media_type_for(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix in {".p12", ".pfx"}:
        return "application/x-pkcs12"
    if suffix == ".der":
        return "application/pkix-cert"
    if suffix == ".pem":
        return "application/x-pem-file"
    return "application/octet-stream"


def openssl_version() -> str:
    if OPENSSL_EXECUTABLE is None:
        raise WorkbenchError(
            503, "openssl_unavailable", "OpenSSL is not installed on the server."
        )
    try:
        result = subprocess.run(
            [OPENSSL_EXECUTABLE, "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=OPENSSL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise WorkbenchError(
            503, "openssl_unavailable", "OpenSSL is not available on the server."
        ) from None
    if result.returncode != 0:
        raise WorkbenchError(
            503, "openssl_unavailable", "OpenSSL is not available on the server."
        )
    return result.stdout.strip()


def run_openssl(
    arguments: list[str],
    *,
    pass_in: bytes | None = None,
    pass_out: bytes | None = None,
    error_code: str = "openssl_operation_failed",
    error_message: str = "OpenSSL could not complete this operation.",
) -> subprocess.CompletedProcess[bytes]:
    if OPENSSL_EXECUTABLE is None:
        raise WorkbenchError(
            503, "openssl_unavailable", "OpenSSL is not installed on the server."
        )
    command = [OPENSSL_EXECUTABLE, *arguments]
    read_descriptors: list[int] = []
    write_descriptors: list[int] = []
    pass_fds: list[int] = []
    try:
        for option, secret in (("-passin", pass_in), ("-passout", pass_out)):
            if secret is None:
                continue
            read_fd, write_fd = os.pipe()
            read_descriptors.append(read_fd)
            write_descriptors.append(write_fd)
            pass_fds.append(read_fd)
            command.extend([option, f"fd:{read_fd}"])
            os.write(write_fd, secret + b"\n")
            os.close(write_fd)
            write_descriptors[-1] = -1
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=OPENSSL_TIMEOUT_SECONDS,
            check=False,
            pass_fds=tuple(pass_fds),
        )
    except subprocess.TimeoutExpired:
        raise WorkbenchError(
            408, "openssl_timeout", "OpenSSL did not finish within the time limit."
        ) from None
    except OSError:
        raise WorkbenchError(
            503, "openssl_unavailable", "OpenSSL could not be started."
        ) from None
    finally:
        for descriptor in read_descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        for descriptor in write_descriptors:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    if result.returncode != 0:
        raise WorkbenchError(400, error_code, error_message)
    return result


@contextmanager
def private_temp_dir() -> Iterator[Path]:
    previous_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="certforge-") as temp_dir:
            directory = Path(temp_dir)
            os.chmod(directory, 0o700)
            yield directory
    finally:
        os.umask(previous_umask)


def write_private_file(directory: Path, filename: str, contents: bytes) -> Path:
    path = directory / filename
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file_handle:
        file_handle.write(contents)
    return path


def convert_certificate_with_openssl(
    contents: bytes,
    input_format: Literal["PEM", "DER"],
    target_format: Literal["PEM", "DER"],
) -> bytes:
    with private_temp_dir() as directory:
        input_path = write_private_file(directory, "input-certificate", contents)
        output_path = directory / "output-certificate"
        run_openssl(
            [
                "x509",
                "-inform",
                input_format,
                "-in",
                str(input_path),
                "-outform",
                target_format,
                "-out",
                str(output_path),
            ],
            error_code="certificate_format_mismatch",
            error_message=(
                f"OpenSSL could not read this file as {input_format}. "
                "Choose the correct input format."
            ),
        )
        return output_path.read_bytes()


def confirm_openssl_certificate_read(contents: bytes) -> None:
    input_format = "PEM" if PEM_CERTIFICATE_MARKER in contents else "DER"
    with private_temp_dir() as directory:
        certificate_path = write_private_file(directory, "certificate", contents)
        run_openssl(
            [
                "x509",
                "-inform",
                input_format,
                "-in",
                str(certificate_path),
                "-noout",
                "-fingerprint",
                "-sha256",
            ],
            error_code="certificate_invalid",
            error_message="OpenSSL could not read this certificate.",
        )


def confirm_openssl_key_read(
    certificate_bytes: bytes,
    key_bytes: bytes,
    passphrase: bytes | None,
    key_kind: Literal["private", "public"],
) -> bool:
    with private_temp_dir() as directory:
        certificate_path = write_private_file(directory, "certificate", certificate_bytes)
        key_path = write_private_file(directory, "uploaded-key", key_bytes)
        certificate_format = (
            "PEM" if PEM_CERTIFICATE_MARKER in certificate_bytes else "DER"
        )
        key_format = "PEM" if b"-----BEGIN" in key_bytes else "DER"
        certificate_public = run_openssl(
            [
                "x509",
                "-inform",
                certificate_format,
                "-in",
                str(certificate_path),
                "-pubkey",
                "-noout",
            ],
            error_code="certificate_invalid",
            error_message="OpenSSL could not read this certificate.",
        ).stdout
        if key_kind == "private":
            key_arguments = [
                "pkey",
                "-inform",
                key_format,
                "-in",
                str(key_path),
                "-pubout",
            ]
            passphrase_input = passphrase or b""
            key_error_code = "private_key_invalid"
            key_error_message = (
                "OpenSSL could not read this private key or its passphrase is incorrect."
            )
        else:
            key_arguments = [
                "pkey",
                "-pubin",
                "-inform",
                key_format,
                "-in",
                str(key_path),
                "-pubout",
            ]
            passphrase_input = None
            key_error_code = "public_key_invalid"
            key_error_message = "OpenSSL could not read this public key."
        key_public = run_openssl(
            key_arguments,
            pass_in=passphrase_input,
            error_code=key_error_code,
            error_message=key_error_message,
        ).stdout
        try:
            certificate_public_key = serialization.load_pem_public_key(certificate_public)
            uploaded_public_key = serialization.load_pem_public_key(key_public)
        except (ValueError, UnsupportedAlgorithm):
            raise WorkbenchError(
                400, "public_key_invalid", "OpenSSL could not derive the public keys."
            ) from None
        return hmac.compare_digest(
            public_key_bytes(certificate_public_key),
            public_key_bytes(uploaded_public_key),
        )


def export_pkcs12_with_openssl(
    certificate_bytes: bytes,
    private_key_bytes: bytes,
    private_key_passphrase: bytes | None,
    pfx_passphrase: bytes | None,
) -> bytes:
    with private_temp_dir() as directory:
        certificate_path = write_private_file(
            directory, "certificate.pem", certificate_bytes
        )
        key_path = write_private_file(directory, "private-key.pem", private_key_bytes)
        output_path = directory / "certificate-bundle.p12"
        run_openssl(
            [
                "pkcs12",
                "-export",
                "-in",
                str(certificate_path),
                "-inkey",
                str(key_path),
                "-out",
                str(output_path),
                "-name",
                "CertForge_t certificate",
            ],
            pass_in=private_key_passphrase or b"",
            pass_out=pfx_passphrase or b"",
            error_code="pkcs12_export_failed",
            error_message=(
                "OpenSSL could not export this certificate and private key. "
                "Check the private-key passphrase and file formats."
            ),
        )
        return output_path.read_bytes()


def extract_pkcs12_with_openssl(
    contents: bytes, passphrase: bytes | None
) -> None:
    with private_temp_dir() as directory:
        pfx_path = write_private_file(directory, "input.p12", contents)
        run_openssl(
            ["pkcs12", "-in", str(pfx_path), "-nodes"],
            pass_in=passphrase or b"",
            error_code="pkcs12_invalid",
            error_message="OpenSSL could not read this PKCS#12 file or its passphrase is incorrect.",
        )
