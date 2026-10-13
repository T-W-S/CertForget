# CertForge_t

CertForge_t is a self-hosted certificate workbench. Its React and TypeScript
interface sends certificate operations to a Python FastAPI backend that uses
OpenSSL and the Python `cryptography` library.

## Run with Docker Compose

Requirements: Docker Engine with the Compose plugin.

```sh
cp .env.example .env
docker compose up --build
```

Open <http://localhost:8080>. To choose another host port, set
`CERTFORGE_PORT` in `.env`. The `.env` file is optional; the documented
defaults are used if it is absent.

Stop the services with `Ctrl+C`, or run `docker compose down` in another
terminal. The app has no database and does not retain uploaded files or
generated results.

## Features

- Live dashboard readiness from the FastAPI/OpenSSL service.
- Inspect PEM or DER X.509 certificates: issuer, subject, serial number,
  validity, days to expiry, SANs, signature/public-key algorithms, and
  SHA-256 fingerprint.
- Compare certificate and private-key public keys. Encrypted private-key
  uploads can be unlocked with a passphrase.
- Convert PEM certificates to DER and DER certificates to PEM.
- Export matching certificate/key pairs to PKCS#12/PFX, or import PFX files
  and download the contained certificate, chain certificates, and private key.
- See the fixed OpenSSL command templates used for supported actions. The
  preview is informational; user-entered command text is never executed.

All uploaded and generated file contents are processed for the request only.
The backend does not save them as application data. Temporary OpenSSL input
files are created with owner-only permissions and removed after the operation.
In Docker, the temporary directory is an in-memory filesystem.

Passphrases are sent only in the HTTPS/local application request body and are
provided to OpenSSL using inherited file descriptors, not command-line
arguments. They and private-key contents are not written to application logs.
For deployment beyond a trusted local network, put the application behind a
TLS-terminating reverse proxy and apply your own access controls.

## Configuration

Copy `.env.example` to `.env` to set:

| Variable | Default | Description |
| --- | --- | --- |
| `CERTFORGE_PORT` | `8080` | Host port for the web interface and API proxy |
| `MAX_UPLOAD_BYTES` | `10485760` | Maximum size of an uploaded file (10 MiB) |
| `OPENSSL_TIMEOUT_SECONDS` | `10` | Maximum run time for an OpenSSL operation |

Do not commit `.env` files or put passphrases in them.

## API

The FastAPI schema and interactive docs are available at
`/certforge-api/openapi.json` and `/certforge-api/docs`.

- `GET /certforge-api/health`
- `POST /certforge-api/certificates/inspect`
- `POST /certforge-api/certificates/match`
- `POST /certforge-api/certificates/convert`
- `POST /certforge-api/pkcs12/export`
- `POST /certforge-api/pkcs12/import`

Certificate and key operations accept multipart form uploads. API errors use
the shape `{"error":{"code":"...","message":"..."}}`; the backend does not
return OpenSSL diagnostic output or passphrases in an error response.

## Tests

Install the backend test dependencies and run the API tests:

```sh
python -m pip install -r artifacts/certforge-t/backend/requirements-dev.txt
cd artifacts/certforge-t/backend
python -m pytest
```

The tests generate throwaway certificates and keys locally, then exercise the
actual endpoints and OpenSSL conversion/export/import commands. They do not
require sample certificates or real keys.

## Project layout

- `artifacts/certforge-t/src/` — responsive React/TypeScript app.
- `artifacts/certforge-t/backend/main.py` — FastAPI app assembly and structured
  error handlers.
- `artifacts/certforge-t/backend/routers/` — separate certificate and PKCS#12
  API routes.
- `artifacts/certforge-t/backend/crypto_operations.py` — reusable certificate,
  key, OpenSSL, and secure temporary-file operations.
- `artifacts/certforge-t/backend/schemas.py` and `api_errors.py` — named
  response models and structured operation errors.
- `artifacts/certforge-t/backend/test_main.py` — automated API tests.
- `artifacts/certforge-t/Dockerfile.web` — frontend build and unprivileged
  Nginx image.
- `artifacts/certforge-t/backend/Dockerfile` — FastAPI and OpenSSL image.
- `docker-compose.yml` — local self-hosted deployment.

The app does not persist certificates or private keys. This keeps the initial
workbench stateless and leaves room to add separately designed CA, S/MIME,
OpenPGP, revocation, and expiry-monitoring modules later.
