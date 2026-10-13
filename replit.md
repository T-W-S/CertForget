# CertForge_t

A self-hosted certificate workbench for inspecting X.509 files, comparing public/private keys, and converting certificate and PKCS#12 formats.

## Run & Operate

- `docker compose up --build` — build and run the self-hosted app
- `docker compose down` — stop and remove the containers
- `python -m pytest` from `artifacts/certforge-t/backend/` — run the FastAPI tests
- `pnpm --filter @workspace/certforge-t run typecheck` — typecheck the React/TypeScript app
- `pnpm --filter @workspace/certforge-t run dev` — run the frontend preview
- Replit development also has a managed FastAPI service on `/certforge-api`.
- Optional environment: copy `.env.example` to `.env` to set the host port, upload limit, or OpenSSL timeout.

## Stack

- Frontend: React, TypeScript, Vite
- Backend: Python FastAPI with Pydantic validation
- Crypto: OpenSSL CLI and Python `cryptography`
- Deployment: Docker Compose, unprivileged Nginx frontend, FastAPI backend

## Where things live

- `artifacts/certforge-t/src/` — React interface and typed API client
- `artifacts/certforge-t/backend/main.py` — FastAPI app, health route, and error handlers
- `artifacts/certforge-t/backend/routers/` — certificate and PKCS#12 endpoints
- `artifacts/certforge-t/backend/crypto_operations.py` — reusable cryptography/OpenSSL operations
- `artifacts/certforge-t/backend/test_main.py` — API and cryptographic tests
- `artifacts/certforge-t/backend/requirements.txt` — backend runtime dependencies
- `docker-compose.yml` — self-hosted frontend/API deployment
- `README.md` — setup, API, testing, and operational notes

## Architecture decisions

- Uploaded files are request-scoped; the app intentionally has no database or certificate storage.
- The API exposes a fixed set of cryptographic operations. User input is never interpreted as a shell command.
- Passphrases travel to OpenSSL via file descriptors; private key inputs are staged in permission-restricted temporary storage and removed after processing.

## Product

- Certificate and key uploads for inspection, matching, and conversion
- X.509 details and SHA-256 fingerprint inspection
- Private-key and public-key matching against a certificate
- PEM/DER certificate conversion and PKCS#12/PFX import/export
- Live backend/OpenSSL health status and informational command previews

## User preferences

- The requested visual direction is a professional dark cybersecurity workbench with purple accents and subtle glassmorphism.

## Gotchas

- The React API client uses `/certforge-api`; Docker Nginx and the managed preview route this prefix to FastAPI.
- The initial app does not save uploaded certificates, private keys, passphrases, or generated files.

## Pointers

- `README.md` documents local Docker Compose use and API tests.
