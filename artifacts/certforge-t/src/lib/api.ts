export interface HealthResponse {
  status: string;
  openssl_version: string;
}

export interface InspectResponse {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  is_valid_now: boolean;
  days_until_expiry: number;
  sans: string[];
  signature_algorithm: string;
  public_key_algorithm: string;
  public_key_size: number | null;
  sha256_fingerprint: string;
  openssl_version: string;
  extensions: CertificateExtensionsResponse;
}

export type KeyAlgorithm =
  | 'RSA-2048'
  | 'RSA-3072'
  | 'RSA-4096'
  | 'ECDSA-P256'
  | 'ECDSA-P384'
  | 'Ed25519';

export type CertificatePurpose = 'tls-server' | 'tls-client' | 'smime' | 'general';

export interface CertificateSubjectRequest {
  common_name: string | null;
  organization: string | null;
  organizational_unit: string | null;
  country: string | null;
  state_or_province: string | null;
  locality: string | null;
  email_address: string | null;
}

export interface SubjectAltNameRequest {
  type: 'DNS' | 'IP' | 'EMAIL' | 'URI';
  value: string;
}

export interface KeySourceRequest {
  source: 'generate' | 'import';
  algorithm: KeyAlgorithm | null;
  private_key_base64?: string | null;
  private_key_passphrase?: string | null;
}

export interface CertificateBuildRequest {
  subject: CertificateSubjectRequest;
  sans: SubjectAltNameRequest[];
  key: KeySourceRequest;
  purpose: CertificatePurpose;
  private_key_export_passphrase: string;
}

export interface SelfSignedCertificateRequest extends CertificateBuildRequest {
  not_before: string;
  not_after: string;
  certificate_format: 'PEM' | 'DER';
}

export interface GenerateCsrRequest extends CertificateBuildRequest {
  csr_format: 'PEM' | 'DER';
}

export interface CertificateExtensionsResponse {
  key_usage: string[];
  extended_key_usage: string[];
  basic_constraints: string | null;
  subject_key_identifier: string | null;
  authority_key_identifier: string | null;
}

export interface GeneratedCertificateResponse {
  certificate: BinaryResponse;
  certificate_pem: BinaryResponse | null;
  private_key: BinaryResponse;
  archive: BinaryResponse;
  inspection: InspectResponse;
  self_signature_verified: boolean;
}

export interface GeneratedCsrResponse {
  csr: BinaryResponse;
  private_key: BinaryResponse;
  subject: string;
  public_key_algorithm: string;
  public_key_fingerprint: string;
  signature_algorithm: string;
  sans: string[];
  requested_extensions: CertificateExtensionsResponse;
  signature_verified: boolean;
}

export interface MatchResponse {
  matches: boolean;
  certificate_fingerprint: string;
  certificate_public_key_algorithm: string;
  key_kind: 'private' | 'public';
  uploaded_key_algorithm: string;
  message: string;
}

export interface BinaryResponse {
  filename: string;
  media_type: string;
  content_base64: string;
  size_bytes: number;
}

export interface ImportResponse {
  files: BinaryResponse[];
  certificate_count: number;
}

export const API_ROOT = '/certforge-api';

async function request<T>(path: string, body?: FormData | object): Promise<T> {
  const init: RequestInit = { method: body ? 'POST' : 'GET' };
  if (body instanceof FormData) {
    init.body = body;
  } else if (body) {
    init.headers = { 'Content-Type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  const response = await fetch(`${API_ROOT}${path}`, init);
  if (!response.ok) {
    let detail = `Request failed with status ${response.status}.`;
    try {
      const payload = await response.json();
      const message =
        payload.error?.message || payload.detail || payload.message;
      detail = typeof message === 'string' ? message : message ? JSON.stringify(message) : detail;
    } catch {
      detail = response.statusText || detail;
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<HealthResponse>('/health'),
  inspect: (body: FormData) => request<InspectResponse>('/certificates/inspect', body),
  match: (body: FormData) => request<MatchResponse>('/certificates/match', body),
  convert: (body: FormData) => request<BinaryResponse>('/certificates/convert', body),
  exportPfx: (body: FormData) => request<BinaryResponse>('/pkcs12/export', body),
  importPfx: (body: FormData) => request<ImportResponse>('/pkcs12/import', body),
  createSelfSigned: (body: SelfSignedCertificateRequest) =>
    request<GeneratedCertificateResponse>('/certificates/self-signed', body),
  generateCsr: (body: GenerateCsrRequest) =>
    request<GeneratedCsrResponse>('/csrs/generate', body),
};

export function downloadBase64(file: BinaryResponse) {
  const outputFile = fileFromBase64(file);
  const url = URL.createObjectURL(outputFile);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = file.filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function fileFromBase64(file: BinaryResponse): File {
  const binary = atob(file.content_base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return new File([bytes], file.filename, { type: file.media_type });
}

export async function encodeFileBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const chunkSize = 0x8000;
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function formatBytes(size: number) {
  if (size < 1024) {
    return `${size} B`;
  }
  return `${(size / 1024).toFixed(1)} KB`;
}
