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

async function request<T>(path: string, body?: FormData): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    method: body ? 'POST' : 'GET',
    body,
  });
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
};

export function downloadBase64(file: BinaryResponse) {
  const binary = atob(file.content_base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  const blob = new Blob([bytes], { type: file.media_type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = file.filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function formatBytes(size: number) {
  if (size < 1024) {
    return `${size} B`;
  }
  return `${(size / 1024).toFixed(1)} KB`;
}
