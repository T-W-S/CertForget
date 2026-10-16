import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Router } from 'wouter';
import CreatePage from '../src/pages/create';
import { api, downloadBase64 } from '../src/lib/api';
import type {
  BinaryResponse,
  GeneratedCertificateResponse,
  GeneratedCsrResponse,
} from '../src/lib/api';

vi.mock('@/lib/api', () => ({
  api: {
    createSelfSigned: vi.fn(),
    generateCsr: vi.fn(),
  },
  downloadBase64: vi.fn(),
  encodeFileBase64: vi.fn(async () => 'AAECAw=='),
  fileFromBase64: vi.fn((file: { content_base64: string; filename: string; media_type: string }) => {
    const contents = atob(file.content_base64);
    const output = new File([contents], file.filename, { type: file.media_type });
    Object.defineProperty(output, 'text', {
      value: async () => contents,
    });
    return output;
  }),
  formatBytes: (size: number) => `${size} bytes`,
}));

const binaryFile = (filename: string, contents: string): BinaryResponse => ({
  filename,
  media_type: 'application/x-pem-file',
  content_base64: btoa(contents),
  size_bytes: contents.length,
});

const certificateResponse: GeneratedCertificateResponse = {
  certificate: binaryFile(
    'certificate.pem',
    '-----BEGIN CERTIFICATE-----\ncertificate bytes\n-----END CERTIFICATE-----\n',
  ),
  certificate_pem: null,
  private_key: binaryFile('private-key.encrypted.pem', 'ENCRYPTED PRIVATE KEY'),
  archive: binaryFile('certificate-and-private-key.zip', 'ZIP bytes'),
  inspection: {
    subject: 'commonName=service.example.test',
    issuer: 'commonName=service.example.test',
    serial_number: '1A2B',
    not_before: '2026-10-16T10:00:00+00:00',
    not_after: '2027-10-16T10:00:00+00:00',
    is_valid_now: true,
    days_until_expiry: 365,
    sans: ['DNS:service.example.test'],
    signature_algorithm: 'sha256WithRSAEncryption with SHA256',
    public_key_algorithm: 'RSA',
    public_key_size: 3072,
    sha256_fingerprint: '01:02:03',
    openssl_version: 'OpenSSL 3',
    extensions: {
      key_usage: ['Digital signature', 'Key encipherment'],
      extended_key_usage: ['serverAuth'],
      basic_constraints: 'CA:FALSE',
      subject_key_identifier: '01:02',
      authority_key_identifier: '01:02',
    },
  },
  self_signature_verified: true,
};

const csrResponse: GeneratedCsrResponse = {
  csr: binaryFile(
    'certificate-request.pem',
    '-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----\n',
  ),
  private_key: binaryFile('private-key.encrypted.pem', 'ENCRYPTED PRIVATE KEY'),
  subject: 'commonName=service.example.test',
  public_key_algorithm: 'RSA-3072',
  public_key_fingerprint: '01:02:03',
  signature_algorithm: 'sha256WithRSAEncryption with SHA256',
  sans: ['DNS:service.example.test'],
  requested_extensions: {
    key_usage: ['Digital signature', 'Key encipherment'],
    extended_key_usage: ['serverAuth'],
    basic_constraints: 'CA:FALSE',
    subject_key_identifier: '01:02',
    authority_key_identifier: null,
  },
  signature_verified: true,
};

const outputPassphrase = 'LongEnoughPassphrase#2026';

function mountCreatePage(onInspectGeneratedCertificate = vi.fn()) {
  const view = render(
    <Router>
      <CreatePage onInspectGeneratedCertificate={onInspectGeneratedCertificate} />
    </Router>,
  );
  return { ...view, onInspectGeneratedCertificate };
}

function addIdentity() {
  fireEvent.change(screen.getByTestId('input-subject-common_name'), {
    target: { value: 'service.example.test' },
  });
  fireEvent.click(screen.getByTestId('button-add-san'));
  fireEvent.change(screen.getByTestId('input-san-value-0'), {
    target: { value: 'service.example.test' },
  });
  fireEvent.click(screen.getByTestId('button-continue'));
}

function enterExportPassphrase() {
  fireEvent.change(screen.getByTestId('input-export-passphrase'), {
    target: { value: outputPassphrase },
  });
  fireEvent.change(screen.getByTestId('input-confirm-export-passphrase'), {
    target: { value: outputPassphrase },
  });
}

beforeEach(() => {
  vi.mocked(api.createSelfSigned).mockReset();
  vi.mocked(api.generateCsr).mockReset();
  vi.mocked(downloadBase64).mockClear();
});

afterEach(() => {
  cleanup();
});

describe('Create certificate wizard', () => {
  it('requires a subject identity or SAN before continuing', () => {
    mountCreatePage();

    fireEvent.click(screen.getByTestId('button-continue'));

    expect(screen.getAllByText(/Enter a Common Name or at least one SAN/).length).toBeGreaterThan(0);
    expect(api.createSelfSigned).not.toHaveBeenCalled();
  });

  it('generates a self-signed certificate and separately downloads each output', async () => {
    vi.mocked(api.createSelfSigned).mockResolvedValue(certificateResponse);
    const { onInspectGeneratedCertificate } = mountCreatePage();

    addIdentity();
    enterExportPassphrase();
    fireEvent.click(screen.getByTestId('button-continue'));
    expect(screen.getAllByText('CA:FALSE').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByTestId('button-generate'));

    await waitFor(() => expect(screen.getByTestId('panel-generated-result')).toBeTruthy());
    expect(api.createSelfSigned).toHaveBeenCalledTimes(1);
    const request = vi.mocked(api.createSelfSigned).mock.calls[0][0];
    expect(request.key.algorithm).toBe('RSA-3072');
    expect(request.sans).toEqual([{ type: 'DNS', value: 'service.example.test' }]);
    expect(request.private_key_export_passphrase).toBe(outputPassphrase);
    expect(request).not.toHaveProperty('confirm_passphrase');
    expect(downloadBase64).not.toHaveBeenCalled();
    expect(screen.getByText('Generated files')).toBeTruthy();
    expect(screen.queryByText(/ENCRYPTED PRIVATE KEY/)).toBeNull();
    expect(screen.getByText('CA:FALSE')).toBeTruthy();

    vi.mocked(downloadBase64).mockImplementationOnce(() => {
      expect(screen.getByTestId('download-status').textContent).toContain(
        'Preparing certificate.pem',
      );
    });
    fireEvent.click(screen.getByTestId('button-download-certificate'));
    expect(downloadBase64).toHaveBeenLastCalledWith(certificateResponse.certificate);
    fireEvent.click(screen.getByTestId('button-download-certificate'));
    expect(downloadBase64).toHaveBeenLastCalledWith(certificateResponse.certificate);
    fireEvent.click(screen.getByTestId('button-download-private-key'));
    expect(downloadBase64).toHaveBeenLastCalledWith(certificateResponse.private_key);
    fireEvent.click(screen.getByTestId('button-download-bundle'));
    expect(downloadBase64).toHaveBeenLastCalledWith(certificateResponse.archive);
    expect(downloadBase64).toHaveBeenCalledTimes(4);
    expect(screen.getByTestId('download-status').textContent).toContain(
      'certificate-and-private-key.zip download started',
    );

    fireEvent.click(screen.getByTestId('button-inspect-generated'));
    expect(onInspectGeneratedCertificate).toHaveBeenCalledTimes(1);
    const inspectedCertificate = vi.mocked(onInspectGeneratedCertificate).mock.calls[0][0];
    expect(inspectedCertificate).toBeInstanceOf(File);
    expect(inspectedCertificate.name).toBe('certificate.pem');
    expect(await inspectedCertificate.text()).toBe(
      '-----BEGIN CERTIFICATE-----\ncertificate bytes\n-----END CERTIFICATE-----\n',
    );

    fireEvent.click(screen.getByTestId('button-edit-request'));
    expect((screen.getByTestId('input-export-passphrase') as HTMLInputElement).value).toBe('');
    expect((screen.getByTestId('input-confirm-export-passphrase') as HTMLInputElement).value).toBe('');
  });

  it('creates a CSR, labels it as a request, and copies PEM only after an explicit click', async () => {
    vi.mocked(api.generateCsr).mockResolvedValue(csrResponse);
    const clipboardWrite = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: clipboardWrite },
    });
    mountCreatePage();

    fireEvent.click(screen.getByTestId('tab-csr'));
    addIdentity();
    enterExportPassphrase();
    fireEvent.click(screen.getByTestId('button-continue'));
    fireEvent.click(screen.getByTestId('button-generate'));

    await waitFor(() => expect(screen.getByTestId('panel-generated-result')).toBeTruthy());
    expect(api.generateCsr).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/This CSR is a request, not a certificate/)).toBeTruthy();
    expect(downloadBase64).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId('button-download-csr'));
    expect(downloadBase64).toHaveBeenLastCalledWith(csrResponse.csr);
    fireEvent.click(screen.getByTestId('button-download-private-key'));
    expect(downloadBase64).toHaveBeenLastCalledWith(csrResponse.private_key);
    expect(downloadBase64).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByTestId('button-copy-csr'));
    await waitFor(() => expect(clipboardWrite).toHaveBeenCalledTimes(1));
    expect(clipboardWrite).toHaveBeenCalledWith(
      '-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----\n',
    );
  });

  it('offers PEM and DER separately while the inspector always receives PEM', async () => {
    const derCertificateResponse: GeneratedCertificateResponse = {
      ...certificateResponse,
      certificate: binaryFile('certificate.der', 'DER certificate bytes'),
      certificate_pem: binaryFile(
        'certificate.pem',
        '-----BEGIN CERTIFICATE-----\ncertificate bytes\n-----END CERTIFICATE-----\n',
      ),
    };
    vi.mocked(api.createSelfSigned).mockResolvedValue(derCertificateResponse);
    const { onInspectGeneratedCertificate } = mountCreatePage();

    addIdentity();
    fireEvent.change(screen.getByTestId('select-output-format'), {
      target: { value: 'DER' },
    });
    enterExportPassphrase();
    fireEvent.click(screen.getByTestId('button-continue'));
    fireEvent.click(screen.getByTestId('button-generate'));
    await waitFor(() => expect(screen.getByTestId('panel-generated-result')).toBeTruthy());

    fireEvent.click(screen.getByTestId('button-download-certificate'));
    expect(downloadBase64).toHaveBeenLastCalledWith(derCertificateResponse.certificate_pem);
    fireEvent.click(screen.getByTestId('button-download-der'));
    expect(downloadBase64).toHaveBeenLastCalledWith(derCertificateResponse.certificate);
    fireEvent.click(screen.getByTestId('button-inspect-generated'));
    const inspectedCertificate = vi.mocked(onInspectGeneratedCertificate).mock.calls[0][0];
    expect(inspectedCertificate.name).toBe('certificate.pem');
    expect(await inspectedCertificate.text()).toContain('BEGIN CERTIFICATE');
    expect(api.createSelfSigned).toHaveBeenCalledTimes(1);
  });

  it('shows a download error without generating the certificate again', async () => {
    vi.mocked(api.createSelfSigned).mockResolvedValue(certificateResponse);
    mountCreatePage();
    addIdentity();
    enterExportPassphrase();
    fireEvent.click(screen.getByTestId('button-continue'));
    fireEvent.click(screen.getByTestId('button-generate'));
    await waitFor(() => expect(screen.getByTestId('panel-generated-result')).toBeTruthy());
    vi.mocked(downloadBase64).mockImplementationOnce(() => {
      throw new Error('browser refused download');
    });

    fireEvent.click(screen.getByTestId('button-download-certificate'));

    expect(screen.getByRole('alert').textContent).toContain('Could not start');
    expect(screen.getByTestId('panel-generated-result')).toBeTruthy();
    expect(api.createSelfSigned).toHaveBeenCalledTimes(1);
  });

  it('encodes imported key bytes and clears all sensitive fields after an API error', async () => {
    vi.mocked(api.createSelfSigned).mockRejectedValue(new Error('Key could not be loaded.'));
    mountCreatePage();
    addIdentity();

    fireEvent.click(screen.getByTestId('choice-key-import'));
    const importedKey = new File(['PRIVATE KEY CONTENT'], 'operator-key.pem');
    fireEvent.change(screen.getByTestId('input-file-create-imported-key'), {
      target: { files: [importedKey] },
    });
    fireEvent.change(screen.getByTestId('input-import-key-passphrase'), {
      target: { value: 'test-only-source-passphrase' },
    });
    enterExportPassphrase();
    fireEvent.click(screen.getByTestId('button-continue'));
    fireEvent.click(screen.getByTestId('button-generate'));

    await waitFor(() => expect(screen.getByText('Key could not be loaded.')).toBeTruthy());
    const request = vi.mocked(api.createSelfSigned).mock.calls[0][0];
    expect(request.key.source).toBe('import');
    expect(request.key.algorithm).toBeNull();
    expect(request.key.private_key_base64).toBe('AAECAw==');
    expect(request.key.private_key_passphrase).toBe('test-only-source-passphrase');

    fireEvent.click(screen.getByTestId('button-edit-request'));
    expect(screen.getByTestId('button-upload-create-imported-key')).toBeTruthy();
    expect((screen.getByTestId('input-import-key-passphrase') as HTMLInputElement).value).toBe('');
    expect((screen.getByTestId('input-export-passphrase') as HTMLInputElement).value).toBe('');
    expect((screen.getByTestId('input-confirm-export-passphrase') as HTMLInputElement).value).toBe('');
  });
});
