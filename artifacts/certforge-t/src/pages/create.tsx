import { type FormEvent, type ReactNode, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronRight,
  Clipboard,
  Download,
  FileKey2,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Plus,
  ShieldCheck,
  Trash2,
  WandSparkles,
} from 'lucide-react';
import { Link } from 'wouter';
import { ErrorNotice } from '@/components/feedback';
import { FileField } from '@/components/file-field';
import {
  api,
  downloadBase64,
  encodeFileBase64,
  fileFromBase64,
  formatBytes,
  type CertificatePurpose,
  type CertificateSubjectRequest,
  type GeneratedCertificateResponse,
  type GeneratedCsrResponse,
  type KeyAlgorithm,
  type SelfSignedCertificateRequest,
  type SubjectAltNameRequest,
} from '@/lib/api';

type BuildMode = 'certificate' | 'csr';
type WizardStep = 0 | 1 | 2;
type SubjectForm = { [Key in keyof CertificateSubjectRequest]: string };
type SafeResult =
  | { kind: 'certificate'; inspection: GeneratedCertificateResponse['inspection']; verified: boolean }
  | { kind: 'csr'; subject: string; publicKeyAlgorithm: string; publicKeyFingerprint: string; signatureAlgorithm: string; sans: string[]; extensions: GeneratedCsrResponse['requested_extensions']; verified: boolean; filename: string; size: number; copyable: boolean };

const steps = ['Identity', 'Key & validity', 'Review'];
const algorithms: KeyAlgorithm[] = ['RSA-2048', 'RSA-3072', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384', 'Ed25519'];
const purposes: { value: CertificatePurpose; label: string; note: string }[] = [
  { value: 'tls-server', label: 'TLS server', note: 'Server authentication' },
  { value: 'tls-client', label: 'TLS client', note: 'Client authentication' },
  { value: 'smime', label: 'S/MIME', note: 'Email signing and encryption' },
  { value: 'general', label: 'General', note: 'No specialized purpose' },
];
const emptySubject: SubjectForm = {
  common_name: '',
  organization: '',
  organizational_unit: '',
  country: '',
  state_or_province: '',
  locality: '',
  email_address: '',
};

function localDateTime(offsetDays: number) {
  const date = new Date(Date.now() + offsetDays * 86400000);
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 16);
}

function optional(value: string) {
  return value || null;
}

function dateToQualified(value: string) {
  return new Date(value).toISOString();
}

function subjectText(subject: SubjectForm) {
  return [
    subject.common_name && `CN=${subject.common_name}`,
    subject.organization && `O=${subject.organization}`,
    subject.organizational_unit && `OU=${subject.organizational_unit}`,
    subject.locality && `L=${subject.locality}`,
    subject.state_or_province && `ST=${subject.state_or_province}`,
    subject.country && `C=${subject.country}`,
    subject.email_address && `emailAddress=${subject.email_address}`,
  ].filter(Boolean).join(', ');
}

export default function CreatePage({ onInspectGeneratedCertificate }: { onInspectGeneratedCertificate: (file: File) => void }) {
  const [mode, setMode] = useState<BuildMode>('certificate');
  const [step, setStep] = useState<WizardStep>(0);
  const [subject, setSubject] = useState<SubjectForm>(emptySubject);
  const [sans, setSans] = useState<SubjectAltNameRequest[]>([]);
  const [algorithm, setAlgorithm] = useState<KeyAlgorithm>('RSA-3072');
  const [keySource, setKeySource] = useState<'generate' | 'import'>('generate');
  const [importedKey, setImportedKey] = useState<File | null>(null);
  const [importPassphrase, setImportPassphrase] = useState('');
  const [purpose, setPurpose] = useState<CertificatePurpose>('tls-server');
  const [notBefore, setNotBefore] = useState(localDateTime(0));
  const [notAfter, setNotAfter] = useState(localDateTime(365));
  const [format, setFormat] = useState<'PEM' | 'DER'>('PEM');
  const [exportPassphrase, setExportPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [fieldError, setFieldError] = useState('');
  const [serverError, setServerError] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SafeResult | null>(null);
  const publicCertificateRef = useRef<GeneratedCertificateResponse['certificate'] | null>(null);
  const csrCopyRef = useRef<GeneratedCsrResponse['csr'] | null>(null);

  const clearFeedback = () => {
    setFieldError('');
    setServerError('');
    setResult(null);
    publicCertificateRef.current = null;
    csrCopyRef.current = null;
  };

  const selectMode = (nextMode: BuildMode) => {
    if (loading) return;
    setMode(nextMode);
    setStep(0);
    clearFeedback();
  };

  const validateStep = (target: WizardStep) => {
    if (target === 0) {
      if (!subject.common_name.trim() && !sans.some((san) => san.value.length > 0)) {
        setFieldError('Enter a Common Name or at least one SAN. A DNS or IP SAN can be the primary identity without a Common Name.');
        return false;
      }
      if (Object.values(subject).some((value) => value !== value.trim())) {
        setFieldError('Remove leading or trailing spaces from subject fields.');
        return false;
      }
      if (subject.email_address && !isValidEmail(subject.email_address)) {
        setFieldError('Enter a valid email address or leave the field empty.');
        return false;
      }
      if (subject.country && !/^[A-Z]{2}$/.test(subject.country)) {
        setFieldError('Country must be a two-letter ISO 3166-1 code, such as GB or US.');
        return false;
      }
      const invalidSan = sans.find((san) => !san.value.trim() || !isValidSan(san));
      if (invalidSan) {
        setFieldError(`${invalidSan.type} subject alternative name needs a valid, non-empty value.`);
        return false;
      }
      const sanKeys = sans.map((san) => `${san.type}:${san.value}`);
      if (new Set(sanKeys).size !== sanKeys.length) {
        setFieldError('Remove duplicate subject alternative names.');
        return false;
      }
      if (purpose === 'tls-server' && !sans.some((san) => ['DNS', 'IP'].includes(san.type) && isValidSan(san))) {
        setFieldError('TLS server identity must include at least one valid DNS or IP SAN.');
        return false;
      }
      if (purpose === 'tls-client' && sans.length === 0) {
        setFieldError('TLS certificates need a SAN; a Common Name alone is not used for identity.');
        return false;
      }
      if (purpose === 'smime' && !subject.email_address && !sans.some((san) => san.type === 'EMAIL' && isValidSan(san))) {
        setFieldError('S/MIME certificates need an email address in the subject or SANs.');
        return false;
      }
    }
    if (target === 1) {
      if (keySource === 'import' && !importedKey) {
        setFieldError('Choose a private key file to continue.');
        return false;
      }
      if (!exportPassphrase) {
        setFieldError('Set an export passphrase to encrypt the downloaded private key.');
        return false;
      }
      if (!isStrongExportPassphrase(exportPassphrase)) {
        setFieldError('Use a passphrase of at least 16 characters, or at least 12 characters with three character types.');
        return false;
      }
      if (exportPassphrase !== confirmPassphrase) {
        setFieldError('The export passphrase and confirmation do not match.');
        return false;
      }
      if (mode === 'certificate') {
        if (!notBefore || !notAfter || Number.isNaN(new Date(notBefore).getTime()) || Number.isNaN(new Date(notAfter).getTime())) {
          setFieldError('Enter valid start and end dates for the certificate.');
          return false;
        }
        if (new Date(notAfter) <= new Date(notBefore)) {
          setFieldError('The expiry date must be later than the start date.');
          return false;
        }
        if (new Date(notAfter).getTime() - new Date(notBefore).getTime() > 3650 * 86400000) {
          setFieldError('Certificate validity cannot exceed 10 years.');
          return false;
        }
      }
    }
    setFieldError('');
    return true;
  };

  const continueStep = () => {
    if (validateStep(step) && step < 2) {
      setFieldError('');
      setStep((current) => (current + 1) as WizardStep);
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (loading || !validateStep(1)) return;
    setFieldError('');
    setServerError('');
    setResult(null);
    setLoading(true);
    let privateKeyBase64: string | undefined;
    try {
      if (keySource === 'import' && importedKey) {
        privateKeyBase64 = await encodeFileBase64(importedKey);
      }
      const key = {
        source: keySource,
        algorithm: keySource === 'generate' ? algorithm : null,
        ...(keySource === 'import' ? {
          private_key_base64: privateKeyBase64 ?? null,
          private_key_passphrase: importPassphrase || null,
        } : {}),
      };
      const base = {
        subject: {
          common_name: optional(subject.common_name),
          organization: optional(subject.organization),
          organizational_unit: optional(subject.organizational_unit),
          country: optional(subject.country),
          state_or_province: optional(subject.state_or_province),
          locality: optional(subject.locality),
          email_address: optional(subject.email_address),
        },
        sans: sans.map((san) => ({ type: san.type, value: san.value })),
        key,
        purpose,
        private_key_export_passphrase: exportPassphrase,
      };

      if (mode === 'certificate') {
        const body: SelfSignedCertificateRequest = {
          ...base,
          not_before: dateToQualified(notBefore),
          not_after: dateToQualified(notAfter),
          certificate_format: format,
        };
        const response = await api.createSelfSigned(body);
        downloadBase64(response.certificate);
        downloadBase64(response.private_key);
        publicCertificateRef.current = response.certificate;
        setResult({
          kind: 'certificate',
          inspection: response.inspection,
          verified: response.self_signature_verified,
        });
      } else {
        const response = await api.generateCsr({ ...base, csr_format: format });
        downloadBase64(response.csr);
        downloadBase64(response.private_key);
        csrCopyRef.current = format === 'PEM' ? response.csr : null;
        setResult({
          kind: 'csr',
          subject: response.subject,
          publicKeyAlgorithm: response.public_key_algorithm,
          publicKeyFingerprint: response.public_key_fingerprint,
          signatureAlgorithm: response.signature_algorithm,
          sans: response.sans,
          extensions: response.requested_extensions,
          verified: response.signature_verified,
          filename: response.csr.filename,
          size: response.csr.size_bytes,
          copyable: format === 'PEM',
        });
      }
    } catch (requestError) {
      setServerError(requestError instanceof Error ? requestError.message : 'The request could not be completed by the certificate service.');
      publicCertificateRef.current = null;
      csrCopyRef.current = null;
    } finally {
      privateKeyBase64 = undefined;
      setImportedKey(null);
      setImportPassphrase('');
      setExportPassphrase('');
      setConfirmPassphrase('');
      setLoading(false);
    }
  };

  const copyCsr = async () => {
    const csr = csrCopyRef.current;
    if (!csr) return;
    try {
      const text = await fileFromBase64(csr).text();
      await navigator.clipboard.writeText(text);
      csrCopyRef.current = null;
      setResult((current) => current?.kind === 'csr' ? { ...current, copyable: false } : current);
      setServerError('');
    } catch {
      setServerError('The CSR could not be copied. Check clipboard permissions and try again.');
    }
  };

  const inspectGenerated = () => {
    if (publicCertificateRef.current) {
      onInspectGeneratedCertificate(fileFromBase64(publicCertificateRef.current));
    }
  };

  return (
    <div className="app-main page-enter">
      <div className="mb-8 flex items-center gap-2 text-xs text-[#8a879a]">
        <Link href="/" className="hover:text-[#d2cede]">Workspace</Link>
        <ChevronRight size={13} />
        <span className="text-[#cbc8d6]">Create certificate</span>
      </div>
      <div className="mb-7">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-violet-300/10 bg-violet-300/[0.08] text-violet-200">
          <WandSparkles size={19} />
        </div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-violet-300/80">Certificate operations</p>
        <h1 className="mt-1.5 font-display text-3xl font-semibold tracking-tight text-[#f0edf6]">Create a certificate</h1>
        <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[#9996a8]">Build an X.509 certificate or a PKCS#10 signing request using the certificate service on your own server.</p>
      </div>

      <section className="mb-5 grid gap-3 rounded-2xl border border-amber-200/[0.13] bg-amber-200/[0.035] p-4 sm:grid-cols-2 sm:p-5" aria-label="Trust guidance">
        <TrustNote icon={<ShieldCheck size={15} />} title="Self-signed does not mean trusted" copy="A self-signature proves the certificate signed itself. Browsers and clients will not trust it unless you establish trust separately." />
        <TrustNote icon={<FileKey2 size={15} />} title="A CSR is a request, not a certificate" copy="A certificate signing request contains identity and public-key details. A certificate authority must review and issue a certificate from it." />
      </section>

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <section className="glass-panel min-w-0 rounded-2xl p-4 sm:p-6">
          <div className="grid grid-cols-2 gap-2 rounded-xl border border-white/[0.06] bg-[#171824]/70 p-1" role="tablist" aria-label="Artifact type">
            <button type="button" role="tab" aria-selected={mode === 'certificate'} onClick={() => selectMode('certificate')} className={`flex min-h-11 items-center justify-center gap-2 rounded-lg px-3 text-[12px] font-semibold transition ${mode === 'certificate' ? 'bg-violet-300/[0.13] text-violet-100' : 'text-[#8e8a9e] hover:text-[#ddd9e8]'}`} data-testid="tab-self-signed">
              <ShieldCheck size={15} />
              Self-signed certificate
            </button>
            <button type="button" role="tab" aria-selected={mode === 'csr'} onClick={() => selectMode('csr')} className={`flex min-h-11 items-center justify-center gap-2 rounded-lg px-3 text-[12px] font-semibold transition ${mode === 'csr' ? 'bg-violet-300/[0.13] text-violet-100' : 'text-[#8e8a9e] hover:text-[#ddd9e8]'}`} data-testid="tab-csr">
              <FileKey2 size={15} />
              CSR
            </button>
          </div>

          <div className="mt-5 flex items-center gap-2" aria-label="Wizard progress">
            {steps.map((label, index) => (
              <div key={label} className="flex min-w-0 flex-1 items-center gap-2">
                <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold ${step === index ? 'border-violet-300/40 bg-violet-300/15 text-violet-100' : step > index ? 'border-emerald-300/25 bg-emerald-300/10 text-emerald-200' : 'border-white/[0.09] bg-white/[0.025] text-[#777486]'}`}>
                  {step > index ? <Check size={13} /> : `0${index + 1}`}
                </span>
                <span className={`truncate text-[10px] font-medium sm:text-[11px] ${step === index ? 'text-[#e0dceb]' : 'text-[#777486]'}`}>{label}</span>
                {index < steps.length - 1 && <span className="h-px min-w-2 flex-1 bg-white/[0.08]" />}
              </div>
            ))}
          </div>

          {step < 2 ? (
            <form className="mt-6 space-y-5" onSubmit={(event) => { event.preventDefault(); continueStep(); }}>
              {step === 0 ? (
                <IdentityStep subject={subject} setSubject={setSubject} sans={sans} setSans={setSans} />
              ) : (
                <KeyValidityStep
                  mode={mode}
                  algorithm={algorithm}
                  setAlgorithm={setAlgorithm}
                  keySource={keySource}
                  setKeySource={setKeySource}
                  importedKey={importedKey}
                  setImportedKey={setImportedKey}
                  importPassphrase={importPassphrase}
                  setImportPassphrase={setImportPassphrase}
                  purpose={purpose}
                  setPurpose={setPurpose}
                  notBefore={notBefore}
                  setNotBefore={setNotBefore}
                  notAfter={notAfter}
                  setNotAfter={setNotAfter}
                  format={format}
                  setFormat={setFormat}
                  exportPassphrase={exportPassphrase}
                  setExportPassphrase={setExportPassphrase}
                  confirmPassphrase={confirmPassphrase}
                  setConfirmPassphrase={setConfirmPassphrase}
                />
              )}
              {fieldError && <FieldError>{fieldError}</FieldError>}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-4">
                <span className="flex items-center gap-1.5 text-[10px] text-[#817e91]"><LockKeyhole size={12} className="text-emerald-300" />Request-scoped sensitive inputs</span>
                {step > 0 ? (
                  <div className="flex gap-2">
                    <button type="button" onClick={() => { setFieldError(''); setStep(0); }} className="secondary-button min-h-10 px-3 text-[11px]" data-testid="button-back"><ArrowLeft size={14} />Back</button>
                    <button type="submit" className="primary-button min-h-10 px-4 text-[12px]" data-testid="button-continue">Review request<ArrowRight size={15} /></button>
                  </div>
                ) : (
                  <button type="submit" className="primary-button min-h-10 px-4 text-[12px]" data-testid="button-continue">Continue<ArrowRight size={15} /></button>
                )}
              </div>
            </form>
          ) : (
            <form className="mt-6 space-y-5" onSubmit={submit}>
              <ReviewPanel
                mode={mode}
                subject={subject}
                sans={sans}
                keySource={keySource}
                algorithm={algorithm}
                purpose={purpose}
                notBefore={notBefore}
                notAfter={notAfter}
                format={format}
                importedKeyName={importedKey?.name}
              />
              {fieldError && <FieldError>{fieldError}</FieldError>}
              {serverError && <ErrorNotice message={serverError} />}
              {loading && <div className="rounded-xl border border-violet-300/15 bg-violet-300/[0.045] p-3 text-[11px] text-violet-100/80" role="status" data-testid="status-progress">Generating on your certificate service. Files will download when the operation completes.</div>}
              {result && <ResultPanel result={result} onInspect={inspectGenerated} onCopyCsr={copyCsr} />}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-4">
                <button type="button" onClick={() => { setFieldError(''); setServerError(''); setResult(null); setStep(1); }} className="secondary-button min-h-10 px-3 text-[11px]" disabled={loading} data-testid="button-edit-request"><ArrowLeft size={14} />Edit request</button>
                <button type="submit" disabled={loading} className="primary-button min-h-10 px-4 text-[12px]" data-testid="button-generate">
                  {loading ? <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" /> : <WandSparkles size={15} />}
                  {loading ? 'Generating securely…' : mode === 'certificate' ? 'Generate certificate' : 'Generate CSR'}
                </button>
              </div>
            </form>
          )}
        </section>

        <aside className="space-y-4">
          <section className="glass-panel rounded-2xl p-5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-violet-200/75">Key handling</p>
            <h2 className="mt-1.5 font-display text-lg font-semibold text-[#ebe9f3]">Sensitive by design.</h2>
            <div className="mt-4 space-y-3">
              <SecurityPoint icon={<LockKeyhole size={14} />} text="Private keys and passphrases stay in memory only for the request." />
              <SecurityPoint icon={<Download size={14} />} text="Generated artifacts download directly. Private-key contents are never rendered." />
              <SecurityPoint icon={<KeyRound size={14} />} text="Downloaded private keys are encrypted with your export passphrase." />
            </div>
          </section>
          <section className="glass-panel rounded-2xl p-5">
            <div className="flex items-center gap-2 text-[12px] font-semibold text-[#d9d6e4]"><Fingerprint size={14} className="text-violet-200" />What the service returns</div>
            <p className="mt-2 text-[11px] leading-5 text-[#888597]">Certificates include parsed inspection details and extensions. CSR results include signature verification and requested extensions. The private key is never kept with those results.</p>
          </section>
        </aside>
      </div>
    </div>
  );
}

function IdentityStep({ subject, setSubject, sans, setSans }: { subject: SubjectForm; setSubject: (subject: SubjectForm) => void; sans: SubjectAltNameRequest[]; setSans: (sans: SubjectAltNameRequest[]) => void }) {
  const field = (key: keyof CertificateSubjectRequest, label: string, hint: string, required = false) => (
    <label key={key} className="block text-[12px] font-medium text-[#d7d4e1]">
      {label}{required && <span className="ml-1 text-violet-200">*</span>}
      <input value={subject[key] ?? ''} onChange={(event) => setSubject({ ...subject, [key]: event.target.value })} className="field-input mt-2 text-[12px]" placeholder={hint} required={required} autoComplete="off" data-testid={`input-subject-${key}`} />
      {required && <span className="mt-1 block text-[10px] font-normal text-[#777486]">Required. This is the primary identity in the distinguished name.</span>}
    </label>
  );
  return (
    <>
      <div>
        <h2 className="font-display text-base font-semibold text-[#e8e5ef]">Subject identity</h2>
        <p className="mt-1 text-[11px] leading-5 text-[#888597]">Use the identity values that should be included in the certificate or requested by the issuing authority. Enter a Common Name or a SAN; a DNS or IP SAN can be the primary identity.</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        {field('common_name', 'Common name', 'service.example.net')}
        {field('organization', 'Organization', 'Northline Systems')}
        {field('organizational_unit', 'Organizational unit', 'Platform Operations')}
        {field('email_address', 'Email address', 'operator@example.net')}
        {field('country', 'Country', 'GB')}
        {field('state_or_province', 'State or province', 'West Midlands')}
        {field('locality', 'Locality', 'Birmingham')}
      </div>
      <div className="border-t border-white/[0.06] pt-4">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
          <div><h3 className="text-[12px] font-semibold text-[#dedbe8]">Subject alternative names</h3><p className="mt-1 text-[10px] text-[#817e91]">Add every DNS name, IP address, email, or URI that clients should recognize.</p></div>
          <button type="button" onClick={() => setSans([...sans, { type: 'DNS', value: '' }])} className="secondary-button min-h-8 px-2.5 text-[10px]" data-testid="button-add-san"><Plus size={13} />Add SAN</button>
        </div>
        {sans.length === 0 ? <p className="rounded-xl border border-dashed border-white/[0.08] bg-white/[0.015] px-3 py-4 text-center text-[11px] text-[#777486]">No SANs added. Use a SAN for browser and service hostname validation.</p> : (
          <div className="space-y-2">
            {sans.map((san, index) => (
              <div key={`san-${index}`} className="grid grid-cols-[108px_minmax(0,1fr)_36px] gap-2">
                <select value={san.type} onChange={(event) => setSans(sans.map((item, itemIndex) => itemIndex === index ? { ...item, type: event.target.value as SubjectAltNameRequest['type'] } : item))} className="field-select text-[11px]" aria-label={`SAN type ${index + 1}`} data-testid={`select-san-type-${index}`}>
                  <option value="DNS">DNS</option><option value="IP">IP address</option><option value="EMAIL">Email</option><option value="URI">URI</option>
                </select>
                <input value={san.value} onChange={(event) => setSans(sans.map((item, itemIndex) => itemIndex === index ? { ...item, value: event.target.value } : item))} className="field-input min-w-0 text-[11px]" placeholder={sanPlaceholder(san.type)} aria-label={`${san.type} SAN value ${index + 1}`} data-testid={`input-san-value-${index}`} />
                <button type="button" onClick={() => setSans(sans.filter((_, itemIndex) => itemIndex !== index))} className="secondary-button min-h-10 px-2 text-rose-200/80 hover:text-rose-100" aria-label={`Remove SAN ${index + 1}`} data-testid={`button-remove-san-${index}`}><Trash2 size={14} /></button>
              </div>
            ))}
          </div>
        )}
        <p className="mt-2 text-[10px] text-[#777486]">Values are sent exactly as entered. Wildcards are supported only where the target usage permits them.</p>
      </div>
    </>
  );
}

function KeyValidityStep(props: {
  mode: BuildMode;
  algorithm: KeyAlgorithm;
  setAlgorithm: (value: KeyAlgorithm) => void;
  keySource: 'generate' | 'import';
  setKeySource: (value: 'generate' | 'import') => void;
  importedKey: File | null;
  setImportedKey: (file: File | null) => void;
  importPassphrase: string;
  setImportPassphrase: (value: string) => void;
  purpose: CertificatePurpose;
  setPurpose: (value: CertificatePurpose) => void;
  notBefore: string;
  setNotBefore: (value: string) => void;
  notAfter: string;
  setNotAfter: (value: string) => void;
  format: 'PEM' | 'DER';
  setFormat: (value: 'PEM' | 'DER') => void;
  exportPassphrase: string;
  setExportPassphrase: (value: string) => void;
  confirmPassphrase: string;
  setConfirmPassphrase: (value: string) => void;
}) {
  return (
    <>
      <div><h2 className="font-display text-base font-semibold text-[#e8e5ef]">Key and usage</h2><p className="mt-1 text-[11px] leading-5 text-[#888597]">Choose how the key is supplied, intended purpose, artifact format, and the validity window when issuing a self-signed certificate.</p></div>
      <div>
        <p className="mb-2 text-[12px] font-medium text-[#d7d4e1]">Private key source</p>
        <div className="grid grid-cols-2 gap-2">
          <ChoiceCard selected={props.keySource === 'generate'} onClick={() => props.setKeySource('generate')} title="Generate new key" copy="Created by the local service" testId="choice-key-generate" />
          <ChoiceCard selected={props.keySource === 'import'} onClick={() => props.setKeySource('import')} title="Import existing key" copy="Read from a local key file" testId="choice-key-import" />
        </div>
      </div>
      {props.keySource === 'generate' ? (
        <label className="block text-[12px] font-medium text-[#d7d4e1]">Key algorithm
          <select value={props.algorithm} onChange={(event) => props.setAlgorithm(event.target.value as KeyAlgorithm)} className="field-select mt-2 text-[12px]" data-testid="select-key-algorithm">
            {algorithms.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <span className="mt-1.5 block text-[10px] font-normal text-[#777486]">RSA and ECDSA use SHA-256 signatures. Ed25519 uses EdDSA with no separate hash and may not be accepted by every client or CA.</span>
        </label>
      ) : (
        <div className="space-y-4">
          <FileField label="Imported private key" accept=".pem,.key,.pk8,.der" helper="PEM or DER private key" file={props.importedKey} onChange={props.setImportedKey} testId="create-imported-key" />
          <SecretInput label="Existing key passphrase" value={props.importPassphrase} onChange={props.setImportPassphrase} placeholder="Only if the imported key is encrypted" testId="input-import-key-passphrase" />
          <p className="text-[10px] text-[#777486]">The key type is detected from the imported file; the algorithm field is sent as null.</p>
        </div>
      )}
      <label className="block text-[12px] font-medium text-[#d7d4e1]">Purpose
        <select value={props.purpose} onChange={(event) => props.setPurpose(event.target.value as CertificatePurpose)} className="field-select mt-2 text-[12px]" data-testid="select-purpose">
          {purposes.map((item) => <option key={item.value} value={item.value}>{item.label} — {item.note}</option>)}
        </select>
      </label>
      {props.mode === 'certificate' && (
        <div className="space-y-3 rounded-xl border border-white/[0.055] bg-white/[0.015] p-3.5">
          <div><h3 className="text-[12px] font-semibold text-[#dedbe8]">Certificate validity</h3><p className="mt-1 text-[10px] leading-4 text-[#817e91]">Dates are submitted as timezone-qualified UTC timestamps.</p></div>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block text-[11px] font-medium text-[#c9c6d4]">Valid from<input type="datetime-local" value={props.notBefore} onChange={(event) => props.setNotBefore(event.target.value)} className="field-input mt-2 text-[11px]" data-testid="input-not-before" /></label>
            <label className="block text-[11px] font-medium text-[#c9c6d4]">Expires<input type="datetime-local" value={props.notAfter} onChange={(event) => props.setNotAfter(event.target.value)} className="field-input mt-2 text-[11px]" data-testid="input-not-after" /></label>
          </div>
        </div>
      )}
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block text-[12px] font-medium text-[#d7d4e1]">{props.mode === 'certificate' ? 'Certificate format' : 'CSR format'}
          <select value={props.format} onChange={(event) => props.setFormat(event.target.value as 'PEM' | 'DER')} className="field-select mt-2 text-[12px]" data-testid="select-output-format"><option value="PEM">PEM</option><option value="DER">DER</option></select>
        </label>
        <div className="hidden sm:block" />
        <SecretInput label="Private-key export passphrase" value={props.exportPassphrase} onChange={props.setExportPassphrase} placeholder="Required to encrypt downloaded key" testId="input-export-passphrase" />
        <SecretInput label="Confirm export passphrase" value={props.confirmPassphrase} onChange={props.setConfirmPassphrase} placeholder="Enter the same passphrase again" testId="input-confirm-export-passphrase" />
      </div>
      <p className="rounded-xl border border-emerald-300/[0.1] bg-emerald-300/[0.025] px-3 py-2.5 text-[10px] leading-5 text-emerald-100/65">The confirmation stays in this form only; only the export passphrase is sent. Both passphrase fields and any imported key are cleared when generation ends.</p>
    </>
  );
}

function ReviewPanel(props: { mode: BuildMode; subject: SubjectForm; sans: SubjectAltNameRequest[]; keySource: 'generate' | 'import'; algorithm: KeyAlgorithm; purpose: CertificatePurpose; notBefore: string; notAfter: string; format: 'PEM' | 'DER'; importedKeyName?: string }) {
  const keyUsage = expectedKeyUsage(props.purpose, props.keySource, props.algorithm);
  const extendedKeyUsage = {
    'tls-server': 'TLS Web Server Authentication',
    'tls-client': 'TLS Web Client Authentication',
    smime: 'Email Protection',
    general: 'Not set',
  }[props.purpose];
  const signatureAlgorithm = props.keySource === 'import'
    ? 'Derived from imported key'
    : props.algorithm === 'Ed25519'
      ? 'Ed25519 / EdDSA'
      : props.algorithm.startsWith('RSA')
        ? 'SHA-256 with RSA'
        : 'ECDSA with SHA-256';
  return (
    <div className="space-y-4">
      <div><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-violet-200/75">Final review</p><h2 className="mt-1 font-display text-base font-semibold text-[#e8e5ef]">Verify the request before generation</h2><p className="mt-1 text-[11px] leading-5 text-[#888597]">The request will be processed by the API running on your server. Review the subject and key settings carefully.</p></div>
      <div className="grid gap-3 sm:grid-cols-2">
        <ReviewBlock title="Artifact" value={props.mode === 'certificate' ? 'Self-signed X.509 certificate' : 'PKCS#10 certificate signing request'} />
        <ReviewBlock title="Subject" value={subjectText(props.subject)} />
        <ReviewBlock title="Key source" value={props.keySource === 'generate' ? `Generate · ${props.algorithm}` : `Import · ${props.importedKeyName || 'private key selected'}`} />
        <ReviewBlock title="Purpose and encoding" value={`${purposeLabel(props.purpose)} · ${props.format}`} />
        <ReviewBlock title="Signature algorithm" value={signatureAlgorithm} />
        <ReviewBlock title="Key usage" value={keyUsage} />
        <ReviewBlock title="Extended key usage" value={extendedKeyUsage} />
        <ReviewBlock title="Basic constraints" value="CA:FALSE" />
        {props.mode === 'certificate' && <ReviewBlock title="Validity" value={`${new Date(props.notBefore).toLocaleString()} – ${new Date(props.notAfter).toLocaleString()} (local display; submitted as UTC)`} />}
        <ReviewBlock title="Subject alternative names" value={props.sans.length ? props.sans.map((san) => `${san.type}: ${san.value}`).join('\n') : 'None'} />
      </div>
      <div className="rounded-xl border border-white/[0.055] bg-[#14151f]/70 p-3.5">
        <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[#858294]">What happens next</p>
        <p className="mt-1.5 text-[11px] leading-5 text-[#a09cad]">The public {props.mode === 'certificate' ? 'certificate' : 'CSR'} and encrypted private key will download to this device. Private-key contents are not shown or retained in the result panel.</p>
      </div>
    </div>
  );
}

function ResultPanel({ result, onInspect, onCopyCsr }: { result: SafeResult; onInspect: () => void; onCopyCsr: () => void }) {
  if (result.kind === 'certificate') {
    const inspection = result.inspection;
    return (
      <section className="rounded-xl border border-emerald-300/[0.13] bg-emerald-300/[0.025] p-4" data-testid="panel-generated-result">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div><p className="text-[10px] font-semibold uppercase tracking-[0.13em] text-emerald-200/80">Certificate created</p><h3 className="mt-1 font-display text-[15px] font-semibold text-[#e7e4ef]">Files downloaded</h3><p className="mt-1 text-[10px] text-[#9290a0]">{inspection.subject} · {inspection.public_key_algorithm}{inspection.public_key_size ? ` · ${inspection.public_key_size} bit` : ''}</p></div>
          <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold ${result.verified ? 'border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200' : 'border-amber-300/20 bg-amber-300/[0.06] text-amber-100'}`}>{result.verified ? 'Self-signature verified' : 'Self-signature not verified'}</span>
        </div>
        <div className="mt-3 grid gap-x-5 sm:grid-cols-2"><Metadata label="Issuer" value={inspection.issuer} /><Metadata label="Serial number" value={inspection.serial_number} /><Metadata label="Signature" value={inspection.signature_algorithm} /><Metadata label="Public key" value={`${inspection.public_key_algorithm}${inspection.public_key_size ? ` · ${inspection.public_key_size} bit` : ''}`} /><Metadata label="Valid from" value={inspection.not_before} /><Metadata label="Expires" value={inspection.not_after} /></div>
        <div className="mt-3 rounded-lg border border-white/[0.05] bg-[#14151f]/65 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.11em] text-[#858294]">Extensions</p>
          <p className="mt-1.5 text-[10px] leading-5 text-[#a09cad]">Key usage: {inspection.extensions.key_usage.join(', ') || 'none'}<br />Extended key usage: {inspection.extensions.extended_key_usage.join(', ') || 'none'}<br />Basic constraints: {inspection.extensions.basic_constraints || 'none'}<br />Subject key identifier: {inspection.extensions.subject_key_identifier || 'none'}<br />Authority key identifier: {inspection.extensions.authority_key_identifier || 'none'}</p>
        </div>
        <p className="mt-3 flex items-start gap-2 text-[10px] leading-5 text-amber-100/75"><AlertTriangle size={13} className="mt-0.5 shrink-0" />A valid self-signature does not establish trust. Configure trust on clients or obtain a certificate from a trusted CA.</p>
        <button type="button" onClick={onInspect} className="secondary-button mt-3 min-h-9 px-3 text-[10px]" data-testid="button-inspect-generated"><Fingerprint size={13} />Open in certificate inspector</button>
      </section>
    );
  }
  return (
    <section className="rounded-xl border border-emerald-300/[0.13] bg-emerald-300/[0.025] p-4" data-testid="panel-generated-result">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><p className="text-[10px] font-semibold uppercase tracking-[0.13em] text-emerald-200/80">CSR created</p><h3 className="mt-1 font-display text-[15px] font-semibold text-[#e7e4ef]">Request downloaded</h3><p className="mt-1 text-[10px] text-[#9290a0]">{result.filename} · {formatBytes(result.size)}</p></div>
        <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold ${result.verified ? 'border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200' : 'border-amber-300/20 bg-amber-300/[0.06] text-amber-100'}`}>{result.verified ? 'Signature verified' : 'Signature not verified'}</span>
      </div>
      <div className="mt-3 grid gap-x-5 sm:grid-cols-2"><Metadata label="Subject" value={result.subject} /><Metadata label="Public key" value={result.publicKeyAlgorithm} /><Metadata label="Signature" value={result.signatureAlgorithm} /><Metadata label="Public-key fingerprint" value={result.publicKeyFingerprint} /><Metadata label="Requested SANs" value={result.sans.join(', ') || 'none'} /></div>
      <div className="mt-3 rounded-lg border border-white/[0.05] bg-[#14151f]/65 p-3">
        <p className="text-[10px] font-semibold uppercase tracking-[0.11em] text-[#858294]">Requested extensions</p>
        <p className="mt-1.5 text-[10px] leading-5 text-[#a09cad]">Key usage: {result.extensions.key_usage.join(', ') || 'none'}<br />Extended key usage: {result.extensions.extended_key_usage.join(', ') || 'none'}<br />Basic constraints: {result.extensions.basic_constraints || 'none'}<br />Subject key identifier: {result.extensions.subject_key_identifier || 'none'}<br />Authority key identifier: {result.extensions.authority_key_identifier || 'none'}</p>
      </div>
      <p className="mt-3 text-[10px] leading-5 text-amber-100/75">This CSR is a request, not a certificate. Send it to a certificate authority; the CA must issue a certificate before it can be used for authentication.</p>
      <button type="button" onClick={onCopyCsr} className="secondary-button mt-3 min-h-9 px-3 text-[10px]" disabled={!result.copyable} data-testid="button-copy-csr"><Clipboard size={13} />Copy CSR PEM</button>
    </section>
  );
}

function TrustNote({ icon, title, copy }: { icon: ReactNode; title: string; copy: string }) {
  return <div className="flex gap-3"><span className="mt-0.5 text-amber-100/80">{icon}</span><div><p className="text-[11px] font-semibold text-amber-50/90">{title}</p><p className="mt-1 text-[10px] leading-5 text-amber-50/60">{copy}</p></div></div>;
}

function SecurityPoint({ icon, text }: { icon: ReactNode; text: string }) {
  return <div className="flex gap-2.5 text-[11px] leading-5 text-[#9996a8]"><span className="mt-0.5 text-emerald-200">{icon}</span>{text}</div>;
}

function ChoiceCard({ selected, onClick, title, copy, testId }: { selected: boolean; onClick: () => void; title: string; copy: string; testId: string }) {
  return <button type="button" onClick={onClick} className={`rounded-xl border p-3 text-left transition ${selected ? 'border-violet-300/25 bg-violet-300/[0.07]' : 'border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.04]'}`} aria-pressed={selected} data-testid={testId}><span className="block text-[11px] font-semibold text-[#dedbe8]">{title}</span><span className="mt-1 block text-[10px] text-[#858294]">{copy}</span></button>;
}

function SecretInput({ label, value, onChange, placeholder, testId }: { label: string; value: string; onChange: (value: string) => void; placeholder: string; testId: string }) {
  return <label className="block text-[12px] font-medium text-[#d7d4e1]">{label}<input type="password" autoComplete="new-password" value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="field-input mt-2 text-[12px]" data-testid={testId} /><span className="mt-1 block text-[10px] font-normal text-[#777486]">Never saved in browser storage or included in a URL.</span></label>;
}

function ReviewBlock({ title, value }: { title: string; value: string }) {
  return <div className="rounded-xl border border-white/[0.055] bg-white/[0.018] p-3"><p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-[#858294]">{title}</p><p className="mt-1.5 whitespace-pre-line break-words text-[11px] leading-5 text-[#d2cfdd]">{value || 'Not provided'}</p></div>;
}

function Metadata({ label, value }: { label: string; value: string }) {
  return <div className="border-b border-white/[0.05] py-2 last:border-0"><p className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#858294]">{label}</p><p className="mt-1 break-all text-[10px] leading-4 text-[#d0cddd]">{value || '—'}</p></div>;
}

function FieldError({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-rose-300/15 bg-rose-300/[0.045] px-3 py-2.5 text-[11px] leading-5 text-rose-100/85" role="alert" data-testid="text-field-error">{children}</p>;
}

function isValidSan(san: SubjectAltNameRequest) {
  const value = san.value;
  if (!value || value !== value.trim() || !/^[\x21-\x7E]+$/.test(value)) {
    return false;
  }
  if (san.type === 'DNS') {
    if (value.length > 253 || value.endsWith('.')) return false;
    const name = value.startsWith('*.') ? value.slice(2) : value;
    if (name.includes('*')) return false;
    const labels = name.split('.');
    return labels.every((label) =>
      label.length > 0
      && label.length <= 63
      && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label)
    );
  }
  if (san.type === 'IP') {
    if (value.includes(':')) {
      try {
        return new URL(`http://[${value}]/`).hostname.length > 0;
      } catch {
        return false;
      }
    }
    const octets = value.split('.');
    return octets.length === 4 && octets.every((octet) =>
      /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255
    );
  }
  if (san.type === 'EMAIL') return isValidEmail(value);
  return /^[A-Za-z][A-Za-z0-9+.-]*:[^\s]*$/.test(value);
}

function isValidEmail(value: string) {
  if (!/^[\x21-\x7E]+$/.test(value) || value.length > 254 || value.split('@').length !== 2) {
    return false;
  }
  const [local, domain] = value.split('@');
  return local.length > 0
    && local.length <= 64
    && /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)
    && isValidSan({ type: 'DNS', value: domain });
}

function isStrongExportPassphrase(value: string) {
  if (value.length >= 16) return true;
  if (value.length < 12) return false;
  const characterClasses = [
    /[a-z]/.test(value),
    /[A-Z]/.test(value),
    /\d/.test(value),
    /[^A-Za-z0-9]/.test(value),
  ];
  return characterClasses.filter(Boolean).length >= 3;
}

function expectedKeyUsage(
  purpose: CertificatePurpose,
  keySource: 'generate' | 'import',
  algorithm: KeyAlgorithm,
) {
  const rsaKey = keySource === 'import' || algorithm.startsWith('RSA');
  const needsEncryption = purpose === 'tls-server' || purpose === 'smime';
  return rsaKey && needsEncryption
    ? 'Digital signature; key encipherment for RSA keys'
    : 'Digital signature';
}

function sanPlaceholder(type: SubjectAltNameRequest['type']) {
  if (type === 'DNS') return 'api.example.net';
  if (type === 'IP') return '192.0.2.18';
  if (type === 'EMAIL') return 'pki@example.net';
  return 'spiffe://example.net/service';
}

function purposeLabel(value: CertificatePurpose) {
  return purposes.find((item) => item.value === value)?.label ?? value;
}
