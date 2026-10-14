import { type FormEvent, useEffect, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { ChevronRight, Clipboard, Fingerprint, LockKeyhole } from 'lucide-react';
import { Link } from 'wouter';
import { FileField } from '@/components/file-field';
import { ErrorNotice, LoadingButton } from '@/components/feedback';
import { CommandPreview } from '@/components/command-preview';
import { api, type InspectResponse } from '@/lib/api';

function Detail({ label, value, mono = false }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="border-b border-white/[0.06] py-3 last:border-0">
      <dt className="text-[10px] font-medium uppercase tracking-[0.11em] text-[#858294]">{label}</dt>
      <dd className={`mt-1.5 break-words text-[12px] leading-5 text-[#e0dde9] ${mono ? 'font-mono-ui text-[11px]' : ''}`} data-testid={`value-${label.toLowerCase().replaceAll(' ', '-')}`}>{value || '—'}</dd>
    </div>
  );
}

function CertificateResult({ result }: { result: InspectResponse }) {
  const copyFingerprint = async () => {
    await navigator.clipboard.writeText(result.sha256_fingerprint);
  };
  return (
    <section className="glass-panel rounded-2xl p-5 sm:p-6" data-testid="panel-inspection-result">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/[0.07] pb-4">
        <div><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-violet-200/75">Inspection result</p><h2 className="mt-1.5 font-display text-lg font-semibold text-[#ebe9f3]">Certificate details</h2></div>
        <span className={`rounded-full border px-3 py-1.5 text-[10px] font-semibold ${result.is_valid_now ? 'border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200' : 'border-rose-300/20 bg-rose-300/[0.06] text-rose-200'}`}>{result.is_valid_now ? 'Valid now' : 'Not currently valid'}</span>
      </div>
      <div className="mt-2 grid gap-x-8 sm:grid-cols-2">
        <dl><Detail label="Subject" value={result.subject} /><Detail label="Issuer" value={result.issuer} /><Detail label="Serial number" value={result.serial_number} mono /><Detail label="Valid from" value={result.not_before} /></dl>
        <dl><Detail label="Valid until" value={result.not_after} /><Detail label="Days until expiry" value={result.days_until_expiry} /><Detail label="Signature algorithm" value={result.signature_algorithm} mono /><Detail label="Public key" value={`${result.public_key_algorithm}${result.public_key_size ? ` · ${result.public_key_size} bit` : ''}`} /></dl>
      </div>
      <div className="mt-1 rounded-xl border border-white/[0.06] bg-[#171824]/75 px-4 py-3">
        <div className="mb-2 flex items-center justify-between gap-2"><p className="text-[10px] font-semibold uppercase tracking-[0.11em] text-[#858294]">SHA-256 fingerprint</p><button type="button" onClick={copyFingerprint} className="secondary-button min-h-8 px-2.5 text-[10px]" data-testid="button-copy-fingerprint"><Clipboard size={12} /> Copy</button></div>
        <p className="break-all font-mono-ui text-[10px] leading-5 text-violet-100/90" data-testid="text-fingerprint">{result.sha256_fingerprint}</p>
      </div>
      <div className="mt-4">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.11em] text-[#858294]">Subject alternative names</p>
        {result.sans.length ? <div className="flex flex-wrap gap-1.5">{result.sans.map((san, index) => <span key={`${san}-${index}`} className="rounded-md border border-white/[0.07] bg-white/[0.025] px-2 py-1 font-mono-ui text-[10px] text-[#c9c5d5]">{san}</span>)}</div> : <p className="text-xs text-[#777486]">No subject alternative names reported.</p>}
      </div>
      <p className="mt-5 border-t border-white/[0.06] pt-3 text-[10px] text-[#777486]">Validated by OpenSSL {result.openssl_version}; certificate fields parsed with Python cryptography.</p>
    </section>
  );
}

export default function InspectPage({ initialCertificate = null }: { initialCertificate?: File | null }) {
  const [certificate, setCertificate] = useState<File | null>(null);
  const [result, setResult] = useState<InspectResponse | null>(null);
  const mutation = useMutation({ mutationFn: api.inspect, onSuccess: setResult });
  useEffect(() => {
    if (!initialCertificate) {
      return;
    }
    setCertificate(initialCertificate);
    const body = new FormData();
    body.append('certificate_file', initialCertificate);
    mutation.mutate(body);
  }, [initialCertificate]);
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!certificate) {
      return;
    }
    const body = new FormData();
    body.append('certificate_file', certificate);
    mutation.mutate(body);
  };
  return (
    <div className="app-main page-enter">
      <div className="mb-8 flex items-center gap-2 text-xs text-[#8a879a]"><Link href="/" className="hover:text-[#d2cede]">Workspace</Link><ChevronRight size={13} /><span className="text-[#cbc8d6]">Inspect certificate</span></div>
      <div className="mb-7">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-violet-300/10 bg-violet-300/[0.08] text-violet-200"><Fingerprint size={19} /></div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-violet-300/80">Certificate analysis</p>
        <h1 className="mt-1.5 font-display text-3xl font-semibold tracking-tight text-[#f0edf6]">Inspect a certificate</h1>
        <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[#9996a8]">Review identity, trust dates and key metadata from a PEM or DER certificate.</p>
      </div>
      <div className="grid items-start gap-5 xl:grid-cols-[minmax(320px,0.78fr)_minmax(450px,1.22fr)]">
        <section className="glass-panel rounded-2xl p-5 sm:p-6">
          <h2 className="font-display text-base font-semibold text-[#e8e5ef]">Certificate file</h2>
          <p className="mt-1 text-[11px] leading-5 text-[#888597]">Choose the certificate to parse and inspect.</p>
          <form className="mt-5 space-y-5" onSubmit={submit}>
            <FileField label="Certificate" accept=".pem,.crt,.cer,.der" helper="PEM or DER X.509 certificate" file={certificate} onChange={setCertificate} testId="inspect-certificate" />
            <CommandPreview lines={['openssl x509 -inform <PEM|DER> -in certificate -noout -text -fingerprint -sha256']} />
            {mutation.isError && <ErrorNotice message={mutation.error.message} />}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-4">
              <span className="flex items-center gap-1.5 text-[10px] text-[#817e91]"><LockKeyhole size={12} className="text-emerald-300" />Sent only to your server</span>
              <LoadingButton loading={mutation.isPending} disabled={!certificate}>Inspect certificate</LoadingButton>
            </div>
          </form>
        </section>
        {result ? <CertificateResult result={result} /> : (
          <section className="glass-panel flex min-h-[340px] flex-col items-center justify-center rounded-2xl border-dashed px-6 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.07] bg-white/[0.025] text-[#868295]"><Fingerprint size={21} /></span>
            <h2 className="mt-4 font-display text-[15px] font-semibold text-[#d8d5e2]">Inspection results appear here</h2>
            <p className="mt-2 max-w-sm text-[12px] leading-5 text-[#858294]">Upload a certificate to view its identity, validity window, fingerprint and subject alternative names.</p>
          </section>
        )}
      </div>
    </div>
  );
}
