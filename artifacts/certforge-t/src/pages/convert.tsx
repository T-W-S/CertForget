import { type FormEvent, type ReactNode, useState } from 'react';
import { ArrowDownToLine, ArrowLeftRight, ArchiveRestore, ChevronRight, Download, FileKey2, LockKeyhole, PackageCheck, ShieldCheck, Upload } from 'lucide-react';
import { Link } from 'wouter';
import { FileField } from '@/components/file-field';
import { ErrorNotice, SuccessNotice } from '@/components/feedback';
import { CommandPreview } from '@/components/command-preview';
import { api, downloadBase64, formatBytes } from '@/lib/api';

type ToolMode = 'convert' | 'export' | 'import';

const modes: { id: ToolMode; label: string; icon: typeof ArrowLeftRight }[] = [
  { id: 'convert', label: 'PEM ↔ DER', icon: ArrowLeftRight },
  { id: 'export', label: 'Export PKCS#12', icon: PackageCheck },
  { id: 'import', label: 'Import PKCS#12', icon: ArchiveRestore },
];

export default function ConvertPage() {
  const [mode, setMode] = useState<ToolMode>('convert');
  const [certificate, setCertificate] = useState<File | null>(null);
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [pfxFile, setPfxFile] = useState<File | null>(null);
  const [inputFormat, setInputFormat] = useState<'PEM' | 'DER'>('PEM');
  const [targetFormat, setTargetFormat] = useState<'PEM' | 'DER'>('DER');
  const [privatePassphrase, setPrivatePassphrase] = useState('');
  const [pfxPassphrase, setPfxPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState<{ message: string; filename?: string; size?: number } | null>(null);

  const clearStatus = () => {
    setError('');
    setSuccess(null);
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (loading) {
      return;
    }
    clearStatus();
    setLoading(true);
    const body = new FormData();
    try {
      if (mode === 'convert' && certificate) {
        body.append('certificate_file', certificate);
        body.append('input_format', inputFormat);
        body.append('target_format', targetFormat);
        const output = await api.convert(body);
        downloadBase64(output);
        setSuccess({ message: `${output.filename} is ready and has been downloaded.`, filename: output.filename, size: output.size_bytes });
      } else if (mode === 'export' && certificate && privateKey) {
        body.append('certificate_file', certificate);
        body.append('private_key_file', privateKey);
        if (privatePassphrase) {
          body.append('private_key_passphrase', privatePassphrase);
        }
        if (pfxPassphrase) {
          body.append('pfx_passphrase', pfxPassphrase);
        }
        const output = await api.exportPfx(body);
        downloadBase64(output);
        setSuccess({ message: `${output.filename} is ready and has been downloaded.`, filename: output.filename, size: output.size_bytes });
      } else if (mode === 'import' && pfxFile) {
        body.append('pfx_file', pfxFile);
        if (pfxPassphrase) {
          body.append('pfx_passphrase', pfxPassphrase);
        }
        if (privatePassphrase) {
          body.append('private_key_passphrase', privatePassphrase);
        }
        const output = await api.importPfx(body);
        output.files.forEach((file) => downloadBase64(file));
        setSuccess({ message: `${output.certificate_count} certificate${output.certificate_count === 1 ? '' : 's'} imported. ${output.files.length} extracted file${output.files.length === 1 ? '' : 's'} downloaded.`, filename: `${output.files.length} files`, size: output.files.reduce((sum, file) => sum + file.size_bytes, 0) });
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The format operation failed.');
    } finally {
      body.delete('private_key_file');
      body.delete('private_key_passphrase');
      body.delete('pfx_passphrase');
      setPrivateKey(null);
      setPfxFile(null);
      setPrivatePassphrase('');
      setPfxPassphrase('');
      setLoading(false);
    }
  };

  const selectMode = (next: ToolMode) => {
    setMode(next);
    setCertificate(null);
    setPrivateKey(null);
    setPfxFile(null);
    setPrivatePassphrase('');
    setPfxPassphrase('');
    clearStatus();
  };

  return (
    <div className="app-main page-enter">
      <div className="mb-8 flex items-center gap-2 text-xs text-[#8a879a]"><Link href="/" className="hover:text-[#d2cede]">Workspace</Link><ChevronRight size={13} /><span className="text-[#cbc8d6]">Format tools</span></div>
      <div className="mb-7">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-violet-300/10 bg-violet-300/[0.08] text-violet-200"><FileKey2 size={19} /></div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-violet-300/80">Format operations</p>
        <h1 className="mt-1.5 font-display text-3xl font-semibold tracking-tight text-[#f0edf6]">Convert & package</h1>
        <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[#9996a8]">Convert certificate encoding or move certificates and keys through a PKCS#12 archive.</p>
      </div>
      <div className="grid items-start gap-5 xl:grid-cols-[minmax(400px,0.9fr)_minmax(340px,1.1fr)]">
        <section className="glass-panel rounded-2xl p-5 sm:p-6">
          <div className="grid grid-cols-3 rounded-xl border border-white/[0.06] bg-[#171824]/70 p-1" role="tablist" aria-label="Format operation">
            {modes.map((item) => {
              const Icon = item.icon;
              return <button key={item.id} type="button" role="tab" aria-selected={mode === item.id} onClick={() => selectMode(item.id)} className={`flex min-h-10 flex-col items-center justify-center gap-1 rounded-lg px-1.5 py-1 text-[9px] font-medium transition sm:flex-row sm:gap-1.5 sm:text-[10px] ${mode === item.id ? 'bg-violet-300/[0.13] text-violet-100' : 'text-[#8e8a9e] hover:text-[#ddd9e8]'}`} data-testid={`tab-${item.id}`}><Icon size={14} />{item.label}</button>;
            })}
          </div>
          {mode === 'convert' && (
            <form onSubmit={submit} className="mt-5 space-y-5">
              <div><h2 className="font-display text-base font-semibold text-[#e8e5ef]">Convert certificate encoding</h2><p className="mt-1 text-[11px] leading-5 text-[#888597]">Output is downloaded directly. No certificate content is shown.</p></div>
              <FileField label="Certificate" accept=".pem,.crt,.cer,.der" helper="PEM or DER X.509 certificate" file={certificate} onChange={setCertificate} testId="convert-certificate" />
              <div className="grid grid-cols-[1fr_auto_1fr] items-end gap-3">
                <label className="block text-[12px] font-medium text-[#d7d4e1]">Input format<select value={inputFormat} onChange={(event) => setInputFormat(event.target.value as 'PEM' | 'DER')} className="field-select mt-2 text-[12px]" data-testid="select-input-format"><option value="PEM">PEM</option><option value="DER">DER</option></select></label>
                <span className="mb-3 text-[#8b859e]"><ArrowLeftRight size={16} /></span>
                <label className="block text-[12px] font-medium text-[#d7d4e1]">Target format<select value={targetFormat} onChange={(event) => setTargetFormat(event.target.value as 'PEM' | 'DER')} className="field-select mt-2 text-[12px]" data-testid="select-target-format"><option value="PEM">PEM</option><option value="DER">DER</option></select></label>
              </div>
              <CommandPreview lines={[`openssl x509 -inform ${inputFormat} -in certificate.${inputFormat.toLowerCase()} \\`, `  -outform ${targetFormat} -out certificate.${targetFormat.toLowerCase()}`]} />
              <SubmitAction loading={loading} label="Convert & download" icon={<ArrowDownToLine size={16} />} disabled={!certificate} />
            </form>
          )}
          {mode === 'export' && (
            <form onSubmit={submit} className="mt-5 space-y-4">
              <div><h2 className="font-display text-base font-semibold text-[#e8e5ef]">Export a PKCS#12 archive</h2><p className="mt-1 text-[11px] leading-5 text-[#888597]">Package your certificate and its matching private key as a PFX file.</p></div>
              <FileField label="Certificate" accept=".pem,.crt,.cer,.der" helper="PEM or DER X.509 certificate" file={certificate} onChange={setCertificate} testId="export-certificate" />
              <FileField label="Private key" accept=".pem,.key,.pk8" helper="PEM or PKCS#8 key" file={privateKey} onChange={setPrivateKey} testId="export-private-key" />
              <SecretInput id="export-key-passphrase" label="Private key passphrase" value={privatePassphrase} onChange={setPrivatePassphrase} optional testId="input-export-private-passphrase" />
              <SecretInput id="export-pfx-passphrase" label="New PFX passphrase" value={pfxPassphrase} onChange={setPfxPassphrase} optional testId="input-export-pfx-passphrase" />
              <CommandPreview lines={['openssl pkcs12 -export -in certificate.pem \\', '  -inkey private-key.pem -out certificate.p12']} />
              <p className="text-[10px] leading-5 text-amber-100/70">Without a PFX passphrase, the exported archive is not password-protected.</p>
              <SubmitAction loading={loading} label="Export & download PFX" icon={<Download size={16} />} disabled={!certificate || !privateKey} />
            </form>
          )}
          {mode === 'import' && (
            <form onSubmit={submit} className="mt-5 space-y-4">
              <div><h2 className="font-display text-base font-semibold text-[#e8e5ef]">Import a PKCS#12 archive</h2><p className="mt-1 text-[11px] leading-5 text-[#888597]">Extract the certificate and key files. Extracted contents are downloaded, never displayed.</p></div>
              <FileField label="PFX / PKCS#12 archive" accept=".p12,.pfx" helper="P12 or PFX archive" file={pfxFile} onChange={setPfxFile} testId="import-pfx" />
              <SecretInput id="import-pfx-passphrase" label="Archive passphrase" value={pfxPassphrase} onChange={setPfxPassphrase} optional testId="input-import-pfx-passphrase" />
              <SecretInput id="import-key-passphrase" label="Passphrase for extracted private key" value={privatePassphrase} onChange={setPrivatePassphrase} optional testId="input-import-key-passphrase" />
              <CommandPreview lines={['openssl pkcs12 -in archive.p12 -nodes \\', '  -out extracted.pem']} />
              <p className="text-[10px] leading-5 text-amber-100/70">Without an output passphrase, the downloaded private-key file is unencrypted.</p>
              <SubmitAction loading={loading} label="Import & download files" icon={<Upload size={16} />} disabled={!pfxFile} />
            </form>
          )}
          {error && <div className="mt-4"><ErrorNotice message={error} /></div>}
          {success && <div className="mt-4"><SuccessNotice><span className="block font-semibold">{success.message}</span>{success.filename && <span className="mt-1 block text-[11px] text-emerald-100/65">{success.filename}{success.size !== undefined ? ` · ${formatBytes(success.size)}` : ''}</span>}</SuccessNotice></div>}
        </section>
        <aside className="space-y-4">
          <section className="glass-panel rounded-2xl p-5 sm:p-6">
            <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-violet-200/75">Handling sensitive material</p>
            <h2 className="mt-1.5 font-display text-lg font-semibold text-[#ebe9f3]">Output never enters the page.</h2>
            <p className="mt-2 text-[12px] leading-6 text-[#9996a8]">Binary payloads are decoded only long enough to trigger a local download. PKCS#12 private-key contents are never rendered or stored in component state.</p>
            <div className="mt-5 space-y-3">
              <SecurityRow icon={<LockKeyhole size={15} />} title="Request-scoped secrets" copy="Private-key and archive passphrases are cleared when processing ends." />
              <SecurityRow icon={<ShieldCheck size={15} />} title="Server-side processing" copy="The API performs all cryptographic operations within your environment." />
              <SecurityRow icon={<Download size={15} />} title="Direct binary download" copy="Converted and extracted files go straight to a download." />
            </div>
          </section>
          <section className="glass-panel rounded-2xl p-5">
            <div className="flex items-center gap-2 text-[12px] font-semibold text-[#d9d6e4]"><LockKeyhole size={14} className="text-emerald-300" /> Informational OpenSSL preview</div>
            <p className="mt-2 text-[11px] leading-5 text-[#888597]">Command previews describe the operation only. They are never submitted to the API, and no user-entered shell commands are accepted.</p>
          </section>
        </aside>
      </div>
    </div>
  );
}

function SecretInput({ id, label, value, onChange, optional, testId }: { id: string; label: string; value: string; onChange: (value: string) => void; optional?: boolean; testId: string }) {
  return (
    <div><label htmlFor={id} className="mb-2 block text-[12px] font-medium text-[#d7d4e1]">{label}{optional && <span className="text-[#777486]"> (optional)</span>}</label><input id={id} type="password" autoComplete="new-password" value={value} onChange={(event) => onChange(event.target.value)} placeholder="Only needed for encrypted files" className="field-input text-[12px]" data-testid={testId} /><p className="mt-1.5 text-[10px] text-[#777486]">Cleared from this form after the request completes.</p></div>
  );
}

function SubmitAction({ loading, label, icon, disabled }: { loading: boolean; label: string; icon: ReactNode; disabled: boolean }) {
  return <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-4"><span className="flex items-center gap-1.5 text-[10px] text-[#817e91]"><LockKeyhole size={12} className="text-emerald-300" />Local service only</span><button type="submit" disabled={disabled || loading} className="primary-button" data-testid="button-submit">{loading ? <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" /> : icon}{loading ? 'Processing securely…' : label}</button></div>;
}

function SecurityRow({ icon, title, copy }: { icon: ReactNode; title: string; copy: string }) {
  return <div className="flex gap-3 rounded-xl border border-white/[0.05] bg-white/[0.02] p-3"><span className="mt-0.5 text-violet-200">{icon}</span><div><p className="text-[12px] font-semibold text-[#d7d4e1]">{title}</p><p className="mt-1 text-[11px] leading-5 text-[#898698]">{copy}</p></div></div>;
}
