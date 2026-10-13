import { type FormEvent, useState } from 'react';
import { Check, ChevronRight, KeyRound, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Link } from 'wouter';
import { FileField } from '@/components/file-field';
import { ErrorNotice, LoadingButton } from '@/components/feedback';
import { CommandPreview } from '@/components/command-preview';
import { api, type MatchResponse } from '@/lib/api';

export default function MatchPage() {
  const [keyKind, setKeyKind] = useState<'private' | 'public'>('private');
  const [certificate, setCertificate] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [result, setResult] = useState<MatchResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!certificate || !keyFile || loading) {
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    const body = new FormData();
    body.append('certificate_file', certificate);
    body.append(
      keyKind === 'private' ? 'private_key_file' : 'public_key_file',
      keyFile,
    );
    if (keyKind === 'private' && passphrase) {
      body.append('private_key_passphrase', passphrase);
    }
    try {
      const response = await api.match(body);
      setResult(response);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The key comparison failed.');
    } finally {
      body.delete('private_key_file');
      body.delete('public_key_file');
      body.delete('private_key_passphrase');
      setKeyFile(null);
      setPassphrase('');
      setLoading(false);
    }
  };

  return (
    <div className="app-main page-enter">
      <div className="mb-8 flex items-center gap-2 text-xs text-[#8a879a]"><Link href="/" className="hover:text-[#d2cede]">Workspace</Link><ChevronRight size={13} /><span className="text-[#cbc8d6]">Match key pair</span></div>
      <div className="mb-7">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-violet-300/10 bg-violet-300/[0.08] text-violet-200"><KeyRound size={19} /></div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-violet-300/80">Key verification</p>
        <h1 className="mt-1.5 font-display text-3xl font-semibold tracking-tight text-[#f0edf6]">Match certificate & key</h1>
        <p className="mt-2 max-w-2xl text-[13px] leading-6 text-[#9996a8]">Compare the certificate public key with either a private key or a separate public-key file.</p>
      </div>
      <div className="grid items-start gap-5 xl:grid-cols-[minmax(330px,0.9fr)_minmax(350px,1.1fr)]">
        <section className="glass-panel rounded-2xl p-5 sm:p-6">
          <h2 className="font-display text-base font-semibold text-[#e8e5ef]">Provide the key pair</h2>
            <p className="mt-1 text-[11px] leading-5 text-[#888597]">Choose a private key or a PEM/DER SubjectPublicKeyInfo file to compare.</p>
          <form className="mt-5 space-y-4" onSubmit={submit}>
            <FileField label="Certificate" accept=".pem,.crt,.cer,.der" helper="PEM or DER X.509 certificate" file={certificate} onChange={setCertificate} testId="match-certificate" />
            <fieldset>
              <legend className="mb-2 text-[13px] font-medium text-[#d7d4e1]">Key file type</legend>
              <div className="grid grid-cols-2 gap-2">
                {(['private', 'public'] as const).map((kind) => (
                  <label key={kind} className={`flex cursor-pointer items-center gap-2 rounded-xl border px-3 py-2.5 text-[12px] transition ${keyKind === kind ? 'border-violet-300/30 bg-violet-300/[0.08] text-violet-100' : 'border-white/[0.07] text-[#9a97a9] hover:bg-white/[0.03]'}`}>
                    <input
                      type="radio"
                      name="key-kind"
                      value={kind}
                      checked={keyKind === kind}
                      onChange={() => {
                        setKeyKind(kind);
                        setKeyFile(null);
                        setPassphrase('');
                        setResult(null);
                        setError('');
                      }}
                    />
                    {kind === 'private' ? 'Private key' : 'Public key'}
                  </label>
                ))}
              </div>
            </fieldset>
            <FileField
              label={keyKind === 'private' ? 'Private key' : 'Public key'}
              accept={keyKind === 'private' ? '.pem,.key,.pk8,.der' : '.pem,.pub,.der'}
              helper={keyKind === 'private' ? 'PEM or DER private key' : 'PEM or DER SubjectPublicKeyInfo'}
              file={keyFile}
              onChange={setKeyFile}
              testId={keyKind === 'private' ? 'match-private-key' : 'match-public-key'}
            />
            {keyKind === 'private' && (
              <div>
                <label htmlFor="private-passphrase" className="mb-2 block text-[13px] font-medium text-[#d7d4e1]">Private key passphrase <span className="text-[#777486]">(optional)</span></label>
                <input id="private-passphrase" type="password" autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="Enter only if the key is encrypted" className="field-input text-[12px]" data-testid="input-private-passphrase" />
                <p className="mt-1.5 text-[10px] text-[#777486]">Never saved; cleared as soon as the request completes.</p>
              </div>
            )}
            <CommandPreview
              lines={[
                'openssl x509 -inform <detected format> -in certificate -pubkey -noout',
                keyKind === 'private'
                  ? 'openssl pkey -inform <detected format> -in private-key -pubout'
                  : 'openssl pkey -pubin -inform <detected format> -in public-key -pubout',
              ]}
            />
            {error && <ErrorNotice message={error} />}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-4">
              <span className="flex items-center gap-1.5 text-[10px] text-[#817e91]"><LockKeyhole size={12} className="text-emerald-300" />Key stays on your server</span>
              <LoadingButton loading={loading} disabled={!certificate || !keyFile}>Compare public keys</LoadingButton>
            </div>
          </form>
        </section>
        {result ? (
          <section className="glass-panel rounded-2xl p-6 sm:p-8" data-testid="panel-match-result">
            <div className="mb-5 flex items-center gap-3">
              <span className={`flex h-11 w-11 items-center justify-center rounded-xl ${result.matches ? 'bg-emerald-300/[0.1] text-emerald-200' : 'bg-rose-300/[0.09] text-rose-200'}`}>{result.matches ? <ShieldCheck size={21} /> : <ShieldAlert size={21} />}</span>
              <div><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[#858294]">Comparison complete</p><h2 className={`mt-1 font-display text-xl font-semibold ${result.matches ? 'text-emerald-100' : 'text-rose-100'}`}>{result.matches ? 'Keys match' : 'Keys do not match'}</h2></div>
            </div>
            <div className={`rounded-xl border p-4 ${result.matches ? 'border-emerald-300/15 bg-emerald-300/[0.04]' : 'border-rose-300/15 bg-rose-300/[0.04]'}`}>
              <p className="text-[13px] leading-6 text-[#d8d5e2]" data-testid="text-match-message">{result.message}</p>
            </div>
            <dl className="mt-4">
              <div className="border-b border-white/[0.06] py-3"><dt className="text-[10px] uppercase tracking-wider text-[#858294]">Certificate public key</dt><dd className="mt-1 text-[12px] text-[#e0dde9]" data-testid="text-cert-key-algorithm">{result.certificate_public_key_algorithm}</dd></div>
              <div className="border-b border-white/[0.06] py-3"><dt className="text-[10px] uppercase tracking-wider text-[#858294]">{result.key_kind === 'private' ? 'Private key public key' : 'Uploaded public key'}</dt><dd className="mt-1 text-[12px] text-[#e0dde9]" data-testid="text-uploaded-key-algorithm">{result.uploaded_key_algorithm}</dd></div>
              <div className="py-3"><dt className="text-[10px] uppercase tracking-wider text-[#858294]">Certificate fingerprint</dt><dd className="mt-1 break-all font-mono-ui text-[10px] leading-5 text-[#c7c3d3]" data-testid="text-match-fingerprint">{result.certificate_fingerprint}</dd></div>
            </dl>
            {result.matches && <p className="mt-3 flex items-center gap-2 text-[11px] text-emerald-200"><Check size={14} />The uploaded key matches the certificate public key.</p>}
          </section>
        ) : error ? (
          <section className="glass-panel flex min-h-[300px] flex-col items-center justify-center rounded-2xl px-7 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-rose-300/[0.07] text-rose-200"><ShieldAlert size={21} /></span>
            <h2 className="mt-4 font-display text-[15px] font-semibold text-[#e1dce8]">Comparison needs attention</h2>
            <p className="mt-2 max-w-sm text-[12px] leading-5 text-[#858294]">Check the files and passphrase, then submit again. Sensitive key fields have already been cleared.</p>
          </section>
        ) : (
          <section className="glass-panel flex min-h-[300px] flex-col items-center justify-center rounded-2xl px-7 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.07] bg-white/[0.025] text-[#868295]"><KeyRound size={21} /></span>
            <h2 className="mt-4 font-display text-[15px] font-semibold text-[#d8d5e2]">Comparison results appear here</h2>
            <p className="mt-2 max-w-sm text-[12px] leading-5 text-[#858294]">The service compares public-key material. The private key itself is never returned or displayed.</p>
          </section>
        )}
      </div>
      <div className="mt-5 flex items-start gap-2.5 rounded-xl border border-amber-200/[0.1] bg-amber-200/[0.025] p-3.5 text-[11px] leading-5 text-[#a7a2ae]"><LockKeyhole size={14} className="mt-0.5 shrink-0 text-amber-200/80" /><p>Encrypted private keys require their passphrase. Passphrases and key file selections are cleared when the request finishes, whether it succeeds or fails.</p></div>
    </div>
  );
}
