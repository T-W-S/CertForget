import { useQuery } from '@tanstack/react-query';
import { ArrowRight, ArrowUpRight, ChevronRight, CircleHelp, FileBadge2, Fingerprint, KeyRound, Layers3, LockKeyhole, Server, Shield, Sparkles } from 'lucide-react';
import { Link } from 'wouter';
import { api } from '@/lib/api';

const tools = [
  { href: '/inspect', number: '01', title: 'Inspect a certificate', copy: 'Read identity, validity, SANs and cryptographic details.', icon: Fingerprint, label: 'CERTIFICATE ANALYSIS' },
  { href: '/match', number: '02', title: 'Match a key pair', copy: 'Verify that a private key belongs to a certificate.', icon: KeyRound, label: 'KEY VERIFICATION' },
  { href: '/convert', number: '03', title: 'Convert & package', copy: 'Convert PEM and DER, or work with PKCS#12 archives.', icon: Layers3, label: 'FORMAT OPERATIONS' },
];

export default function Home() {
  const health = useQuery({ queryKey: ['certforge-health'], queryFn: api.health, refetchInterval: 30000, retry: 1 });
  return (
    <div className="app-main page-enter">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs text-[#8a879a]"><span className="text-[#5e5c6d]">Workspace</span><ChevronRight size={13} /><span className="text-[#cbc8d6]">Overview</span></div>
        <div className="flex items-center gap-2 rounded-full border border-white/[0.07] bg-white/[0.025] px-3 py-1.5 text-[11px] text-[#9895a8]"><LockKeyhole size={12} className="text-emerald-300" />Private key material stays on your server</div>
      </div>

      <section className="glass-panel relative overflow-hidden rounded-[24px] px-6 py-8 sm:px-9 sm:py-10 lg:px-12">
        <div className="pointer-events-none absolute -right-16 -top-24 h-80 w-80 rounded-full border border-violet-300/[0.07]" />
        <div className="pointer-events-none absolute -right-3 -top-12 h-56 w-56 rounded-full border border-violet-300/[0.08]" />
        <div className="pointer-events-none absolute right-14 top-10 h-24 w-24 rounded-full bg-violet-500/[0.08] blur-3xl" />
        <div className="relative max-w-[730px]">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-violet-300/[0.16] bg-violet-300/[0.07] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.15em] text-violet-200"><Sparkles size={12} /> Secure certificate operations</div>
          <h1 className="font-display text-[clamp(34px,5vw,58px)] font-semibold leading-[1.08] tracking-[-0.045em] text-[#f1eff8]">Clarity for your<br className="hidden sm:block" /> certificate infrastructure.</h1>
          <p className="mt-5 max-w-[540px] text-[15px] leading-7 text-[#aaa7b8]">Inspect, verify and transform certificates with OpenSSL-backed tools running on your own server. No key material leaves your environment.</p>
          <div className="mt-7 flex flex-wrap items-center gap-3">
            <Link href="/inspect" className="primary-button" data-testid="link-start-inspection">Inspect a certificate <ArrowRight size={16} /></Link>
            <span className="flex items-center gap-2 text-[11px] text-[#868396]"><Shield size={14} className="text-emerald-300" /> No uploads retained</span>
          </div>
        </div>
      </section>

      <section className="mt-7 grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
        <div className="glass-panel rounded-2xl p-5 sm:p-6">
          <div className="mb-5 flex items-center justify-between gap-3">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#797689]">Service health</p>
              <h2 className="mt-1.5 font-display text-lg font-semibold text-[#eae8f2]">Runtime status</h2>
            </div>
            <div className={`flex items-center gap-2 rounded-full border px-2.5 py-1.5 text-[10px] font-medium ${health.isLoading ? 'border-amber-300/15 bg-amber-300/[0.05] text-amber-100' : health.data?.status === 'healthy' ? 'border-emerald-300/15 bg-emerald-300/[0.05] text-emerald-100' : 'border-rose-300/15 bg-rose-300/[0.05] text-rose-100'}`} data-testid="status-runtime">
              <span className={`h-1.5 w-1.5 rounded-full ${health.isLoading ? 'animate-pulse bg-amber-300' : health.data?.status === 'healthy' ? 'bg-emerald-300' : 'bg-rose-300'}`} />
              {health.isLoading ? 'Connecting' : health.data ? health.data.status : 'Unavailable'}
            </div>
          </div>
          {health.isLoading ? (
            <div className="space-y-3" aria-label="Loading service health"><div className="h-12 animate-pulse rounded-xl bg-white/[0.04]" /><div className="h-12 animate-pulse rounded-xl bg-white/[0.04]" /></div>
          ) : health.isError ? (
            <div className="rounded-xl border border-rose-300/10 bg-rose-300/[0.035] p-4" data-testid="status-health-error">
              <p className="text-sm font-medium text-[#dedbe7]">Certificate service is unreachable.</p>
              <p className="mt-1 text-xs leading-5 text-[#888597]">Check that the local API is running, then try again.</p>
              <button type="button" onClick={() => health.refetch()} className="mt-3 text-xs font-semibold text-violet-200 hover:text-white" data-testid="button-retry-health">Retry connection</button>
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.025] p-3.5">
                <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-300/[0.08] text-emerald-200"><Server size={16} /></span>
                <div><p className="text-[10px] text-[#8b889a]">API</p><p className="mt-0.5 text-[13px] font-semibold capitalize text-[#dfdce8]" data-testid="text-api-status">{health.data?.status || 'unavailable'}</p></div>
              </div>
              <div className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.025] p-3.5">
                <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-300/[0.09] text-violet-200"><FileBadge2 size={16} /></span>
                <div><p className="text-[10px] text-[#8b889a]">OpenSSL</p><p className="mt-0.5 font-mono-ui text-[11px] text-[#dfdce8]" data-testid="text-openssl-version">{health.data?.openssl_version || 'unavailable'}</p></div>
              </div>
            </div>
          )}
          <p className="mt-4 flex items-center gap-2 border-t border-white/[0.06] pt-4 text-[11px] text-[#858294]"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300" /> Health status refreshes automatically</p>
        </div>
        <div className="glass-panel flex flex-col justify-between rounded-2xl p-5 sm:p-6">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#797689]">Trust boundary</p>
            <h2 className="mt-1.5 font-display text-lg font-semibold text-[#eae8f2]">Your server. Your keys.</h2>
            <p className="mt-2 max-w-sm text-[12px] leading-5 text-[#9693a5]">Operations are sent directly to your self-hosted CertForge API. Private keys and passphrases are cleared from the form after processing.</p>
          </div>
          <div className="mt-5 grid grid-cols-3 divide-x divide-white/[0.08] rounded-xl border border-white/[0.06] bg-white/[0.025] py-3">
            <div className="px-3 text-center"><p className="font-display text-[15px] font-semibold text-[#ebe8f4]">Local</p><p className="mt-1 text-[9px] uppercase tracking-wider text-[#777486]">Processing</p></div>
            <div className="px-3 text-center"><p className="font-display text-[15px] font-semibold text-[#ebe8f4]">Memory</p><p className="mt-1 text-[9px] uppercase tracking-wider text-[#777486]">Only</p></div>
            <div className="px-3 text-center"><p className="font-display text-[15px] font-semibold text-[#ebe8f4]">Private</p><p className="mt-1 text-[9px] uppercase tracking-wider text-[#777486]">By design</p></div>
          </div>
        </div>
      </section>

      <section className="mt-10">
        <div className="mb-4 flex items-end justify-between gap-4">
          <div><p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-violet-300/80">Workbench</p><h2 className="mt-1.5 font-display text-2xl font-semibold tracking-tight text-[#eeecf5]">Choose an operation</h2></div>
          <span className="hidden items-center gap-1 text-[11px] text-[#777486] sm:flex"><CircleHelp size={13} /> Files processed in memory only</span>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {tools.map((tool) => {
            const Icon = tool.icon;
            return (
              <Link key={tool.href} href={tool.href} className="glass-panel group rounded-2xl p-5 transition duration-200 hover:-translate-y-0.5 hover:border-violet-300/25" data-testid={`card-tool-${tool.number}`}>
                <div className="flex items-start justify-between">
                  <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-violet-300/10 bg-violet-300/[0.07] text-violet-200 transition group-hover:bg-violet-300/[0.13]"><Icon size={18} /></span>
                  <span className="font-mono-ui text-[10px] text-[#666476]">{tool.number}</span>
                </div>
                <p className="mt-5 text-[9px] font-semibold tracking-[0.14em] text-violet-200/75">{tool.label}</p>
                <h3 className="mt-1.5 font-display text-[17px] font-semibold text-[#eae8f2]">{tool.title}</h3>
                <p className="mt-1.5 min-h-[40px] text-[12px] leading-5 text-[#9290a1]">{tool.copy}</p>
                <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-3 text-[11px] font-medium text-[#bcb8ca]">
                  Open tool <ArrowUpRight size={14} className="text-[#888498] transition group-hover:text-violet-200" />
                </div>
              </Link>
            );
          })}
        </div>
      </section>
      <footer id="security-note" className="mt-10 flex flex-col gap-2 border-t border-white/[0.07] pt-5 text-[10px] leading-5 text-[#777486] sm:flex-row sm:items-center sm:justify-between">
        <p><Shield size={12} className="mr-1.5 inline text-emerald-300" />CertForge is a self-hosted workbench. Uploads are sent only to your configured API service.</p>
        <p className="font-mono-ui tracking-wider">NO CLIENT-SIDE KEY STORAGE</p>
      </footer>
    </div>
  );
}
