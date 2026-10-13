import { type ReactNode } from 'react';
import { Activity, ArrowUpRight, FileKey2, Fingerprint, Gauge, KeyRound, Layers3, ShieldCheck } from 'lucide-react';
import { Link, useLocation } from 'wouter';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

const navigation = [
  { href: '/', label: 'Overview', icon: Gauge },
  { href: '/inspect', label: 'Inspect certificate', icon: Fingerprint },
  { href: '/match', label: 'Match key pair', icon: KeyRound },
  { href: '/convert', label: 'Format tools', icon: Layers3 },
];

export function AppShell({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const health = useQuery({
    queryKey: ['certforge-health'],
    queryFn: api.health,
    refetchInterval: 30000,
    retry: 1,
  });
  const ready = health.data?.status === 'healthy';

  return (
    <div className="app-shell">
      <header className="sticky top-0 z-20 border-b border-white/[0.07] bg-[#11121c]/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-5 px-5 py-3.5 lg:px-9">
          <Link href="/" className="flex items-center gap-3 rounded-lg" data-testid="link-brand-home">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-violet-300/20 bg-violet-400/10 text-violet-200">
              <ShieldCheck size={19} strokeWidth={1.8} />
            </span>
            <span>
              <span className="block font-display text-[16px] font-bold tracking-tight text-[#f1eff8]">CertForge<span className="text-violet-300">_t</span></span>
              <span className="hidden text-[10px] tracking-[0.15em] text-[#777588] sm:block">CERTIFICATE WORKBENCH</span>
            </span>
          </Link>
          <div className="hidden items-center gap-1.5 rounded-full border border-white/[0.07] bg-white/[0.025] px-3 py-1.5 text-xs text-[#a7a4b6] sm:flex" data-testid="status-api-readiness">
            {health.isLoading ? <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-300" /> : <span className={`h-1.5 w-1.5 rounded-full ${ready ? 'bg-emerald-400' : 'bg-rose-400'}`} />}
            {health.isLoading ? 'Checking service' : ready ? 'Service operational' : health.isError ? 'Service unavailable' : health.data?.status || 'Service unavailable'}
          </div>
          <a href="#security-note" className="flex items-center gap-1.5 text-xs text-[#a9a5b8] transition hover:text-violet-200" data-testid="link-security-note">
            <Activity size={14} />
            <span className="hidden sm:inline">Local-first security</span>
            <ArrowUpRight size={13} />
          </a>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1600px] lg:grid-cols-[232px_minmax(0,1fr)]">
        <aside className="border-b border-white/[0.07] bg-[#151520]/55 px-4 py-3 lg:sticky lg:top-[65px] lg:h-[calc(100dvh-65px)] lg:border-b-0 lg:border-r lg:px-4 lg:py-8">
          <div className="mb-3 hidden px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-[#706e80] lg:block">Workspace</div>
          <nav className="flex gap-1 overflow-x-auto lg:flex-col">
            {navigation.map((item) => {
              const active = location === item.href;
              const Icon = item.icon;
              return (
                <Link key={item.href} href={item.href} className={`flex shrink-0 items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] transition ${active ? 'border border-violet-300/10 bg-violet-400/[0.12] font-semibold text-violet-100' : 'border border-transparent text-[#a3a0b2] hover:bg-white/[0.04] hover:text-[#efedf7]'}`} data-testid={`link-nav-${item.href === '/' ? 'overview' : item.href.slice(1)}`}>
                  <Icon size={16} strokeWidth={1.8} />
                  {item.label}
                  {active && <span className="ml-auto hidden h-1.5 w-1.5 rounded-full bg-violet-300 lg:block" />}
                </Link>
              );
            })}
          </nav>
          <div className="mt-9 hidden rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4 lg:block">
            <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold text-[#d6d2e3]">
              <span className={`h-1.5 w-1.5 rounded-full ${ready ? 'bg-emerald-400' : 'bg-amber-300'}`} />
              Runtime status
            </div>
            <p className="text-[11px] leading-5 text-[#888597]">{health.isLoading ? 'Connecting to the local certificate service…' : health.data ? `OpenSSL ${health.data.openssl_version}` : health.isError ? 'Unable to reach the API service.' : 'Waiting for service status.'}</p>
            {health.isError && <button type="button" onClick={() => health.refetch()} className="mt-3 text-[11px] font-semibold text-violet-300 hover:text-violet-200" data-testid="button-retry-health">Retry connection</button>}
          </div>
          <div className="mt-auto hidden pt-10 lg:block">
            <div className="rounded-xl border border-emerald-300/[0.12] bg-emerald-300/[0.035] p-3.5">
              <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold text-emerald-200"><FileKey2 size={14} />Private by design</div>
              <p className="text-[10px] leading-[1.65] text-[#888b96]">Files are processed by your server. This interface never stores certificate material.</p>
            </div>
            <p className="mt-4 px-2 text-[10px] text-[#605e6e]">CERTFORGE WORKBENCH <span className="float-right">SELF-HOSTED</span></p>
          </div>
        </aside>
        <main className="min-w-0">{children}</main>
      </div>
    </div>
  );
}
