import { type ReactNode } from 'react';
import { AlertCircle, Check, LoaderCircle, ShieldCheck } from 'lucide-react';

export function ErrorNotice({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-rose-400/20 bg-rose-400/[0.06] p-4" role="alert" data-testid="status-error">
      <AlertCircle size={18} className="mt-0.5 shrink-0 text-rose-300" />
      <div className="min-w-0 flex-1">
        <p className="text-[13px] font-semibold text-rose-100">The operation could not be completed</p>
        <p className="mt-1 break-words text-[12px] leading-5 text-rose-100/70">{message}</p>
      </div>
      {onRetry && <button type="button" onClick={onRetry} className="text-xs font-semibold text-rose-200 hover:text-white" data-testid="button-retry">Retry</button>}
    </div>
  );
}

export function SuccessNotice({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-emerald-300/15 bg-emerald-300/[0.055] p-4" role="status" data-testid="status-success">
      <span className="mt-0.5 flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full bg-emerald-300/15 text-emerald-200"><Check size={12} /></span>
      <div className="min-w-0 flex-1 text-[13px] leading-5 text-emerald-100/90">{children}</div>
    </div>
  );
}

export function LoadingButton({ loading, disabled = false, children }: { loading: boolean; disabled?: boolean; children: ReactNode }) {
  return (
    <button type="submit" className="primary-button" disabled={loading || disabled} data-testid="button-submit">
      {loading ? <LoaderCircle size={16} className="animate-spin" /> : <ShieldCheck size={16} />}
      {loading ? 'Processing securely…' : children}
    </button>
  );
}
