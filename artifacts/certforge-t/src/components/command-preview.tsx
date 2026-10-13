import { LockKeyhole } from 'lucide-react';

export function CommandPreview({ lines }: { lines: string[] }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#14151f] px-3.5 py-3">
      <div className="mb-2 flex items-center gap-1.5 text-[9px] font-semibold uppercase tracking-[0.13em] text-[#777486]">
        <LockKeyhole size={11} />
        OpenSSL command preview
      </div>
      <code className="block overflow-x-auto font-mono-ui text-[10px] leading-[1.8] text-[#b2a8ca]">
        {lines.map((line, index) => (
          <span key={`${line}-${index}`} className="block whitespace-nowrap">
            {line}
          </span>
        ))}
      </code>
      <p className="mt-1.5 text-[9px] text-[#777486]">
        Illustrative only. Passphrases use protected input channels and are not
        shown here.
      </p>
    </div>
  );
}
