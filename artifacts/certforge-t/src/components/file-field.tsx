import { useRef } from 'react';
import { FileKey2, FileUp, X } from 'lucide-react';

interface FileFieldProps {
  label: string;
  accept?: string;
  file: File | null;
  onChange: (file: File | null) => void;
  helper?: string;
  testId: string;
}

export function FileField({ label, accept = '.pem,.crt,.cer,.der,.p12,.pfx', file, onChange, helper = 'PEM, DER, CRT or CER', testId }: FileFieldProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <label className="text-[13px] font-medium text-[#d7d4e1]">{label}</label>
        <span className="text-[10px] text-[#747285]">{helper}</span>
      </div>
      <div className="drop-zone rounded-xl border border-dashed border-[#424055] bg-[#191a27]/70" onDragOver={(event) => event.preventDefault()} onDrop={(event) => {
        event.preventDefault();
        const droppedFile = event.dataTransfer.files[0];
        if (droppedFile) {
          onChange(droppedFile);
        }
      }}>
        {file ? (
          <div className="flex min-h-[74px] items-center gap-3 px-4 py-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-violet-400/10 text-violet-200"><FileKey2 size={17} /></span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-[13px] font-medium text-[#e8e5f0]" data-testid={`text-selected-${testId}`}>{file.name}</p>
              <p className="mt-0.5 text-[11px] text-[#848195]">{(file.size / 1024).toFixed(1)} KB · selected locally</p>
            </div>
            <button type="button" onClick={() => onChange(null)} className="rounded-lg p-2 text-[#9995a9] transition hover:bg-white/[0.06] hover:text-white" aria-label={`Remove ${label}`} data-testid={`button-remove-${testId}`}><X size={16} /></button>
          </div>
        ) : (
          <button type="button" onClick={() => inputRef.current?.click()} className="flex min-h-[74px] w-full items-center gap-3 px-4 py-3 text-left" data-testid={`button-upload-${testId}`}>
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/[0.07] bg-white/[0.035] text-[#a9a5b8]"><FileUp size={17} /></span>
            <span className="min-w-0 flex-1">
              <span className="block text-[13px] font-medium text-[#d7d4e1]">Choose a file <span className="font-normal text-[#8d899b]">or drop it here</span></span>
              <span className="mt-0.5 block text-[11px] text-[#777486]">{helper} · processed in memory by your server</span>
            </span>
          </button>
        )}
        <input ref={inputRef} type="file" accept={accept} className="sr-only" onChange={(event) => {
          onChange(event.target.files?.[0] || null);
          event.target.value = '';
        }} data-testid={`input-file-${testId}`} />
      </div>
    </div>
  );
}
