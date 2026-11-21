import { HiMiniExclamationTriangle } from "react-icons/hi2";

export function LeftoverGuardCleanup({ warnings }: { warnings: string[] }) {
  return (
    <div className="mt-4 rounded-xl border border-brand-attention/15 bg-brand-attention/[0.04] p-4">
      <div className="flex items-start gap-3">
        <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-brand-dark">Leftover Guard files detected</p>
          <ul className="mt-1 space-y-1 text-sm text-muted-foreground">
            {warnings.slice(0, 3).map((warning) => <li key={warning}>{warning}</li>)}
          </ul>
        </div>
      </div>
    </div>
  );
}
