import type { EvidenceView } from "./evidence-types";

export const VIEW_TABS: { key: EvidenceView; label: string }[] = [
  { key: "actions", label: "All actions" },
  { key: "insights", label: "Insights" },
  { key: "apps", label: "Apps" },
  { key: "story", label: "Story" },
  { key: "categories", label: "Categories" },
  { key: "export", label: "Export" },
];

export function EvidenceLoadingState() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading evidence">
      <div className="guard-skeleton h-8 w-64" />
      <div className="guard-skeleton h-32 w-full" />
    </div>
  );
}

export function EvidenceErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4">
      <p className="text-sm text-brand-dark">{message}</p>
    </div>
  );
}

export interface EvidenceHeaderProps {
  totalCount: number;
  lastActivityAt: string | null;
  onExport: () => void;
  onClear?: () => void;
}

export function EvidenceHeader({
  totalCount,
  lastActivityAt,
  onExport,
  onClear,
}: EvidenceHeaderProps) {
  const lastActivityLabel = lastActivityAt
    ? new Date(lastActivityAt).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
      })
    : null;

  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="space-y-0.5 min-w-0">
        <h1 className="text-lg font-semibold text-brand-dark">Evidence</h1>
        <p className="text-xs text-slate-500">
          Every action Guard reviewed on this machine.
        </p>
        {lastActivityLabel && (
          <p className="text-[11px] text-slate-400">
            Last activity: {lastActivityLabel}
          </p>
        )}
      </div>
      <div className="flex items-center gap-1.5 shrink-0">
        <button
          type="button"
          onClick={onExport}
          aria-label="Export evidence"
          className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-brand-dark hover:bg-slate-50 transition-colors"
        >
          Export
        </button>
        {onClear && totalCount > 0 && (
          <button
            type="button"
            onClick={onClear}
            aria-label="Clear all evidence"
            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-500 hover:bg-slate-50 hover:text-brand-attention transition-colors"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );
}
