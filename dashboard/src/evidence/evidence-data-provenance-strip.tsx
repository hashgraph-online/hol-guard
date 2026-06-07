import { HiMiniChevronRight } from "react-icons/hi2";
import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { formatDurationSince, formatEvidenceCount } from "./evidence-format";

interface EvidenceDataProvenanceStripProps {
  analytics: GuardReceiptAnalytics;
  sampleCount: number;
  runtime: GuardRuntimeSnapshot | null;
  onViewActions: () => void;
}

export function EvidenceDataProvenanceStrip({
  analytics,
  sampleCount,
  runtime,
  onViewActions,
}: EvidenceDataProvenanceStripProps) {
  const beyondSample = analytics.total > sampleCount;
  const cloudNote =
    runtime?.cloud_state === "local_only"
      ? "Guard Cloud not connected."
      : runtime?.cloud_state === "paired_active" && runtime?.cloud_sync_health?.label !== "Synced"
        ? runtime?.cloud_sync_health?.label
        : null;

  return (
    <div className="flex flex-col gap-2 border-t border-slate-100 px-5 py-3 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
      <p>
        {formatEvidenceCount(analytics.total)} actions from full local store
        {beyondSample ? ` · list shows latest ${formatEvidenceCount(sampleCount)}` : ""}
        {analytics.last_activity_at ? ` · last activity ${formatDurationSince(analytics.last_activity_at)}` : ""}
        {cloudNote ? ` · ${cloudNote}` : ""}
      </p>
      <button
        type="button"
        onClick={onViewActions}
        className="inline-flex shrink-0 items-center gap-1 font-medium text-brand-blue transition-colors hover:text-brand-dark"
      >
        Browse actions
        <HiMiniChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
    </div>
  );
}
