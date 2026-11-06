import { useCallback } from "react";
import { HiMiniXMark } from "react-icons/hi2";
import { Tag, IconActionButton } from "./approval-center-primitives";
import { decisionTone, severityTone } from "./package-workbench-common";
import type { SupplyChainAuditFinding } from "./guard-types";

function humanizeReasonMessage(code: string, message: string): string {
  if (code === "unknown_package") {
    return "Guard Cloud has not indexed this package yet. It is not treated as a security finding.";
  }
  if (code === "no_cached_match") {
    return "No local intel match yet. Sync Guard Cloud or retry after the next bundle refresh.";
  }
  return message;
}

type FindingDetailPanelProps = {
  finding: SupplyChainAuditFinding;
  onClose: () => void;
};

export function FindingDetailPanel({ finding, onClose }: FindingDetailPanelProps) {
  const handleClose = useCallback(() => {
    onClose();
  }, [onClose]);

  return (
    <div className="max-h-[min(85vh,40rem)] overflow-y-auto rounded-2xl border border-slate-100 bg-white shadow-xl">
      <div className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-slate-100 bg-white/95 px-4 py-3 backdrop-blur-sm">
        <div className="min-w-0">
          <p className="text-base font-semibold text-brand-dark">{finding.packageName}</p>
          <p className="mt-0.5 text-xs text-slate-500">
            {finding.ecosystem}
            {finding.namespace !== null ? ` · ${finding.namespace}` : ""}
          </p>
        </div>
        <IconActionButton
          variant="ghost"
          label="Close finding detail"
          icon={<HiMiniXMark className="h-4 w-4" />}
          onClick={handleClose}
        />
      </div>
      <div className="px-4 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <Tag tone={decisionTone(finding.decision)}>{finding.decision}</Tag>
          <Tag tone={severityTone(finding.severity)}>{finding.severity}</Tag>
        </div>
        {finding.reasons.length > 0 ? (
          <ul className="mt-4 space-y-3">
            {finding.reasons.map((reason) => (
              <li
                key={`${finding.id}-${reason.code}`}
                className="rounded-xl border border-slate-100 bg-slate-50/80 px-3 py-2.5 text-xs leading-relaxed text-slate-600"
              >
                <span className="font-semibold text-slate-700">{reason.code}</span>
                <span className="text-slate-400"> · </span>
                {humanizeReasonMessage(reason.code, reason.message)}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-4 text-xs text-slate-500">No advisory detail recorded for this package yet.</p>
        )}
        <div className="mt-5">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Advisory aliases</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {finding.advisoryAliases.map((alias) => (
              <span
                key={`${finding.id}-${alias}`}
                className="rounded-full border border-slate-200 bg-white px-2.5 py-0.5 font-mono text-[11px] text-slate-600"
              >
                {alias}
              </span>
            ))}
          </div>
          {finding.advisoryAliases.length === 0 ? (
            <p className="mt-2 text-[11px] text-slate-500">No linked CVE or GHSA aliases for this finding.</p>
          ) : null}
        </div>
      </div>
    </div>
  );
}

type FindingRowProps = {
  finding: SupplyChainAuditFinding;
  selected: boolean;
  onSelect: (id: string) => void;
};

export function FindingRow({ finding, selected, onSelect }: FindingRowProps) {
  const handleSelect = useCallback(() => {
    onSelect(finding.id);
  }, [finding.id, onSelect]);

  return (
    <button
      type="button"
      onClick={handleSelect}
      aria-pressed={selected}
      className={`flex w-full items-center justify-between gap-3 border-b border-slate-100 px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-slate-50/70 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30 ${
        selected ? "bg-brand-blue/[0.04]" : ""
      }`}
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-brand-dark">{finding.packageName}</p>
        <p className="mt-0.5 truncate text-xs text-slate-500">
          {finding.ecosystem}
          {finding.namespace !== null ? ` · ${finding.namespace}` : ""}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Tag tone={decisionTone(finding.decision)}>{finding.decision}</Tag>
        <Tag tone={severityTone(finding.severity)}>{finding.severity}</Tag>
      </div>
    </button>
  );
}
