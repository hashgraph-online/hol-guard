import { Tag } from "../../approval-center-primitives";
import type { AboutRuntimeSummary } from "../about-types";

export function AboutRuntimeProofStrip({
  summary,
}: {
  summary: AboutRuntimeSummary | null;
}) {
  if (!summary) return null;

  const items = [
    {
      label: "Local protection",
      value: summary.pendingCount > 0 ? `${summary.pendingCount} pending` : "Active",
      tone: summary.pendingCount > 0 ? ("attention" as const) : ("green" as const),
    },
    {
      label: "Guard version",
      value: summary.guardVersion ?? "Unknown",
      tone: "slate" as const,
    },
    {
      label: "Sync",
      value: summary.cloudStateLabel,
      tone: summary.syncConfigured ? ("blue" as const) : ("slate" as const),
    },
    {
      label: "Receipts",
      value: String(summary.receiptCount),
      tone: "green" as const,
    },
  ];

  return (
    <div className="flex flex-wrap gap-2 pt-3">
      {items.map((item) => (
        <div key={item.label} className="flex items-center gap-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            {item.label}
          </span>
          <Tag tone={item.tone}>{item.value}</Tag>
        </div>
      ))}
    </div>
  );
}
