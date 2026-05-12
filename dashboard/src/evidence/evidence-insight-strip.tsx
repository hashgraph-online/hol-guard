import type { EvidenceMetrics } from "./evidence-metrics";

interface EvidenceInsightStripProps {
  metrics: EvidenceMetrics;
}

interface StatTileProps {
  label: string;
  value: string;
  tone: "blue" | "green" | "attention" | "neutral";
}

function StatTile({ label, value, tone }: StatTileProps) {
  const colorMap: Record<string, string> = {
    blue: "text-brand-blue",
    green: "text-brand-green",
    attention: "text-brand-attention",
    neutral: "text-brand-dark",
  };
  return (
    <div className="flex flex-col items-center gap-0.5 px-4 py-2">
      <span className={`text-xl font-bold tabular-nums ${colorMap[tone]}`}>
        {value}
      </span>
      <span className="text-[11px] font-medium text-slate-500">{label}</span>
    </div>
  );
}

export function EvidenceInsightStrip({ metrics }: EvidenceInsightStripProps) {
  const lastAction = metrics.lastActivityAt
    ? new Date(metrics.lastActivityAt).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
      })
    : "—";

  const appCount = metrics.byHarness.size;

  return (
    <div
      className="flex flex-wrap divide-x divide-slate-100 overflow-hidden rounded-xl border border-slate-200 bg-white/80 shadow-sm"
      aria-label="Evidence summary"
    >
      <StatTile label="Total" value={String(metrics.total)} tone="neutral" />
      <StatTile label="Stopped" value={String(metrics.blocked)} tone="attention" />
      <StatTile label="Apps seen" value={String(appCount)} tone="blue" />
      <StatTile label="Last action" value={lastAction} tone="neutral" />
    </div>
  );
}
