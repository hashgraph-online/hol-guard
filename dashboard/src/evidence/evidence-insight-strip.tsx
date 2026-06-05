import type { EvidenceMetrics } from "./evidence-metrics";
import { ProofStrip } from "../approval-center-primitives";

interface EvidenceInsightStripProps {
  metrics: EvidenceMetrics;
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
      className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm"
      aria-label="Evidence summary"
    >
      <ProofStrip
        items={[
          { label: "Total", value: String(metrics.total), tone: "slate" },
          { label: "Stopped", value: String(metrics.blocked), tone: "blue" },
          { label: "Apps seen", value: String(appCount), tone: "green" },
          { label: "Last action", value: lastAction, tone: "slate" },
        ]}
      />
    </div>
  );
}
