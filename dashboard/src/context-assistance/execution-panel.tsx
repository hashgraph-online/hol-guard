import type { ContextAssistanceStatus } from "./types";

const phases = {
  prepared: "Context checked before launch",
  not_dispatched: "No new dispatch acknowledged",
  dispatch_acknowledged: "Native dispatch acknowledged",
  completed: "Native execution record completed",
  outcome_unknown: "Native outcome needs reconciliation",
};

export function ContextExecutionPanel({ status }: { status: ContextAssistanceStatus | null }) {
  if (!status?.preferences.features.execution_context) return null;
  const observations = status.execution_observations;
  return <section aria-label="Native execution context observations" className="space-y-3 rounded-lg border border-slate-200 p-3 text-sm">
    <h4 className="font-semibold text-brand-dark">Native execution context</h4>
    <p className="text-slate-600">{status.execution_ready
      ? "Preparation is ready for Pi and Oh My Pi workspace grants using Guard's native captured-Bash executor."
      : "Preparation is unavailable. Commands keep their native authorization and can proceed without this association."}</p>
    <p className="text-slate-600">Execution checks use fixed native capture and policy facts. Selected files and shared notes remain separate review context. End-to-end app delivery has not been qualified in this candidate.</p>
    {observations === null ? <p role="status">Recent observations are busy. Refresh status to check again.</p>
      : !observations?.length ? <p>No recent execution-context observations.</p>
        : <ul className="space-y-3">{observations.slice(0, 6).map((item) => <li key={item.effect_id} className="rounded-md bg-slate-50 p-3">
          <p className="font-medium text-brand-dark">{phases[item.phase]}</p>
          <p>{item.association_applied ? "Checked context was associated at native dispatch."
            : item.phase === "prepared" ? "Association awaits native dispatch."
              : "No CIGAR association is confirmed for this attempt."}</p>
          {item.phase === "outcome_unknown" ? <p className="mt-1 text-amber-800">Consult Guard's native execution record before retrying.</p> : null}
          <details className="mt-2">
            <summary className="cursor-pointer font-medium">Observation details</summary>
            <dl className="mt-2 space-y-1 break-all text-xs text-slate-600">
              <div><dt>Execution reference</dt><dd>{item.execution_reference ?? "Not associated"}</dd></div>
              <div><dt>Context snapshot</dt><dd>{item.snapshot_id}</dd></div>
              <div><dt>Native launch check</dt><dd>{item.native_barrier_checked_at_ms === null ? "No launch check recorded" : new Date(item.native_barrier_checked_at_ms).toLocaleString()}</dd></div>
              <div><dt>Scope</dt><dd>{item.scope_id}</dd></div>
              {item.reason ? <div><dt>Association detail</dt><dd>{item.reason.replaceAll("_", " ")}</dd></div> : null}
            </dl>
          </details>
        </li>)}</ul>}
    <p className="text-xs text-slate-500">Up to 32 metadata observations remain in memory for five minutes. Entries can be omitted; this is a context check record. Guard's native journal owns execution, approvals and uncertain outcomes.</p>
  </section>;
}
