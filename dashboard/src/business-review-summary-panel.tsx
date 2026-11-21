import { useEffect, useState } from "react";
import { fetchBusinessReviewSummary } from "./guard-api";
import { businessOperationLabels, businessServiceLabels, type BusinessReviewSummary } from "./business-review-summary";

export function BusinessReviewSummaryDetails({ summary }: { summary: BusinessReviewSummary }) {
  const count = new Intl.NumberFormat();
  const audience = { private: "Private", named: "Named recipients", public: "Public", unknown: "Unknown" }[summary.audience_kind];
  return (
    <section className="mt-5 border-t border-slate-200 pt-4" aria-label="Saved business action details">
      <h3 className="text-sm font-semibold text-brand-dark">{businessOperationLabels[summary.operation]} · {businessServiceLabels[summary.service]}</h3>
      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
        {[
          ["Audience", audience], ["Recipients", count.format(summary.recipient_count)],
          ["Records", count.format(summary.record_count)], ["Attachments", count.format(summary.attachment_count)],
          ["Content size", `${count.format(summary.byte_count)} bytes`],
          ["Sensitivity", summary.sensitivity_labels.length ? summary.sensitivity_labels.join(", ") : "Not labeled"],
        ].map(([label, value]) => <div key={label} className="min-w-0"><dt className="text-muted-foreground">{label}</dt><dd className="mt-1 break-words text-brand-dark">{value}</dd></div>)}
      </dl>
      <p className="mt-4 text-sm leading-6 text-brand-dark">These details describe the saved request. This summary does not verify the work account or confirm execution.</p>
      {summary.audience_expansion_state !== "known" || summary.inspection_state !== "known" || summary.snapshot_fact_completeness !== "known" ? (
        <p className="mt-2 text-sm leading-6 text-brand-dark">Some recipient or content details are unknown or unsupported. Counts alone do not establish that the action is safe.</p>
      ) : null}
      <p className="mt-2 text-xs leading-5 text-muted-foreground">Message content, exact recipients and attachments are not shown in this summary.</p>
    </section>
  );
}

type SummaryState = { requestId: string; status: "loading" | "error" | "ready"; summary: BusinessReviewSummary | null };

export function BusinessReviewSummaryPanel({ requestId }: { requestId: string }) {
  const [state, setState] = useState<SummaryState | null>(null);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setState({ requestId, status: "loading", summary: null });
    fetchBusinessReviewSummary(requestId, controller.signal).then((summary) => {
      if (!controller.signal.aborted) setState({ requestId, status: "ready", summary });
    }).catch(() => {
      if (!controller.signal.aborted) setState({ requestId, status: "error", summary: null });
    });
    return () => controller.abort();
  }, [requestId, revision]);
  if (!state || state.requestId !== requestId || state.status === "loading") return <p className="mt-4 text-sm text-muted-foreground" role="status">Checking saved business details…</p>;
  if (state.status === "error") return (
    <div className="mt-4 text-sm text-brand-dark" role="status">
      <p>Saved business details could not be loaded.</p>
      <button type="button" className="mt-2 min-h-11 rounded-lg px-3 text-brand-blue underline underline-offset-4 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue" onClick={() => setRevision(value => value + 1)}>Refresh details</button>
    </div>
  );
  return state.summary ? <BusinessReviewSummaryDetails summary={state.summary} /> : null;
}
