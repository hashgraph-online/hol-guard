import { useEffect, useState } from "react";
import { fetchProviderWorkflows, type ProviderWorkflow } from "../provider-workflows-api";

const requirementLabels = { "saved-deny": "Saved Deny", unresolved: "Not observed", ask: "Needs review" };

export function ProviderWorkflows({ cliId }: { cliId: string }) {
  const [open, setOpen] = useState(false);
  const [offset, setOffset] = useState(0);
  const [retry, setRetry] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState<{ proposals: ProviderWorkflow[]; nextOffset: number | null } | null>(null);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setBusy(true); setError(null); setPage(null);
    void fetchProviderWorkflows(cliId, offset, controller.signal).then((result) => {
      if (!controller.signal.aborted) setPage(result);
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load suggestions.");
    }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [cliId, open, offset, retry]);
  return <details className="mt-5 border-b border-slate-200 pb-5" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary className="min-h-11 cursor-pointer py-3 text-base font-semibold text-brand-dark">Suggested action workflows</summary>
    {open ? <section aria-label="Composio workflow suggestions" aria-busy={busy}>
      <p className="max-w-2xl text-sm leading-6 text-brand-dark/75">
        Suggestions from observed Composio search results. They are not MCP Skills, account verification, or permission grants.
        Search may omit a workflow, and each action still needs its own review.
      </p>
      {busy ? <p role="status" className="mt-3 text-sm text-brand-dark/75">Loading suggestions…</p> : null}
      {error ? <div role="alert" className="mt-3 text-sm text-red-700"><p>{error}</p>
        <button type="button" onClick={() => { setOffset(0); setRetry((value) => value + 1); }}
          className="mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark">Reload suggestions</button>
      </div> : null}
      {!busy && !error && page?.proposals.length === 0 ? <p className="mt-3 text-sm text-brand-dark/75">
        No workflow suggestion was observed. Search Composio for a specific task to discover one.
      </p> : null}
      {!busy && !error && page ? <>
        <ol start={offset + 1} className="mt-4 space-y-4">{page.proposals.map((proposal) => <li key={proposal.proposalId}
          className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-brand-dark">
          <p className="font-semibold">Suggested workflow {offset + page.proposals.indexOf(proposal) + 1}</p>
          <p className="mt-1 text-brand-dark/75">{proposal.guidancePresent
            ? "Composio also returned plan guidance; Guard kept only suggested action IDs."
            : "Action suggestions only; no plan guidance was returned."}</p>
          <ul className="mt-2 space-y-1">{proposal.requirements.map((part) => <li key={part.slug} className="break-words">
            {part.slug.replaceAll("_", " ").toLowerCase()} · {part.role === "primary" ? "Primary" : "Supporting"}
            {" · "}{requirementLabels[part.state]}
            {!part.schemaObserved && part.state !== "unresolved" ? " · Schema incomplete" : ""}
          </li>)}</ul>
        </li>)}</ol>
        {offset > 0 || page.nextOffset !== null ? <nav aria-label="Suggestion pages" className="mt-3 flex items-center gap-3">
          <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 10))}
            className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Previous</button>
          <span className="text-sm text-brand-dark/75">Page {offset / 10 + 1}</span>
          <button type="button" disabled={page.nextOffset === null} onClick={() => { if (page.nextOffset !== null) setOffset(page.nextOffset); }}
            className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Next</button>
        </nav> : null}
      </> : null}
    </section> : null}
  </details>;
}
