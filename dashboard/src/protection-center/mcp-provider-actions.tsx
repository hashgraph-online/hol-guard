import { useEffect, useRef, useState } from "react";

import { fetchMcpProviderActions, type McpProviderAction } from "../local-cli-api";
import { McpClassificationEvidence } from "./mcp-classification-evidence";

function actionTitle(action: McpProviderAction): string {
  const prefix = `${action.toolkit.toUpperCase()}_`;
  const name = action.tool_slug.startsWith(prefix) ? action.tool_slug.slice(prefix.length) : action.tool_slug;
  const words = name.replaceAll("_", " ").toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export type ProviderActionDraft = { tool_slug: string; state: "review" | "block"; revision: number };

export function McpProviderActions(props: {
  cliId: string; knownCount: number; disabled: boolean; authorityRevision: number;
  drafts: Record<string, ProviderActionDraft>;
  onChange: (action: McpProviderAction, state: "review" | "block") => void;
}) {
  const [input, setInput] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<{ actions: McpProviderAction[]; nextOffset: number | null } | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const catalogToken = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (input === search) return;
    const timer = window.setTimeout(() => { setSearch(input); setOffset(0); }, 250);
    return () => window.clearTimeout(timer);
  }, [input, search]);
  useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError(null);
    void fetchMcpProviderActions(props.cliId, {
      search, offset, signal: controller.signal, catalogToken: offset > 0 ? catalogToken.current : undefined,
    }).then((next) => {
      if (!controller.signal.aborted) {
        catalogToken.current = next.catalogToken;
        setPage(next);
      }
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load discovered actions.");
    }).finally(() => {
      if (!controller.signal.aborted) setBusy(false);
    });
    return () => controller.abort();
  }, [props.cliId, props.authorityRevision, search, offset, retry]);
  return (
    <section className="mt-6 border-b border-slate-200 pb-5" aria-labelledby="mcp-provider-heading" aria-busy={busy}>
      <h2 id="mcp-provider-heading" className="text-base font-semibold text-brand-dark">Discovered app actions</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75">
        {props.knownCount} actions cached from discovery results. This is a partial inventory.
        Allow requires a verified account and enforcement of the action inside its execution wrapper.
        Deny applies to this action across all accounts in this host connection. Opaque workbench execution is blocked while any action is denied.
      </p>
      <label className="mt-4 block text-sm font-semibold text-brand-dark" htmlFor="mcp-provider-search">Search actions or apps</label>
      <input id="mcp-provider-search" type="search" maxLength={128} value={input} onChange={(event) => setInput(event.target.value)}
        className="mt-2 min-h-11 w-full max-w-xl rounded-xl border border-slate-300 bg-white px-3 text-sm text-brand-dark" />
      {busy ? <p role="status" className="mt-3 text-sm text-brand-dark/75">Loading discovered actions…</p> : null}
      {error ? (
        <div role="alert" className="mt-3 text-sm text-red-700">
          <p>{error}</p>
          <button type="button" className="mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark"
            onClick={() => { setOffset(0); setRetry((value) => value + 1); }}>Reload action inventory</button>
        </div>
      ) : null}
      {!busy && !error && page?.actions.length === 0 ? (
        <p className="mt-4 text-sm leading-6 text-brand-dark/75">No discovered actions match this search. Discovery may find more during use.</p>
      ) : null}
      {!error && page && !busy ? (
        <>
          <ul className="mt-4 divide-y divide-slate-200">
            {page.actions.map((action) => (
              <li key={action.tool_slug} className="py-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-semibold text-brand-dark">{actionTitle(action)}</h3>
                    <p className="mt-1 text-xs text-brand-dark/75">{action.toolkit} · Account not verified</p>
                  </div>
                  <label className="flex items-center gap-2 text-xs font-semibold text-brand-dark">
                    <span className="sr-only">Permission for {actionTitle(action)}</span>
                    <select disabled={props.disabled} aria-label={`Permission for ${actionTitle(action)}`}
                      value={props.drafts[action.tool_slug]?.state ?? action.permission_state}
                      onChange={(event) => props.onChange(action, event.target.value as "review" | "block")}
                      className="min-h-11 rounded-xl border border-slate-300 bg-white px-3 text-sm">
                      <option value="review">Ask</option>
                      <option value="block">Deny</option>
                    </select>
                  </label>
                </div>
                <p className="mt-2 max-w-2xl break-words text-sm leading-6 text-brand-dark/75">{action.description.slice(0, 260)}</p>
                <McpClassificationEvidence value={action.classification} />
                <details className="mt-1 text-xs text-brand-dark/75">
                  <summary className="min-h-11 cursor-pointer py-3 font-semibold">Action details</summary>
                  <p className="break-all font-mono">{action.tool_slug}</p>
                  <p className="mt-2">Schema {action.full_schema ? "available" : "incomplete"} · Revision {action.revision}</p>
                  <p className="mt-2">Observed provider metadata. Execution permission has not been granted.</p>
                </details>
              </li>
            ))}
          </ul>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}
              className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50">Previous page</button>
            <span className="text-sm text-brand-dark/75">Page {offset / 50 + 1}</span>
            <button type="button" disabled={page.nextOffset === null} onClick={() => { if (page.nextOffset !== null) setOffset(page.nextOffset); }}
              className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50">Next page</button>
          </div>
        </>
      ) : null}
    </section>
  );
}
