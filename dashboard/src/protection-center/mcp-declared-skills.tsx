import { useEffect, useRef, useState } from "react";
import { fetchMcpSkillMetadata, type McpSkillMetadata } from "../mcp-skills-api";

export function McpDeclaredSkills(props: {
  cliId: string; identityHash: string; revision: number; knownCount: number; complete: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [input, setInput] = useState("");
  const [offset, setOffset] = useState(0);
  const [retry, setRetry] = useState(0);
  const [page, setPage] = useState<{ entries: McpSkillMetadata[]; nextOffset: number | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const revision = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (input === search) return;
    const timer = window.setTimeout(() => { setSearch(input); setOffset(0); }, 250);
    return () => window.clearTimeout(timer);
  }, [input, search]);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setBusy(true); setError(null);
    void fetchMcpSkillMetadata({ cliId: props.cliId, identityHash: props.identityHash, offset, search,
      revision: offset > 0 ? revision.current : undefined, signal: controller.signal }).then((next) => {
      if (!controller.signal.aborted) { setPage(next); revision.current = next.revision; }
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Could not load workflows.");
    }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [open, props.cliId, props.identityHash, props.revision, offset, search, retry]);
  return <details className="mt-6 border-b border-slate-200 pb-5" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary className="min-h-11 cursor-pointer py-3 text-base font-semibold text-brand-dark">Remote workflows · {props.knownCount} cached</summary>
    {open ? <section aria-label="Remote workflow metadata" aria-busy={busy}>
      <p className="max-w-2xl text-sm leading-6 text-brand-dark/75">
        This connection declares MCP Skills. {props.complete ? "Its workflow metadata was listed." : "Its workflow inventory is incomplete."}
        Instructions are not loaded. Guard has not enabled skill activation in this host; tool permissions remain separate.
      </p>
      <label className="mt-4 block max-w-xl text-sm font-semibold text-brand-dark">Find a remote workflow
        <input type="search" value={input} onChange={(event) => setInput(event.target.value)}
          className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-3 font-normal" />
      </label>
      {error ? <div role="alert" className="mt-3 text-sm text-red-700"><p>{error}</p>
        <button type="button" onClick={() => { setOffset(0); setRetry((current) => current + 1); }}
          className="mt-2 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark">Reload workflow metadata</button></div> : null}
      {!busy && !error && page?.entries.length === 0 ? <p className="mt-4 text-sm text-brand-dark/75">No workflow metadata matches this search.</p> : null}
      {!busy && !error && page ? <>
        <ul className="mt-4 divide-y divide-slate-200">{page.entries.map((entry) => <li key={entry.uri} className="py-4">
          <h3 className="text-sm font-semibold text-brand-dark">{entry.name}</h3>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-brand-dark/75">{entry.description}</p>
          <p className="mt-2 break-all text-xs text-brand-dark/75">Origin: this MCP connection · {entry.uri}</p>
          <p className="mt-2 text-xs text-brand-dark/75">{entry.dynamic ? "Dynamic content cannot carry persisted content approval."
            : `${entry.resource_count} files in the declared manifest. Files must be verified when read.`}</p>
        </li>)}</ul>
        {offset > 0 || page.nextOffset !== null ? <nav aria-label="Remote workflow pages" className="mt-3 flex flex-wrap items-center gap-3">
          <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}
            className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Previous</button>
          <span className="text-sm text-brand-dark/75">Page {offset / 50 + 1}</span>
          <button type="button" disabled={page.nextOffset === null} onClick={() => { if (page.nextOffset !== null) setOffset(page.nextOffset); }}
            className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Next</button>
        </nav> : null}
      </> : null}
    </section> : null}
  </details>;
}
