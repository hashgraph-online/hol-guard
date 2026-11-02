import { useEffect, useId, useRef, useState } from "react";
import { SelectMenu } from "../select-menu";
import { guardAwareHref } from "../guard-api";
import { harnessDisplayName } from "../approval-center-utils";
import { fetchContextAssistance } from "./api";
import { ContextBriefView } from "./brief-view";
import { listContextHistory, readContextHistory, type ContextHistoryDetail, type ContextHistoryEntry, type ContextHistorySummary } from "./history-api";
import { listContextWorkspaces, type ContextWorkspaceScope } from "./workspaces-api";

const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
const preparedAt = (value: string) => {
  const date = new Date(Number(value));
  return Number.isNaN(date.getTime()) ? "Unknown preparation time" : date.toLocaleString();
};
type Props = { decisionId?: string; harness?: string };

export function ContextHistoryPanel({ decisionId, harness }: Props) {
  const [open, setOpen] = useState(false);
  const [scopes, setScopes] = useState<ContextWorkspaceScope[]>([]);
  const [scope, setScope] = useState<ContextWorkspaceScope | null>(null);
  const [entries, setEntries] = useState<ContextHistoryEntry[]>([]);
  const [summary, setSummary] = useState<ContextHistorySummary | null>(null);
  const [detail, setDetail] = useState<ContextHistoryDetail | null>(null);
  const [previous, setPrevious] = useState<ContextHistoryDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const revision = useRef(0);
  const generation = useRef<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const id = useId();
  useEffect(() => {
    revision.current += 1; request.current?.abort(); generation.current = null;
    setOpen(false); setScopes([]); setScope(null); setEntries([]); setDetail(null); setPrevious(null); setError(null); setBusy(false);
    return () => { revision.current += 1; request.current?.abort(); };
  }, [decisionId, harness]);

  useEffect(() => {
    if (!open || !scope) return;
    const controller = new AbortController();
    let pending = false;
    const timer = window.setInterval(() => {
      if (pending) return;
      pending = true;
      void fetchContextAssistance(controller.signal).then(async (status) => {
        if (!status.effective_enabled || status.generation !== generation.current) throw new Error("Context access changed. Reload history to continue.");
        const result = await listContextHistory(scope, decisionId, controller.signal);
        if (controller.signal.aborted) return;
        setEntries(result.entries); setSummary(result.summary);
        setDetail((value) => value && result.entries.some((entry) => entry.history_id === value.entry.history_id) ? value : null);
        setPrevious((value) => value && result.entries.some((entry) => entry.history_id === value.entry.history_id) ? value : null);
      }).catch(() => {
        if (!controller.signal.aborted) {
          revision.current += 1; request.current?.abort(); setBusy(false);
          setEntries([]); setDetail(null); setPrevious(null); setScope(null);
          setError("Context access changed or its runtime stopped. Reload history to check availability.");
        }
      }).finally(() => { pending = false; });
    }, 3000);
    return () => { window.clearInterval(timer); controller.abort(); };
  }, [open, scope, decisionId]);

  async function perform(operation: (signal: AbortSignal) => Promise<void>) {
    if (busy) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(null); setOpen(true);
    try { await operation(controller.signal); }
    catch (cause) {
      if (revision.current === current && !controller.signal.aborted) {
        setDetail(null); setPrevious(null); setEntries([]);
        setError(cause instanceof Error ? cause.message : "Prepared history is unavailable.");
      }
    } finally { if (revision.current === current) setBusy(false); }
  }
  async function choose(selected: ContextWorkspaceScope, signal: AbortSignal) {
    setDetail(null); setPrevious(null); setEntries([]);
    const value = await listContextHistory(selected, decisionId, signal);
    if (!signal.aborted) { setScope(value.scope); setEntries(value.entries); setSummary(value.summary); }
  }
  function load() {
    void perform(async (signal) => {
      const status = await fetchContextAssistance(signal);
      if (!status.effective_enabled) throw new Error("No active context history is available. Check Context assistance in Protection.");
      generation.current = status.generation;
      // Receipt paths are privacy-redacted display metadata. Native grants
      // and each history entry's decision association determine selection.
      const granted = (await listContextWorkspaces(signal)).filter((scope) => !scope.revoked
        && (!harness || scope.app === "dashboard" || scope.app === harness));
      if (signal.aborted) return;
      setScopes(granted); setDetail(null); setPrevious(null); setEntries([]); setScope(null);
      const selected = granted.find((scope) => scope.app === "dashboard") ?? granted[0];
      if (selected) await choose(selected, signal);
    });
  }

  return <section aria-label="Prepared context history" className="space-y-3 rounded-xl border border-slate-200 bg-white p-4">
    <h3 className="text-sm font-semibold text-brand-dark">Prepared context history</h3>
    <p className="text-sm text-slate-600">Historical supporting data from authorized sources. Preparation does not confirm delivery, approval, or execution. History stays in local memory while access remains available.</p>
    <div className="flex flex-wrap gap-2">
      <button className={button} type="button" disabled={busy} onClick={load}>{busy ? "Loading context history…" : "Load prepared context history"}</button>
      <a className={`${button} inline-flex items-center`} href={guardAwareHref("/cigar?section=data")}>Manage context data</a>
    </div>
    {error ? <p role="status" className="text-sm text-slate-600">{error}</p> : null}
    {open && !busy && !error && scopes.length === 0 ? <p className="text-sm text-slate-600">No authorized workspace has available context history.</p> : null}
    {open && scopes.length > 0 ? <div><span id={id + "-label"} className="text-sm text-slate-600">Context workspace and app</span>
      <SelectMenu id={id} labelledBy={id + "-label"} className="mt-1 w-full" disabled={busy} value={scope?.scope_id ?? ""} placeholder="Choose authorized context access"
        options={scopes.map((item) => ({ value: item.scope_id, label: item.workspace + " · " + (item.app === "dashboard" ? "Guard dashboard" : harnessDisplayName(item.app)) }))}
        onChange={(value) => { const selected = scopes.find((item) => item.scope_id === value); if (selected) void perform((signal) => choose(selected, signal)); }} />
    </div> : null}
    {scope && !busy && entries.length === 0 ? <p className="text-sm text-slate-600">No prepared context is retained for this selection.</p> : null}
    {scope && summary && summary.dropped !== "0" ? <p role="status" className="text-sm text-slate-600">Some prepared observations were omitted by history limits. This is a bounded window; Guard's evidence log is separate.</p> : null}
    <ul className="space-y-2">{entries.map((entry, index) => <li key={entry.history_id}>
      <button className={`${button} w-full text-left`} type="button" disabled={busy} aria-pressed={detail?.entry.history_id === entry.history_id}
        onClick={() => { if (scope) void perform(async (signal) => {
          const value = await readContextHistory(scope, entry.history_id, signal);
          if (!signal.aborted) {
            if (!value.brief) setPrevious(null);
            else if (detail && detail.entry.history_id !== value.entry.history_id) setPrevious(detail);
            setDetail(value);
          }
        }); }}>
        View prepared context {index + 1} · {preparedAt(entry.prepared_at_ms)} · {entry.rendered_tokens} tokens
        {entry.association ? <span className="block break-all text-xs">Native decision {entry.association.decision_id}</span> : null}
      </button>
    </li>)}</ul>
    {detail ? <section aria-label="Historical prepared context" className="space-y-3 border-t border-slate-200 pt-3">
      <p className="text-sm font-semibold text-brand-dark">Historical · prepared {preparedAt(detail.entry.prepared_at_ms)}</p>
      <p className="text-sm text-slate-600">Source state was checked when opened. Native facts describe the recorded evaluation. This view makes no current execution or approval claim.</p>
      {detail.brief ? <ContextBriefView brief={detail.brief} scope={detail.scope} /> : <p role="status" className="text-sm text-slate-600">Retained text is withheld because current source access is unavailable. Check or withdraw source access in Protection.</p>}
      <ul className="space-y-1 text-sm text-slate-600">{detail.source_states.map((source) => <li key={source.source_id}>
        {detail.entry.sources.find((item) => item.source_id === source.source_id)?.path}: {source.state === "changed" ? "Changed since preparation" : source.state === "unchanged" ? "Same source version when checked" : "Source unavailable"}
      </li>)}</ul>
      {previous?.brief ? <details><summary className="min-h-11 cursor-pointer text-sm font-semibold">Compare with previously opened context</summary>
        <p className="mb-2 text-sm text-slate-600">Both snapshots are historical. Source and policy digests identify their recorded revisions.</p>
        <ContextBriefView brief={previous.brief} scope={previous.scope} />
      </details> : null}
    </section> : null}
  </section>;
}
