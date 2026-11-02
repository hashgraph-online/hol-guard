import { useEffect, useRef, useState, type ReactNode } from "react";
import { ConfirmDialog } from "../confirm-dialog";
import { guardAwareHref } from "../guard-api";
import { downloadBlob } from "../history-export";
import { HiMiniArrowDownTray, HiMiniArrowPath, HiMiniLockClosed } from "react-icons/hi2";
import { versionButton, versionHeading, versionLead, versionList, versionQuiet } from "./versions-view";
import type { GuardContextAssistanceConfig } from "../guard-types";
import { controlContextAssistance, fetchContextAssistance } from "./api";
import { fetchContextData, forgetContextHistory, forgetSavedEvidence, type ContextDataSummary } from "./history-api";
import { manageContextWorkspace } from "./workspaces-api";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus } from "./types";
import { savedEvidenceCopy } from "./saved-evidence";

const caption = "text-xs leading-5 text-brand-dark/60";
const danger = "inline-flex min-h-11 items-center justify-center rounded-lg border border-red-200 bg-white px-3.5 py-2 text-sm font-semibold text-red-700 transition-colors hover:border-red-300 hover:bg-red-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400/40 disabled:cursor-not-allowed disabled:opacity-50 motion-reduce:transition-none";
function Stat({ term, value }: { term: string; value: ReactNode }) {
  return <div className="rounded-xl border border-brand-dark/[0.08] bg-white px-3.5 py-3"><dt className="text-xs text-brand-dark/60">{term}</dt><dd className="mt-1 text-lg font-semibold tabular-nums text-brand-dark">{value}</dd></div>;
}
function Row({ title, body, action }: { title: string; body: string; action: ReactNode }) {
  return <li className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3 px-4 py-4 sm:px-5">
    <div className="min-w-0 flex-[1_1_16rem]"><p className="text-sm font-semibold text-brand-dark">{title}</p><p className="mt-0.5 text-xs leading-5 text-brand-dark/65">{body}</p></div>
    <div className="shrink-0">{action}</div></li>;
}
type Action = "history" | "data" | "saved" | "recheck";
type Props = { savedEnabled: boolean; disabled: boolean; onStopped: (value: GuardContextAssistanceConfig) => void; onBusyChange: (busy: boolean) => void };

export function contextDiagnostics(status: ContextAssistanceStatus, data: ContextDataSummary | null) {
  const runtime = status.runtime ?? status.last_check;
  const code = (value: string | null) => value === null ? null : /^[a-z0-9_]{1,160}$/.test(value) ? value : "redacted_diagnostic";
  return { schema: "guard-context-diagnostics.v1", exported_at: new Date().toISOString(), data_role: true,
    availability: status.availability, requested_enabled: status.requested_enabled, effective_enabled: status.effective_enabled,
    qualification: status.qualification, diagnostic: code(status.diagnostic), restriction: code(status.restriction), status_observation: "last_successful_refresh",
    verification_permitted: status.verification_permitted, generation: status.generation,
    job: status.job ? { operation: status.job.operation, phase: status.job.phase } : null,
    runtime: runtime ? { python_version: runtime.interpreter.version, python_implementation: runtime.interpreter.implementation,
      sdk_version: runtime.package_version, protocol: runtime.protocol, worker_fingerprint: runtime.worker_fingerprint,
      package_fingerprint: runtime.package_fingerprint, compile_verified: runtime.compile_verified,
      persistence_compile_verified: runtime.persistence_compile_verified ?? false, active: runtime.active } : null,
    storage: { mode: status.effective_preferences.storage.mode, retention_hours: status.effective_preferences.storage.retention_hours },
    counts: data ? { active_scopes: data.active_scopes, selected_files: data.selected_files, current_contexts: data.current_contexts,
      history_entries: data.history_entries, history_encoded_bytes: data.history_encoded_bytes, agent_sessions: data.agent_sessions,
      saved_evidence: data.saved_evidence ? { status: data.saved_evidence.status, slots: data.saved_evidence.slots,
        bytes: data.saved_evidence.bytes, unresolved_writes: data.saved_evidence.unresolved_writes,
        invalid_records: data.saved_evidence.invalid_records, diagnostic: code(data.saved_evidence.diagnostic) } : null } : null,
    redaction: "No source text, queries, workspace paths, executable paths, credentials or approval tokens." };
}

export function ContextDataRepairPanel({ savedEnabled, disabled, onStopped, onBusyChange }: Props) {
  const [status, setStatus] = useState<ContextAssistanceStatus | null>(null);
  const [data, setData] = useState<ContextDataSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Action | null>(null);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);

  async function refresh(signal: AbortSignal) {
    const value = await fetchContextAssistance(signal);
    if (signal.aborted) return;
    setStatus(value); setData(null);
    const summary = await fetchContextData(signal);
    if (!signal.aborted) setData(summary);
  }
  async function perform(operation: (signal: AbortSignal) => Promise<void>, changes = false) {
    if (busy || disabled) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setMessage(null);
    if (changes) onBusyChange(true);
    try { await operation(controller.signal); }
    catch (cause) { if (revision.current === current && !controller.signal.aborted) {
      setStatus(null); setData(null); setMessage(cause instanceof Error ? cause.message : "Context data is unavailable. Refresh its status.");
    } }
    finally { if (changes) onBusyChange(false); if (revision.current === current) setBusy(false); }
  }
  useEffect(() => {
    const controller = new AbortController();
    request.current = controller;
    void refresh(controller.signal).catch(() => { if (!controller.signal.aborted) setMessage("Context status is unavailable. Refresh or turn off the feature to check it."); });
    return () => { revision.current += 1; controller.abort(); request.current?.abort(); onBusyChange(false); };
  }, []);

  function execute(action: Action) {
    setConfirm(null);
    void perform(async (signal) => {
      if (action === "history") {
        const value = await forgetContextHistory(signal);
        if (!signal.aborted) { setData(value); setMessage("Prepared context history cleared. Current context and source access remain available."); }
      } else if (action === "saved") {
        await forgetSavedEvidence(signal);
        await refresh(signal);
        if (!signal.aborted) setMessage("Saved evidence removed and current context access ended. Check and start the runtime, then grant sources again to continue.");
      } else if (action === "data") {
        await manageContextWorkspace("clear", undefined, undefined, signal);
        await refresh(signal);
        if (!signal.aborted) setMessage("Context data cleared. Grant workspace and app access again before preparing more context.");
      } else {
        const value = await controlContextAssistance("recheck", signal);
        if (!signal.aborted) { setStatus(value); setData(null); setMessage("Runtime check scheduled. Refresh status to see the result; earlier context access has ended."); }
      }
    }, true);
  }
  function stop() {
    void perform(async (signal) => {
      const value = await controlContextAssistance("stop", signal);
      if (!signal.aborted) { setStatus(value); setData(null); onStopped(value.preferences); setMessage("Context assistance is off. Guard approvals and evidence remain available."); }
    }, true);
  }
  const ready = Boolean(status?.effective_enabled);
  const copy = status ? contextStatusCopy(status) : { label: "Status unavailable", detail: "Refresh context status to inspect this optional feature." };
  const offAvailable = Boolean(savedEnabled || status?.requested_enabled || status?.effective_enabled || status?.job);
  const removable = Boolean(data?.saved_evidence && data.saved_evidence.status !== "empty" && data.saved_evidence.status !== "unsupported");
  return <div className="space-y-8">
    <div role="region" aria-label="Context data and repair controls" className="space-y-8" aria-busy={busy}>
      <section className="guard-surface-in rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5" aria-label="Context data status">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-4">
          <div className="flex min-w-0 flex-[1_1_20rem] items-start gap-3.5">
            <span aria-hidden="true" className={"flex size-10 shrink-0 items-center justify-center rounded-full " + (ready ? "bg-brand-green-bg text-brand-green-text" : "bg-brand-dark/[0.06] text-brand-dark/55")}>
              <HiMiniLockClosed className="size-5" /></span>
            <div className="min-w-0 space-y-1.5">
              <h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-brand-dark/55">Context data and repair</h3>
              <p role="status" className="text-lg font-semibold tracking-[-0.01em] text-brand-dark">{copy.label}</p>
              <p className="max-w-[62ch] text-sm leading-6 text-brand-dark/75">{copy.detail}</p>
              <p className={caption + " max-w-[70ch]"}>Prepared contexts and history use local memory. {status?.capabilities?.private_persistence
                ? "Optional saved evidence uses private local files, with no Guard encryption. It remains after the runtime stops until expiry cleanup or removal. Guard removes expired evidence while running or before reuse after launch. Permissions must be granted again after restart."
                : "This build cannot activate saved evidence. Existing saved evidence can still be inspected and removed below."}</p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <button className={versionQuiet} type="button" disabled={busy || disabled} onClick={() => void perform(refresh)}><HiMiniArrowPath aria-hidden="true" className="size-4" />Refresh context data</button>
            <button className={versionQuiet} type="button" disabled={busy || !status} onClick={() => {
              if (status) downloadBlob(new Blob([JSON.stringify(contextDiagnostics(status, data), null, 2)], { type: "application/json" }), "guard-context-diagnostics.json");
            }}><HiMiniArrowDownTray aria-hidden="true" className="size-4" />Export context diagnostics</button>
          </div>
        </div>
      </section>
      {message ? <p role="status" className="rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75">{message}</p> : null}
      <section className="space-y-3" aria-labelledby="cigar-data-held">
        <div><h3 id="cigar-data-held" className={versionHeading}>What CIGAR is holding</h3>
          <p className={versionLead}>Counts only. Guard never shows source text, queries or paths here.</p></div>
        {data ? <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          <Stat term="Active workspace/app grants" value={data.active_scopes} />
          <Stat term="Selected files" value={data.selected_files} />
          <Stat term="Current contexts" value={data.current_contexts} />
          <Stat term="Prepared history entries" value={data.history_entries} />
          <Stat term="Encoded history payload" value={data.history_encoded_bytes.toLocaleString() + " bytes"} />
          <Stat term="App connections" value={data.agent_sessions} />
        </dl> : <p className="rounded-2xl border border-dashed border-brand-dark/15 px-5 py-6 text-center text-sm text-brand-dark/70">Live context counts are available while a verified runtime is ready.</p>}
        <p className={caption}>History is limited to eight entries and 512 KiB of encoded payload per workspace/app grant, with the configured retention period. These counts do not measure process memory or execution safety.</p>
      </section>
      {data?.saved_evidence ? <section className="space-y-3 rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5" role="region" aria-label="Saved context evidence">
        <h4 className="text-sm font-semibold text-brand-dark">Saved evidence</h4>
        <p role="status" className="text-sm text-brand-dark/75">{savedEvidenceCopy(data.saved_evidence)}</p>
        {data.saved_evidence.slots !== null ? <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat term="Saved workspace/app stores" value={data.saved_evidence.slots} />
          <Stat term="Saved file bytes" value={data.saved_evidence.bytes?.toLocaleString() ?? "Unavailable"} />
          <Stat term="Note writes to reconcile" value={data.saved_evidence.unresolved_writes ?? "Unavailable"} />
          <Stat term="Expired stores awaiting cleanup" value={data.saved_evidence.expired_slots ?? "Unavailable"} />
        </dl> : null}
        <p className={caption}>Saved evidence is limited to eight stores and 528 MiB of logical file bytes, including database journals. This does not measure process memory.</p>
      </section> : null}
      <section className="space-y-3" aria-labelledby="cigar-data-fix">
        <h3 id="cigar-data-fix" className={versionHeading}>Fix a problem</h3>
        <ul className={versionList}>
          <Row title="Check the runtime again" body={!ready ? "If a runtime is unavailable, turn off assistance to release its context. Rechecking requires an enrolled Python 3.14 runtime." : "Ends current context access, then checks the selected runtime. Grant access again afterward."}
            action={<button className={versionButton} type="button" disabled={busy || disabled || !status?.verification_permitted || !status?.preferences.runtime_id || Boolean(status.job)} onClick={() => setConfirm("recheck")}>Recheck context runtime</button>} />
          <Row title="Change setup" body="Runtime, sources, limits and storage live in Settings."
            action={<a className={versionButton} href={guardAwareHref("/cigar?section=runtime")}>Manage context setup</a>} />
        </ul>
      </section>
      <section className="space-y-3" aria-labelledby="cigar-data-danger">
        <div><h3 id="cigar-data-danger" className={versionHeading}>Delete or turn off</h3>
          <p className={versionLead}>Each of these asks you first. Guard approvals and evidence are never touched.</p></div>
        <ul className="divide-y divide-red-200/70 overflow-hidden rounded-2xl border border-red-200 bg-red-50/30">
          <Row title="Prepared context history" body="Deletes retained historical briefs. Current contexts and source permissions stay."
            action={<button className={danger} type="button" disabled={busy || disabled || !ready || !data?.history_entries} onClick={() => setConfirm("history")}>Clear context history</button>} />
          {removable ? <Row title="Saved evidence" body="Removes saved source evidence and reviewed notes, including inactive stores."
            action={<button className={danger} type="button" disabled={busy || disabled} onClick={() => setConfirm("saved")}>Remove saved evidence</button>} /> : null}
          <Row title="Everything CIGAR knows" body="Deletes briefs, saved evidence, source grants and app connections. You can grant access again later."
            action={<button className={danger} type="button" disabled={busy || disabled || (!ready && !data?.saved_evidence)} onClick={() => setConfirm("data")}>Clear all context data</button>} />
          {offAvailable ? <Row title="Turn CIGAR off" body="Stops the runtime now and ends all context access."
            action={<button className={danger} type="button" disabled={busy || disabled} onClick={stop}>Turn off context assistance</button>} /> : null}
        </ul>
      </section>
    </div>
    {confirm ? <ConfirmDialog title={confirm === "history" ? "Clear prepared context history?" : confirm === "saved" ? "Remove saved evidence?" : confirm === "data" ? "Clear all context data?" : "Recheck context runtime?"}
      description={confirm === "history" ? "Deletes retained historical briefs. Current contexts and source permissions stay available. Guard approvals and evidence are unchanged."
        : confirm === "saved" ? "Ends current context access and removes saved source evidence and reviewed notes, including inactive stores. Check and start the runtime and grant access again to continue. Guard approvals and evidence are unchanged."
        : confirm === "data" ? "Closes context graphs and deletes retained briefs, saved evidence, native context origins, source grants and app connections. Grant access again to continue. Guard approvals and evidence are unchanged."
        : "Ends current context access and checks the selected runtime again. An enabled preference may start a fresh runtime. Grant source and app access again afterward."}
      confirmLabel={confirm === "history" ? "Clear history" : confirm === "saved" ? "Remove saved evidence" : confirm === "data" ? "Clear context data" : "Recheck runtime"}
      tone={confirm === "recheck" ? "default" : "destructive"} onCancel={() => setConfirm(null)} onConfirm={() => execute(confirm)} /> : null}
  </div>;
}
