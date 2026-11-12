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
import { clearRecentProjects } from "./recent-projects";
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
const CONFIRM: Record<Action, { title: string; description: string; label: string }> = {
  history: { title: "Clear past answers?", label: "Clear past answers",
    description: "Deletes the answers CIGAR kept. Your projects keep their access. Guard's approvals and records are not touched." },
  saved: { title: "Remove saved notes?", label: "Remove saved notes",
    description: "Deletes everything CIGAR saved on this computer, including old projects, and ends current access. Turn CIGAR on and add your projects again to keep going. Guard's approvals and records are not touched." },
  data: { title: "Delete everything CIGAR knows?", label: "Delete everything",
    description: "Deletes past answers, saved notes, project access, app connections and the recent projects this page remembers. You can set it up again anytime. Guard's approvals and records are not touched." },
  recheck: { title: "Start CIGAR fresh?", label: "Start fresh",
    description: "Ends current access and checks CIGAR again. If it is turned on, it starts fresh. Add your projects again afterward." },
};
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
      setStatus(null); setData(null); setMessage(cause instanceof Error ? cause.message : "CIGAR did not answer. Try Refresh.");
    } }
    finally { if (changes) onBusyChange(false); if (revision.current === current) setBusy(false); }
  }
  useEffect(() => {
    const controller = new AbortController();
    request.current = controller;
    void refresh(controller.signal).catch(() => { if (!controller.signal.aborted) setMessage("CIGAR did not answer. Try Refresh, or turn it off."); });
    return () => { revision.current += 1; controller.abort(); request.current?.abort(); onBusyChange(false); };
  }, []);

  function execute(action: Action) {
    setConfirm(null);
    void perform(async (signal) => {
      if (action === "history") {
        const value = await forgetContextHistory(signal);
        if (!signal.aborted) { setData(value); setMessage("Past answers cleared. Your projects keep their access."); }
      } else if (action === "saved") {
        await forgetSavedEvidence(signal);
        await refresh(signal);
        if (!signal.aborted) setMessage("Saved notes removed. Turn CIGAR on and add your projects again to keep going.");
      } else if (action === "data") {
        await manageContextWorkspace("clear", undefined, undefined, signal);
        clearRecentProjects();
        await refresh(signal);
        if (!signal.aborted) setMessage("Everything CIGAR knew is deleted. Add a project to start again.");
      } else {
        const value = await controlContextAssistance("recheck", signal);
        if (!signal.aborted) { setStatus(value); setData(null); setMessage("Checking CIGAR again. Refresh in a moment to see how it went."); }
      }
    }, true);
  }
  function stop() {
    void perform(async (signal) => {
      const value = await controlContextAssistance("stop", signal);
      if (!signal.aborted) { setStatus(value); setData(null); onStopped(value.preferences); setMessage("CIGAR is off. Guard keeps protecting you as usual."); }
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
              <h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-brand-dark/55">Privacy and repair</h3>
              <p role="status" className="text-lg font-semibold tracking-[-0.01em] text-brand-dark">{copy.label}</p>
              <p className="max-w-[62ch] text-sm leading-6 text-brand-dark/75">{copy.detail}</p>
              <p className={caption + " max-w-[70ch]"}>What CIGAR prepares stays in this computer's memory. {status?.capabilities?.private_persistence
                ? "If you turn on saved notes, they are kept in private files here, not encrypted by Guard, until they expire or you remove them. After Guard restarts, add your projects again."
                : "This version cannot save notes. Anything saved earlier can still be checked and removed below."}</p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <button className={versionQuiet} type="button" disabled={busy || disabled} onClick={() => void perform(refresh)}><HiMiniArrowPath aria-hidden="true" className="size-4" />Refresh</button>
            <button className={versionQuiet} type="button" disabled={busy || !status} onClick={() => {
              if (status) downloadBlob(new Blob([JSON.stringify(contextDiagnostics(status, data), null, 2)], { type: "application/json" }), "guard-context-diagnostics.json");
            }}><HiMiniArrowDownTray aria-hidden="true" className="size-4" />Download diagnostics</button>
          </div>
        </div>
      </section>
      {message ? <p role="status" className="rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75">{message}</p> : null}
      <section className="space-y-3" aria-labelledby="cigar-data-held">
        <div><h3 id="cigar-data-held" className={versionHeading}>What CIGAR is holding</h3>
          <p className={versionLead}>Just counts. Your files, questions and folder names are never shown here.</p></div>
        {data ? <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          <Stat term="Projects with access (per app)" value={data.active_scopes} />
          <Stat term="Files it can read" value={data.selected_files} />
          <Stat term="Answers ready" value={data.current_contexts} />
          <Stat term="Past answers kept" value={data.history_entries} />
          <Stat term="Space used by past answers" value={data.history_encoded_bytes.toLocaleString() + " bytes"} />
          <Stat term="Connected apps" value={data.agent_sessions} />
        </dl> : <p className="rounded-2xl border border-dashed border-brand-dark/15 px-5 py-6 text-center text-sm text-brand-dark/70">Counts show up while CIGAR is on.</p>}
        <p className={caption}>CIGAR keeps at most 8 past answers (512 KiB) for each project and app, and clears them after the time you chose in Settings.</p>
      </section>
      {data?.saved_evidence ? <section className="space-y-3 rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5" role="region" aria-label="Saved context evidence">
        <h4 className="text-sm font-semibold text-brand-dark">Saved notes</h4>
        <p role="status" className="text-sm text-brand-dark/75">{savedEvidenceCopy(data.saved_evidence)}</p>
        {data.saved_evidence.slots !== null ? <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat term="Projects with saved notes (per app)" value={data.saved_evidence.slots} />
          <Stat term="Space used (bytes)" value={data.saved_evidence.bytes?.toLocaleString() ?? "Unavailable"} />
          <Stat term="Notes still saving" value={data.saved_evidence.unresolved_writes ?? "Unavailable"} />
          <Stat term="Expired, waiting to clear" value={data.saved_evidence.expired_slots ?? "Unavailable"} />
        </dl> : null}
        <p className={caption}>Saved notes cover at most 8 projects (each app counts separately) and use about 550 MB of disk.</p>
      </section> : null}
      <section className="space-y-3" aria-labelledby="cigar-data-fix">
        <h3 id="cigar-data-fix" className={versionHeading}>Fix a problem</h3>
        <ul className={versionList}>
          <Row title="Start CIGAR fresh" body={!ready ? "If CIGAR seems stuck, turn it off to free everything it holds. Starting fresh needs Python 3.14, which Settings can set up." : "Ends current access and starts CIGAR again. Add your projects again afterward."}
            action={<button className={versionButton} type="button" disabled={busy || disabled || !status?.verification_permitted || !status?.preferences.runtime_id || Boolean(status.job)} onClick={() => setConfirm("recheck")}>Start fresh</button>} />
          <Row title="Change setup" body="Choose what CIGAR may read and how long it keeps things."
            action={<a className={versionButton} href={guardAwareHref("/cigar?section=runtime")}>Open Settings</a>} />
        </ul>
      </section>
      <section className="space-y-3" aria-labelledby="cigar-data-danger">
        <div><h3 id="cigar-data-danger" className={versionHeading}>Delete or turn off</h3>
          <p className={versionLead}>Each one asks you first. Guard's approvals and records are never touched.</p></div>
        <ul className="divide-y divide-red-200/70 overflow-hidden rounded-2xl border border-red-200 bg-red-50/30">
          <Row title="Past answers" body="Deletes the answers CIGAR kept. Projects keep their access."
            action={<button className={danger} type="button" disabled={busy || disabled || !ready || !data?.history_entries} onClick={() => setConfirm("history")}>Clear past answers</button>} />
          {removable ? <Row title="Saved notes" body="Deletes what CIGAR saved on this computer, including old projects."
            action={<button className={danger} type="button" disabled={busy || disabled} onClick={() => setConfirm("saved")}>Remove saved notes</button>} /> : null}
          <Row title="Everything CIGAR knows" body="Deletes past answers, saved notes, project access, app connections and recent projects. You can set it up again anytime."
            action={<button className={danger} type="button" disabled={busy || disabled || (!ready && !data?.saved_evidence)} onClick={() => setConfirm("data")}>Delete everything</button>} />
          {offAvailable ? <Row title="Turn CIGAR off" body="Stops CIGAR now. Projects lose access until you turn it back on."
            action={<button className={danger} type="button" disabled={busy || disabled} onClick={stop}>Turn CIGAR off</button>} /> : null}
        </ul>
      </section>
    </div>
    {confirm ? <ConfirmDialog title={CONFIRM[confirm].title} description={CONFIRM[confirm].description} confirmLabel={CONFIRM[confirm].label}
      tone={confirm === "recheck" ? "default" : "destructive"} onCancel={() => setConfirm(null)} onConfirm={() => execute(confirm)} /> : null}
  </div>;
}
