import { useEffect, useRef, useState } from "react";
import { ConfirmDialog } from "../confirm-dialog";
import { guardAwareHref } from "../guard-api";
import { downloadBlob } from "../history-export";
import { SettingsFormSection } from "../settings/settings-row-primitives";
import type { GuardContextAssistanceConfig } from "../guard-types";
import { controlContextAssistance, fetchContextAssistance } from "./api";
import { fetchContextData, forgetContextHistory, forgetSavedEvidence, type ContextDataSummary } from "./history-api";
import { manageContextWorkspace } from "./workspaces-api";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus } from "./types";
import { savedEvidenceCopy } from "./saved-evidence";

const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
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
  return <SettingsFormSection title="Context data and repair" description="Inspect or clear optional context separately from Guard approvals and evidence.">
    <div role="region" aria-label="Context data and repair controls" className="space-y-3 py-4" aria-busy={busy}>
      <p role="status" className="text-sm font-semibold text-brand-dark">{copy.label}</p>
      <p className="text-sm text-slate-600">{copy.detail}</p>
      <p className="text-sm text-slate-600">Prepared contexts and history use local memory. {status?.capabilities?.private_persistence
        ? "Optional saved evidence uses private local files, with no Guard encryption. It remains after the runtime stops until expiry cleanup or removal. Guard removes expired evidence while running or before reuse after launch. Permissions must be granted again after restart."
        : "This build cannot activate saved evidence. Existing saved evidence can still be inspected and removed below."}</p>
      {data ? <dl className="grid grid-cols-2 gap-2 text-sm text-slate-600">
        <dt>Active workspace/app grants</dt><dd>{data.active_scopes}</dd>
        <dt>Selected files</dt><dd>{data.selected_files}</dd>
        <dt>Current contexts</dt><dd>{data.current_contexts}</dd>
        <dt>Prepared history entries</dt><dd>{data.history_entries}</dd>
        <dt>Encoded history payload</dt><dd>{data.history_encoded_bytes.toLocaleString()} bytes</dd>
        <dt>App connections</dt><dd>{data.agent_sessions}</dd>
      </dl> : <p className="text-sm text-slate-600">Live context counts are available while a verified runtime is ready.</p>}
      {data?.saved_evidence ? <div className="space-y-2 text-sm text-slate-600" role="region" aria-label="Saved context evidence">
        <p role="status">{savedEvidenceCopy(data.saved_evidence)}</p>
        {data.saved_evidence.slots !== null ? <dl className="grid grid-cols-2 gap-2">
          <dt>Saved workspace/app stores</dt><dd>{data.saved_evidence.slots}</dd>
          <dt>Saved file bytes</dt><dd>{data.saved_evidence.bytes?.toLocaleString() ?? "Unavailable"}</dd>
          <dt>Note writes to reconcile</dt><dd>{data.saved_evidence.unresolved_writes ?? "Unavailable"}</dd>
          <dt>Expired stores awaiting cleanup</dt><dd>{data.saved_evidence.expired_slots ?? "Unavailable"}</dd>
        </dl> : null}
        <p>Saved evidence is limited to eight stores and 528 MiB of logical file bytes, including database journals. This does not measure process memory.</p>
      </div> : null}
      <p className="text-sm text-slate-600">History is limited to eight entries and 512 KiB of encoded payload per workspace/app grant, with the configured retention period. These counts do not measure process memory or execution safety.</p>
      {message ? <p role="status" className="text-sm text-slate-600">{message}</p> : null}
      <div className="flex flex-wrap gap-2">
        <button className={button} type="button" disabled={busy || disabled} onClick={() => void perform(refresh)}>Refresh context data</button>
        <button className={button} type="button" disabled={busy || disabled || !ready || !data?.history_entries} onClick={() => setConfirm("history")}>Clear context history</button>
        <button className={button} type="button" disabled={busy || disabled || (!ready && !data?.saved_evidence)} onClick={() => setConfirm("data")}>Clear all context data</button>
        {data?.saved_evidence && data.saved_evidence.status !== "empty" && data.saved_evidence.status !== "unsupported"
          ? <button className={button} type="button" disabled={busy || disabled} onClick={() => setConfirm("saved")}>Remove saved evidence</button> : null}
        <button className={button} type="button" disabled={busy || disabled || !status?.verification_permitted || !status?.preferences.runtime_id || Boolean(status.job)} onClick={() => setConfirm("recheck")}>Recheck context runtime</button>
        <button className={button} type="button" disabled={busy || !status} onClick={() => {
          if (status) downloadBlob(new Blob([JSON.stringify(contextDiagnostics(status, data), null, 2)], { type: "application/json" }), "guard-context-diagnostics.json");
        }}>Export context diagnostics</button>
        {(savedEnabled || status?.requested_enabled || status?.effective_enabled || status?.job) ? <button className={button} type="button" disabled={busy || disabled} onClick={stop}>Turn off context assistance</button> : null}
        <a className={`${button} inline-flex items-center`} href={guardAwareHref("/cigar?section=runtime")}>Manage context setup</a>
      </div>
      {!ready ? <p className="text-sm text-slate-600">If a runtime is unavailable, turn off assistance to release its context. Rechecking requires an enrolled Python 3.14 runtime.</p> : null}
    </div>
    {confirm ? <ConfirmDialog title={confirm === "history" ? "Clear prepared context history?" : confirm === "saved" ? "Remove saved evidence?" : confirm === "data" ? "Clear all context data?" : "Recheck context runtime?"}
      description={confirm === "history" ? "Deletes retained historical briefs. Current contexts and source permissions stay available. Guard approvals and evidence are unchanged."
        : confirm === "saved" ? "Ends current context access and removes saved source evidence and reviewed notes, including inactive stores. Check and start the runtime and grant access again to continue. Guard approvals and evidence are unchanged."
        : confirm === "data" ? "Closes context graphs and deletes retained briefs, saved evidence, native context origins, source grants and app connections. Grant access again to continue. Guard approvals and evidence are unchanged."
        : "Ends current context access and checks the selected runtime again. An enabled preference may start a fresh runtime. Grant source and app access again afterward."}
      confirmLabel={confirm === "history" ? "Clear history" : confirm === "saved" ? "Remove saved evidence" : confirm === "data" ? "Clear context data" : "Recheck runtime"}
      tone={confirm === "recheck" ? "default" : "destructive"} onCancel={() => setConfirm(null)} onConfirm={() => execute(confirm)} /> : null}
  </SettingsFormSection>;
}
