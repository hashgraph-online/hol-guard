import { useCallback, useEffect, useId, useRef, useState } from "react";
import { HiMiniArrowPath, HiMiniLink } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import { SelectMenu } from "../select-menu";
import { versionHeading, versionLead, versionPrimary, versionQuiet } from "./versions-view";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { ContextAssistanceApiError } from "./api";
import { authorizeContextAgentSession, listContextAgentSessions, revokeContextAgentSession,
  type ContextAgentSession, type ContextWorkspaceScope } from "./workspaces-api";

const empty = "rounded-2xl border border-dashed border-brand-dark/15 px-5 py-6 text-center text-sm text-brand-dark/70";
type Props = { ready: boolean; enabled: boolean; dirty: boolean; generation: string | null; scopes: ContextWorkspaceScope[]; gate: GuardApprovalGatePublicConfig | null };

export function ContextAgentsPanel({ ready, enabled, dirty, generation, scopes, gate }: Props) {
  const [sessions, setSessions] = useState<ContextAgentSession[]>([]);
  const [selected, setSelected] = useState<Record<string, string>>({});
  const [confirm, setConfirm] = useState<ContextAgentSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const revision = useRef(0);
  const request = useRef<AbortController | null>(null);
  const pending = useRef(false);
  const allowed = ready && enabled;
  const idBase = useId();
  const confirmationScope = scopes.find((scope) => scope.scope_id === selected[confirm?.session_id ?? ""]);

  const refresh = useCallback(async () => {
    if (!allowed || pending.current) return;
    const id = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    try {
      const values = await listContextAgentSessions(controller.signal);
      if (revision.current === id) { setSessions(values); setStatusError(null); }
    } catch {
      if (revision.current === id) { setSessions([]); setStatusError("Connection status is unavailable. Refresh before granting access."); }
    }
  }, [allowed]);

  useEffect(() => {
    setSessions([]); setSelected({}); setConfirm(null); setError(null); setStatusError(null); setBusy(false);
    void refresh();
    const timer = allowed ? window.setInterval(() => { if (!document.hidden) void refresh(); }, 3_000) : null;
    return () => { revision.current += 1; request.current?.abort(); if (timer !== null) window.clearInterval(timer); };
  }, [allowed, generation, refresh]);

  async function perform(session: ContextAgentSession, credentials?: SettingsSaveProofCredentials, revoke = false) {
    if (pending.current) return;
    const scope = scopes.find((scope) => scope.scope_id === selected[session.session_id] && !scope.revoked && scope.app !== "dashboard");
    if (!revoke && (dirty || !scope)) return;
    pending.current = true;
    const id = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(null);
    try {
      if (revoke) await revokeContextAgentSession(session.session_id, controller.signal);
      else await authorizeContextAgentSession(session.session_id, scope!.scope_id, credentials, controller.signal);
      if (revision.current === id) setConfirm(null);
    } catch (failure) {
      if (revision.current === id) setError(failure instanceof ContextAssistanceApiError ? failure.message
        : "The connection change did not return a verified result. Refresh its status before trying again.");
    } finally {
      pending.current = false;
      if (revision.current === id) { setBusy(false); void refresh(); }
    }
  }

  const grants = scopes.filter((scope) => !scope.revoked && scope.app !== "dashboard").map((scope) => ({ value: scope.scope_id,
    label: harnessDisplayName(scope.app) + " · " + scope.workspace }));
  return <section aria-label="AI app context connections" className="space-y-4">
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
      <div><h3 className={versionHeading}>AI app context connections</h3>
        <p className={versionLead}>Use Guard's MCP server in your app, then match the connection code from get_context_status before granting access. Pairing authenticates that MCP process; the app label is your permission choice. A running runtime alone grants no app access.</p></div>
      {allowed ? <button className={versionQuiet} type="button" disabled={busy} onClick={() => { setError(null); void refresh(); }}><HiMiniArrowPath aria-hidden="true" className="size-4" />Refresh app connections</button> : null}
    </div>
    {!allowed ? <p className={empty}>Enable Context for AI apps, save settings and start a verified runtime to pair a connection.</p> : <>
      {error || statusError ? <p role="alert" className="cigar-note">{error ?? statusError}</p> : null}
      {sessions.length === 0 ? <p className={empty}>No context connection is waiting or paired.</p> : <ul className="space-y-3">{sessions.map((session) => <li key={session.session_id}><section
        className={"space-y-3 rounded-2xl border p-4 sm:p-5 " + (session.phase === "pending" ? "border-brand-blue/25 bg-brand-blue/[0.03]" : "border-brand-dark/10 bg-white")} aria-label={`Context connection ${session.session_id}`}>
        <div className="flex flex-wrap items-center gap-2">
          <span aria-hidden="true" className="flex size-9 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue"><HiMiniLink className="size-4" /></span>
          <Tag tone={session.phase === "pending" ? "attention" : "green"}>{session.phase === "pending" ? "Waiting for your permission" : "Grant assigned"}</Tag>
          <span className="text-xs text-brand-dark/60">expires in {Math.ceil(session.expires_in_seconds / 60)} minutes</span>
        </div>
        <p className="break-all font-mono text-xs text-brand-dark/70">Connection code: <span className="font-semibold text-brand-dark">{session.session_id}</span></p>
        {session.phase === "pending" ? <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
          <div><span id={`${idBase}-${session.session_id}`} className="text-sm font-medium text-brand-dark">Workspace and app grant</span>
            <SelectMenu labelledBy={`${idBase}-${session.session_id}`} className="mt-1.5 w-full" disabled={busy || dirty} placeholder="Choose a grant"
              value={selected[session.session_id] ?? ""} options={grants} onChange={(value) => setSelected((values) => ({ ...values, [session.session_id]: value }))} /></div>
          <button className={versionPrimary} type="button" disabled={busy || dirty || !selected[session.session_id]} onClick={() => { if (gate?.enabled) setConfirm(session); else void perform(session); }}>Authorize context connection</button>
        </div> : <p className="break-all text-sm text-brand-dark/75">{scopes.find((scope) => scope.scope_id === session.scope_id)?.workspace ?? "This grant is unavailable. Revoke it and pair again."}</p>}
        <button className={versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800"} type="button" disabled={busy} onClick={() => void perform(session, undefined, true)}>Revoke context connection</button>
      </section></li>)}</ul>}
    </>}
    <SettingsSaveProofModal open={confirm !== null} mode="verify-save" gate={gate} title="Authorize AI app context"
      detail={`Grant connection ${confirm?.session_id ?? ""} access to ${confirmationScope ? `${harnessDisplayName(confirmationScope.app)} sources in ${confirmationScope.workspace}` : "the selected sources"} for this runtime session.${confirmationScope?.sharing?.mode === "shared_broker" ? ` Five-minute lease. Reviewed shared notes: ${confirmationScope.sharing.notes.read ? "allowed" : "not granted"}. Note proposals: ${confirmationScope.sharing.notes.propose ? "allowed, subject to your separate review" : "not granted"}.` : ""} This grants no command approval.`}
      confirmLabel="Authorize connection" pending={busy} error={error} onCancel={() => { if (!busy) setConfirm(null); }}
      onConfirm={(credentials) => { if (confirm) void perform(confirm, credentials); }} />
  </section>;
}
