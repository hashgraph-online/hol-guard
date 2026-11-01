import { useCallback, useEffect, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { ContextAssistanceApiError } from "./api";
import { authorizeContextAgentSession, listContextAgentSessions, revokeContextAgentSession,
  type ContextAgentSession, type ContextWorkspaceScope } from "./workspaces-api";

const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
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

  return <section aria-label="AI app context connections" className="space-y-3 rounded-lg border border-slate-200 p-3">
    <h4 className="text-sm font-semibold text-brand-dark">AI app context connections</h4>
    <p className="text-sm text-slate-600">Use Guard's MCP server in your app, then match the connection code from get_context_status before granting access. Pairing authenticates that MCP process; the app label is your permission choice. A running runtime alone grants no app access.</p>
    {!allowed ? <p className="text-sm text-slate-600">Enable Context for AI apps, save settings and start a verified runtime to pair a connection.</p> : <>
      {error || statusError ? <p role="alert" className="text-sm text-red-700">{error ?? statusError}</p> : null}
      <button className={button} type="button" disabled={busy} onClick={() => { setError(null); void refresh(); }}>Refresh app connections</button>
      {sessions.length === 0 ? <p className="text-sm text-slate-600">No context connection is waiting or paired.</p> : sessions.map((session) => <section key={session.session_id} className="space-y-2 border-t border-slate-100 pt-3" aria-label={`Context connection ${session.session_id}`}>
        <p className="break-all font-mono text-xs text-slate-600">Connection code: {session.session_id}</p>
        <p className="text-sm text-slate-600">{session.phase === "pending" ? "Waiting for your permission" : "Grant assigned"} · expires in {Math.ceil(session.expires_in_seconds / 60)} minutes.</p>
        {session.phase === "pending" ? <>
          <label className="block text-sm text-slate-600">Workspace and app grant
            <select className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm" disabled={busy || dirty}
              value={selected[session.session_id] ?? ""} onChange={(event) => setSelected((values) => ({ ...values, [session.session_id]: event.target.value }))}>
              <option value="">Choose a grant</option>
              {scopes.filter((scope) => !scope.revoked && scope.app !== "dashboard").map((scope) => <option key={scope.scope_id} value={scope.scope_id}>{harnessDisplayName(scope.app)} · {scope.workspace}</option>)}
            </select>
          </label>
          <button className={button} type="button" disabled={busy || dirty || !selected[session.session_id]} onClick={() => { if (gate?.enabled) setConfirm(session); else void perform(session); }}>Authorize context connection</button>
        </> : <p className="text-sm text-slate-600">{scopes.find((scope) => scope.scope_id === session.scope_id)?.workspace ?? "This grant is unavailable. Revoke it and pair again."}</p>}
        <button className={button} type="button" disabled={busy} onClick={() => void perform(session, undefined, true)}>Revoke context connection</button>
      </section>)}
    </>}
    <SettingsSaveProofModal open={confirm !== null} mode="verify-save" gate={gate} title="Authorize AI app context"
      detail={`Grant connection ${confirm?.session_id ?? ""} access to ${confirmationScope ? `${harnessDisplayName(confirmationScope.app)} sources in ${confirmationScope.workspace}` : "the selected sources"} for this runtime session.${confirmationScope?.sharing?.mode === "shared_broker" ? ` Five-minute lease. Reviewed shared notes: ${confirmationScope.sharing.notes.read ? "allowed" : "not granted"}. Note proposals: ${confirmationScope.sharing.notes.propose ? "allowed, subject to your separate review" : "not granted"}.` : ""} This grants no command approval.`}
      confirmLabel="Authorize connection" pending={busy} error={error} onCancel={() => { if (!busy) setConfirm(null); }}
      onConfirm={(credentials) => { if (confirm) void perform(confirm, credentials); }} />
  </section>;
}
