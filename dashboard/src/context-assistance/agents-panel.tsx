import { useCallback, useEffect, useId, useRef, useState } from "react";
import { HiMiniArrowPath, HiMiniLink } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import { SelectMenu } from "../select-menu";
import { versionHeading, versionLead, versionPrimary, versionQuiet } from "./versions-view";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { ContextAssistanceApiError } from "./api";
import { authorizeContextAgentSession, grantContextWorkspace, listContextAgentSessions, revokeContextAgentSession,
  type ContextAgentSession, type ContextWorkspaceScope } from "./workspaces-api";

const empty = "rounded-2xl border border-dashed border-brand-dark/15 px-5 py-6 text-center text-sm text-brand-dark/70";
const label = "text-sm font-medium text-brand-dark";
/** Apps Guard protects. A connection does not say which app it is, so the person names it. */
export const CONNECTABLE_APPS = ["cursor", "codex", "claude-code", "copilot", "gemini", "opencode", "cline", "kimi", "hermes",
  "openclaw", "antigravity", "zcode", "devin", "muse", "paseo", "pi", "omp"] as const;
const folderName = (path: string) => path.split(/[\\/]/).filter(Boolean).pop() ?? path;

type Choice = { workspace?: string; app?: string; read: boolean; propose: boolean };
type Props = {
  ready: boolean; enabled: boolean; dirty: boolean; generation: string | null; scopes: ContextWorkspaceScope[];
  gate: GuardApprovalGatePublicConfig | null; sharingAllowed?: boolean;
  /** A project connected to one app for the first time becomes its own entry in the list. */
  onGranted?: (scope: ContextWorkspaceScope) => void;
};

/** The project's entry for one app, if it already has one. */
export function appScope(scopes: ContextWorkspaceScope[], workspace: string, app: string) {
  return scopes.find((scope) => !scope.revoked && scope.workspace === workspace && scope.app === app);
}

/** The files the person already picked for a project, so a connected app reads the same ones. */
export function pickedFiles(scopes: ContextWorkspaceScope[], workspace: string): string[] {
  const own = scopes.filter((scope) => !scope.revoked && scope.workspace === workspace);
  const picked = own.find((scope) => scope.app === "dashboard") ?? own[0];
  return picked ? picked.sources.map((source) => source.path) : [];
}

export function ContextAgentsPanel({ ready, enabled, dirty, generation, scopes, gate, sharingAllowed = false, onGranted }: Props) {
  const [sessions, setSessions] = useState<ContextAgentSession[]>([]);
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const [confirm, setConfirm] = useState<ContextAgentSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const revision = useRef(0);
  const request = useRef<AbortController | null>(null);
  const pending = useRef(false);
  const allowed = ready && enabled;
  const idBase = useId();
  const projects = [...new Set(scopes.filter((scope) => !scope.revoked).map((scope) => scope.workspace))];
  const projectOptions = projects.map((workspace) => ({ value: workspace, label: folderName(workspace), description: workspace }));
  const appOptions = CONNECTABLE_APPS.map((app) => ({ value: app, label: harnessDisplayName(app) }));
  const choice = (session: ContextAgentSession): Choice => choices[session.session_id] ?? { read: false, propose: false };
  const choose = (session: ContextAgentSession, change: Partial<Choice>) =>
    setChoices((values) => ({ ...values, [session.session_id]: { ...choice(session), ...change } }));

  const refresh = useCallback(async () => {
    if (!allowed || pending.current) return;
    const id = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    try {
      const values = await listContextAgentSessions(controller.signal);
      if (revision.current === id) { setSessions(values); setStatusError(null); }
    } catch {
      if (revision.current === id) { setSessions([]); setStatusError("Guard could not check for apps waiting to connect. Refresh to try again."); }
    }
  }, [allowed]);

  useEffect(() => {
    setSessions([]); setChoices({}); setConfirm(null); setError(null); setStatusError(null); setBusy(false);
    void refresh();
    const timer = allowed ? window.setInterval(() => { if (!document.hidden) void refresh(); }, 3_000) : null;
    return () => { revision.current += 1; request.current?.abort(); if (timer !== null) window.clearInterval(timer); };
  }, [allowed, generation, refresh]);

  async function perform(session: ContextAgentSession, credentials?: SettingsSaveProofCredentials, revoke = false) {
    if (pending.current) return;
    const { workspace, app, read, propose } = choice(session);
    if (!revoke && (dirty || !workspace || !app)) return;
    pending.current = true;
    const id = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(null);
    try {
      if (revoke) await revokeContextAgentSession(session.session_id, controller.signal);
      else {
        let scope = appScope(scopes, workspace!, app!);
        let proof = credentials;
        if (!scope) {
          scope = await grantContextWorkspace(workspace!, pickedFiles(scopes, workspace!), credentials, controller.signal, app,
            sharingAllowed ? { read, propose: read && propose } : undefined);
          onGranted?.(scope);
          // An authenticator code works once; Guard accepts the password again for the next step.
          proof = credentials?.currentPassword ? { currentPassword: credentials.currentPassword } : credentials;
        }
        await authorizeContextAgentSession(session.session_id, scope.scope_id, proof, controller.signal);
      }
      if (revision.current === id) setConfirm(null);
    } catch (failure) {
      if (revision.current === id) setError(failure instanceof ContextAssistanceApiError ? failure.message
        : "Guard did not confirm that change. Refresh, then try again.");
    } finally {
      pending.current = false;
      if (revision.current === id) { setBusy(false); void refresh(); }
    }
  }

  const asked = confirm ? choice(confirm) : null;
  return <section aria-label="Connect another app" className="space-y-4">
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
      <div><h3 className={versionHeading}>Connect another app</h3>
        <p className={versionLead}>Claude Code, Codex, Pi and Oh My Pi need nothing here. Other apps, like Cursor, can ask CIGAR for files through Guard's tool server (MCP). When one asks, it shows up here with a short code. Check it matches the code your app shows, then choose the project.</p></div>
      {allowed ? <button className={versionQuiet} type="button" disabled={busy} onClick={() => { setError(null); void refresh(); }}><HiMiniArrowPath aria-hidden="true" className="size-4" />Check for apps</button> : null}
    </div>
    {!allowed ? <p className={empty}>Turn on CIGAR and let it read project files to connect other apps.</p> : <>
      {error || statusError ? <p role="alert" className="cigar-note">{error ?? statusError}</p> : null}
      {sessions.length === 0 ? <p className={empty}>No app is asking to connect right now.</p> : <ul className="space-y-3">{sessions.map((session) => {
        const current = choice(session);
        const connected = scopes.find((scope) => scope.scope_id === session.scope_id);
        return <li key={session.session_id}><section aria-label={`App connection ${session.session_id}`}
          className={"space-y-3 rounded-2xl border p-4 sm:p-5 " + (session.phase === "pending" ? "border-brand-blue/25 bg-brand-blue/[0.03]" : "border-brand-dark/10 bg-white")}>
          <div className="flex flex-wrap items-center gap-2">
            <span aria-hidden="true" className="flex size-9 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue"><HiMiniLink className="size-4" /></span>
            <Tag tone={session.phase === "pending" ? "attention" : "green"}>{session.phase === "pending" ? "Asking to connect" : "Connected"}</Tag>
            <span className="text-xs text-brand-dark/60">ends in {Math.ceil(session.expires_in_seconds / 60)} minutes</span>
          </div>
          <p className="break-all text-sm text-brand-dark/75">Code: <span className="font-mono font-semibold text-brand-dark">{session.session_id}</span></p>
          {session.phase === "pending" ? <>
            {projects.length === 0 ? <p className="text-sm text-brand-dark/70">Add a project above first, then connect it here.</p> : <div className="grid gap-3 sm:grid-cols-2">
              <div><span id={`${idBase}-${session.session_id}-app`} className={label}>Which app is this?</span>
                <SelectMenu labelledBy={`${idBase}-${session.session_id}-app`} className="mt-1.5 w-full" disabled={busy || dirty} placeholder="Choose the app"
                  value={current.app ?? ""} options={appOptions} onChange={(app) => choose(session, { app })} /></div>
              <div><span id={`${idBase}-${session.session_id}-project`} className={label}>Which project?</span>
                <SelectMenu labelledBy={`${idBase}-${session.session_id}-project`} className="mt-1.5 w-full" disabled={busy || dirty} placeholder="Choose a project"
                  value={current.workspace ?? ""} options={projectOptions} onChange={(workspace) => choose(session, { workspace })} /></div>
            </div>}
            {sharingAllowed && projects.length ? <div className="space-y-0.5 rounded-xl bg-surface-1/70 px-3 py-1.5 text-sm text-brand-dark/80">
              <label className="flex min-h-11 cursor-pointer items-center gap-3"><input type="checkbox" className="size-4 accent-brand-blue" checked={current.read} disabled={busy || dirty}
                onChange={(event) => choose(session, { read: event.target.checked, propose: event.target.checked && current.propose })} />Let it read shared notes you approved</label>
              <label className="flex min-h-11 cursor-pointer items-center gap-3"><input type="checkbox" className="size-4 accent-brand-blue" checked={current.propose} disabled={busy || dirty || !current.read}
                onChange={(event) => choose(session, { propose: event.target.checked })} />Let it suggest new notes for you to review</label>
            </div> : null}
            <button className={versionPrimary} type="button" disabled={busy || dirty || !current.app || !current.workspace}
              onClick={() => { if (gate?.enabled) setConfirm(session); else void perform(session); }}>Connect</button>
          </> : <p className="break-all text-sm text-brand-dark/75">{connected ? `${harnessDisplayName(connected.app)} · ${folderName(connected.workspace)}` : "This project is gone. Disconnect, then connect the app again."}</p>}
          <button className={versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800"} type="button" disabled={busy} onClick={() => void perform(session, undefined, true)}>
            {session.phase === "pending" ? "Turn down" : "Disconnect"}</button>
        </section></li>;
      })}</ul>}
    </>}
    <SettingsSaveProofModal open={confirm !== null} mode="verify-save" gate={gate} title="Connect this app"
      detail={asked?.app && asked.workspace ? `${harnessDisplayName(asked.app)} (code ${confirm?.session_id ?? ""}) can ask CIGAR for files in ${folderName(asked.workspace)} for the next few minutes.${sharingAllowed ? ` Shared notes: ${asked.read ? "it can read the ones you approved" : "off"}${asked.read && asked.propose ? ", and it can suggest new ones for you to review" : ""}.` : ""} This does not approve any command.` : ""}
      confirmLabel="Connect" pending={busy} error={error} onCancel={() => { if (!busy) setConfirm(null); }}
      onConfirm={(credentials) => { if (confirm) void perform(confirm, credentials); }} />
  </section>;
}
