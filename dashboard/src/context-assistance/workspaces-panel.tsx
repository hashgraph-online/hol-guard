import { useEffect, useId, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { ContextAgentsPanel } from "./agents-panel";
import { ContextNotesPanel } from "./notes-panel";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { SettingsFormSection } from "../settings/settings-row-primitives";
import { compileWorkspaceContext, grantContextWorkspace, listContextWorkspaces, manageContextWorkspace,
  type ContextBrief, type ContextWorkspaceScope } from "./workspaces-api";

const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
const field = "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark";
type Props = { ready: boolean; generation: string | null; dirty: boolean; documentsAllowed: boolean; agentsAllowed: boolean; sharingAllowed?: boolean; executionAllowed?: boolean; gate: GuardApprovalGatePublicConfig | null };

export function ContextWorkspacesPanel({ ready, generation, dirty, documentsAllowed, agentsAllowed, sharingAllowed = false, executionAllowed = false, gate }: Props) {
  const [scopes, setScopes] = useState<ContextWorkspaceScope[]>([]);
  const [workspace, setWorkspace] = useState("");
  const [paths, setPaths] = useState("");
  const [app, setApp] = useState("dashboard");
  const [notesRead, setNotesRead] = useState(false);
  const [notesPropose, setNotesPropose] = useState(false);
  const [query, setQuery] = useState("");
  const [brief, setBrief] = useState<{ scope: ContextWorkspaceScope; value: ContextBrief } | null>(null);
  const [previous, setPrevious] = useState<ContextBrief | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofOpen, setProofOpen] = useState(false);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);
  const id = useId();
  useEffect(() => { if (!agentsAllowed && !executionAllowed) setApp("dashboard"); }, [agentsAllowed, executionAllowed]);

  useEffect(() => {
    const generation = ++revision.current;
    request.current?.abort();
    setScopes([]); setBrief(null); setPrevious(null); setProofOpen(false); setBusy(false); setError(null);
    if (!ready) return;
    const controller = new AbortController(); request.current = controller;
    void listContextWorkspaces(controller.signal).then((values) => {
      if (revision.current === generation) setScopes(values);
    }).catch((cause) => {
      if (revision.current === generation && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Context access is unavailable.");
    });
    return () => { revision.current += 1; controller.abort(); };
  }, [ready, generation]);

  async function perform(operation: (signal: AbortSignal) => Promise<void>) {
    if (busy || !ready) return;
    const generation = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(null);
    try {
      await operation(controller.signal);
    } catch (cause) {
      if (revision.current === generation && !controller.signal.aborted) {
        if (brief) setPrevious(brief.value);
        setBrief(null);
        setError(cause instanceof Error ? cause.message : "Context did not return a verified result.");
      }
    } finally {
      if (revision.current === generation) setBusy(false);
    }
  }

  async function grant(credentials?: SettingsSaveProofCredentials) {
    await perform(async (signal) => {
      const selected = paths.split(/\r?\n/).map((path) => path.trim()).filter(Boolean);
      const scope = await grantContextWorkspace(workspace.trim(), selected, credentials, signal, app,
        sharingAllowed && app !== "dashboard" ? { read: notesRead, propose: notesPropose } : undefined);
      if (signal.aborted) return;
      setScopes((values) => [...values, scope]); setProofOpen(false); setPaths("");
    });
  }

  function manage(action: "refresh" | "withdraw" | "revoke" | "clear", scopeId?: string, sourceId?: string) {
    void perform(async (signal) => {
      if (action === "refresh") { if (brief) setPrevious(brief.value); }
      else setPrevious(null);
      setBrief(null);
      await manageContextWorkspace(action, scopeId, sourceId, signal);
      const values = await listContextWorkspaces(signal);
      if (!signal.aborted) setScopes(values);
      if (action === "revoke" || action === "clear" || action === "withdraw") setPrevious(null);
    });
  }

  return <SettingsFormSection title="Workspace context access" description="Choose each workspace and file used for local review context. Source access ends when you turn assistance off.">
    <div className="space-y-4 py-4" aria-busy={busy}>
      {!ready ? <p className="text-sm text-slate-600">Start a verified context runtime to manage sources. Existing Guard approvals remain available.</p> : <>
        {error ? <p role="alert" className="text-sm text-red-700">{error}</p> : null}
        <p className="text-sm text-slate-600">Context uses the native Guard facts you enable and files you select. Environment files, credential stores, detected secrets and unsafe paths are excluded. Guard stores context locally using your Evidence storage preference.</p>
        <fieldset disabled={busy || dirty} className="grid gap-3">
          <legend className="text-sm font-semibold text-brand-dark">Add review sources</legend>
          <label htmlFor={`${id}-app`} className="text-sm text-slate-600">Context consumer
            <select id={`${id}-app`} className={field} value={app} onChange={(event) => setApp(event.target.value)}>
              <option value="dashboard">Guard dashboard</option>
              {agentsAllowed ? ["codex", "claude-code", "cursor"].map((name) => <option key={name} value={name}>{harnessDisplayName(name)} · paired MCP connection</option>) : null}
              {executionAllowed ? ["pi", "omp"].map((name) => <option key={name} value={name}>{harnessDisplayName(name)} · native captured-Bash executor</option>) : null}
            </select>
          </label>
          {executionAllowed ? <p className="text-sm text-slate-600">Execution associations apply to Pi and Oh My Pi through Guard's native captured-Bash executor on macOS. Granting access does not install an app adapter.</p> : null}
          {sharingAllowed && app !== "dashboard" ? <div className="space-y-2 text-sm text-slate-600">
            <label className="flex min-h-11 items-center gap-3"><input type="checkbox" checked={notesRead}
              onChange={(event) => { setNotesRead(event.target.checked); if (!event.target.checked) setNotesPropose(false); }} />Allow reviewed shared notes in this app's context</label>
            <label className="flex min-h-11 items-center gap-3"><input type="checkbox" checked={notesPropose} disabled={!notesRead}
              onChange={(event) => setNotesPropose(event.target.checked)} />Allow paired connections to propose shared notes</label>
            <p>Proposals require a current context snapshot and your separate review. Pair each connection after granting access. Connections expire after five minutes.</p>
          </div> : null}
          <label htmlFor={`${id}-workspace`} className="text-sm text-slate-600">Workspace folder
            <input id={`${id}-workspace`} className={field} value={workspace} onChange={(event) => setWorkspace(event.target.value)} placeholder="Absolute workspace path" autoComplete="off" />
          </label>
          <label htmlFor={`${id}-sources`} className="text-sm text-slate-600">Files relative to the workspace, one per line
            <textarea id={`${id}-sources`} className={field} rows={3} value={paths} onChange={(event) => setPaths(event.target.value)} placeholder={"README.md\ndocs/design.md"} disabled={!documentsAllowed} />
          </label>
          {!documentsAllowed ? <p className="text-sm text-slate-600">Enable selected workspace documents in Context assistance and save settings to add files. You can still use native Guard facts.</p> : null}
          {dirty ? <p role="status" className="text-sm text-slate-600">Save your context preferences before granting access.</p> : null}
          <button className={button} type="button" disabled={!workspace.trim() || paths.split(/\r?\n/).filter((path) => path.trim()).length > 32}
            onClick={() => { if (gate?.enabled) setProofOpen(true); else void grant(); }}>Grant review source access</button>
        </fieldset>
        <div className="flex flex-wrap gap-2">
          <button className={button} type="button" disabled={busy} onClick={() => void perform(async (signal) => { const values = await listContextWorkspaces(signal); if (!signal.aborted) setScopes(values); })}>Refresh context access</button>
          <button className={button} type="button" disabled={busy || scopes.length === 0} onClick={() => manage("clear")}>Clear all context data</button>
        </div>
        {scopes.length === 0 ? <p className="text-sm text-slate-600">No workspace has context access.</p> : <>
          <label htmlFor={`${id}-query`} className="block text-sm text-slate-600">What would you like context about?
            <input id={`${id}-query`} className={field} maxLength={4096} value={query} onChange={(event) => setQuery(event.target.value)} />
          </label>
          {scopes.map((scope) => <section key={scope.scope_id} className="space-y-3 rounded-lg border border-slate-200 p-3" aria-label={`Context access for ${scope.workspace}`}>
            <p className="break-all text-sm font-semibold text-brand-dark">{scope.workspace}</p>
            <p className="text-sm text-slate-600">{scope.revoked ? "Access revoked by policy. Grant access again to continue." : `${scope.app === "dashboard" ? "Review context" : harnessDisplayName(scope.app)} · local memory`}</p>
            {scope.native_policy_facts ? <p className="text-sm text-slate-600">Includes native Guard policy and decision facts.</p> : null}
            {scope.sharing?.mode === "shared_broker" ? <p className="text-sm text-slate-600">Shared context · {scope.sharing.notes.read ? "reviewed notes allowed" : "shared notes not granted"}{scope.sharing.notes.propose ? " · connection proposals allowed" : ""}. Each paired connection has a five-minute lease.</p> : null}
            {scope.receipt_window?.enabled ? <p className="text-sm text-slate-600">Recent native receipt facts: {scope.receipt_window.retained} of at most 16 retained. This window covers recorded decisions in this exact workspace, not execution confirmation or a complete activity history.</p> : null}
            {scope.receipt_window?.enabled && scope.receipt_window.dropped !== "0" ? <p role="status" className="text-sm text-amber-800">Some optional receipt updates were missed. Earlier context was invalidated; durable Guard evidence is unchanged.</p> : null}
            <ul className="space-y-2">
              {scope.sources.map((source) => <li key={source.source_id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                <span className="break-all">{source.path}</span>
                <button className={button} type="button" disabled={busy} onClick={() => manage("withdraw", scope.scope_id, source.source_id)}>Withdraw {source.path}</button>
              </li>)}
            </ul>
            <div className="flex flex-wrap gap-2">
              <button className={button} type="button" disabled={busy || dirty || scope.revoked} onClick={() => void perform(async (signal) => {
                const value = await compileWorkspaceContext(scope.scope_id, query, signal);
                if (!signal.aborted) {
                  if (brief) setPrevious(brief.value);
                  const current = value.scope ?? scope;
                  setBrief({ scope: current, value: value.brief });
                  setScopes((values) => values.map((item) => item.scope_id === current.scope_id ? current : item));
                }
              })}>Prepare cited context</button>
              <button className={button} type="button" disabled={busy || scope.revoked} onClick={() => manage("refresh", scope.scope_id)}>Refresh selected files</button>
              <button className={button} type="button" disabled={busy} onClick={() => manage("revoke", scope.scope_id)}>Revoke workspace access</button>
            </div>
            {!scope.revoked && scope.sharing?.mode === "shared_broker" && scope.sharing.notes.read ? <ContextNotesPanel scope={scope} disabled={busy || dirty} gate={gate}
              onChanged={() => {
                setBrief(null); setPrevious(null);
                void perform(async (signal) => { const values = await listContextWorkspaces(signal); if (!signal.aborted) setScopes(values); });
              }} /> : null}
          </section>)}
        </>}
        {brief ? <section aria-label="Prepared context" className="space-y-3 rounded-lg border border-slate-200 p-3">
          <h4 className="text-sm font-semibold text-brand-dark">Cited context</h4>
          <p className="text-sm text-slate-600">Supporting data verified when prepared. Use a fresh context after files or access change. {brief.value.rendered_tokens} tokens.</p>
          <div className="max-h-96 space-y-3 overflow-auto text-sm text-slate-700">
            {brief.value.excerpts.map((excerpt, index) => <p key={index} className="whitespace-pre-wrap break-words">{excerpt.text}</p>)}
          </div>
          <details><summary className="cursor-pointer text-sm font-semibold">Sources and revisions</summary>
            <ul className="mt-2 space-y-2 text-sm">{brief.value.citations.map((citation, index) => <li key={`${citation.node_id}-${index}`}>
              {brief.scope.sources.find((source) => source.source_id === citation.source)?.path ?? (citation.source === "guard:notes" ? "Reviewed shared notes" : citation.source === "guard:receipts" ? "Native Guard receipt facts" : "Native Guard policy facts")}, lines {citation.start_line}–{citation.end_line}
              <span className="block break-all text-xs text-slate-500">{citation.document_digest}</span>
            </li>)}</ul>
          </details>
          {previous ? <details><summary className="cursor-pointer text-sm font-semibold">Compare with earlier context</summary>
            <p className="my-2 text-sm text-slate-600">Earlier context is historical and may no longer apply.</p>
            <div className="max-h-64 space-y-3 overflow-auto text-sm">
              {previous.excerpts.map((excerpt, index) => <p key={index} className="whitespace-pre-wrap break-words">{excerpt.text}</p>)}
            </div>
          </details> : null}
        </section> : null}
      </>}
    </div>
    <ContextAgentsPanel ready={ready} enabled={agentsAllowed} dirty={dirty} generation={generation} scopes={scopes} gate={gate} />
    <SettingsSaveProofModal open={proofOpen} mode="verify-save" gate={gate} title="Confirm source access"
      detail={`Grant ${app === "dashboard" ? "Guard dashboard" : harnessDisplayName(app)} context access for ${workspace.trim()}. Allow the enabled native Guard facts and ${paths.split(/\r?\n/).filter((path) => path.trim()).length} selected workspace files.${executionAllowed && (app === "pi" || app === "omp") ? " Execution associations use native capture facts. This does not approve commands or install an app adapter." : ""}${sharingAllowed && app !== "dashboard" ? ` Reviewed shared notes: ${notesRead ? "allowed" : "not granted"}. Connection note proposals: ${notesPropose ? "allowed, subject to your separate review" : "not granted"}.` : ""}`} confirmLabel="Grant source access"
      error={error} pending={busy} onCancel={() => { if (!busy) setProofOpen(false); }} onConfirm={(credentials) => void grant(credentials)} />
  </SettingsFormSection>;
}
