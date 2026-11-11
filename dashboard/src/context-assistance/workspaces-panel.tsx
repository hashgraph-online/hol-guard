import { useEffect, useId, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { ContextAgentsPanel } from "./agents-panel";
import { ContextNotesPanel } from "./notes-panel";
import { setSwarmContextTarget, useSwarmContextTarget } from "./swarm-handoff";
import { SwarmContextPanel } from "./swarm-context-panel";
import type { SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { AddProjectPanel, type AddProjectInput } from "./add-project-panel";
import type { CigarAllowFiles } from "./allow-files";
import { clearRecentProjects } from "./recent-projects";
import { HiMiniArrowPath, HiMiniChevronRight, HiMiniDocumentText, HiMiniFolder, HiMiniFolderOpen } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import { versionButton, versionField, versionHeading, versionLead, versionPrimary, versionQuiet } from "./versions-view";
import { compileWorkspaceContext, grantContextWorkspace, listContextWorkspaces, manageContextWorkspace,
  type ContextBrief, type ContextWorkspaceScope } from "./workspaces-api";

const fieldLabel = "text-sm font-medium text-brand-dark";
const empty = "rounded-2xl border border-dashed border-brand-dark/15 px-5 py-8 text-center text-sm text-brand-dark/70";
const summary = "inline-flex min-h-11 cursor-pointer list-none items-center gap-1.5 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark [&::-webkit-details-marker]:hidden";
// `ready` means CIGAR is running and folders can change; `waking` lists saved folders read-only while it rests or starts.
type Props = { ready: boolean; waking?: boolean; generation: string | null; dirty: boolean; documentsAllowed: boolean; agentsAllowed: boolean; sharingAllowed?: boolean; executionAllowed?: boolean; gate: GuardApprovalGatePublicConfig | null; allowFiles?: CigarAllowFiles };

export function ContextWorkspacesPanel({ ready, waking = false, generation, dirty, documentsAllowed, agentsAllowed, sharingAllowed = false, executionAllowed = false, gate, allowFiles }: Props) {
  const target = useSwarmContextTarget();
  const [scopes, setScopes] = useState<ContextWorkspaceScope[]>([]);
  const [loaded, setLoaded] = useState(false);
  const listable = ready || waking;
  const [query, setQuery] = useState("");
  const [brief, setBrief] = useState<{ scope: ContextWorkspaceScope; value: ContextBrief } | null>(null);
  const briefPanel = useRef<HTMLElement>(null);
  const [previous, setPrevious] = useState<ContextBrief | null>(null);
  // Remounts the add panel so a cleared recent list is not shown again.
  const [cleared, setCleared] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);
  // A list that failed while CIGAR started is asked again, not shown empty.
  const failed = useRef(false);
  const id = useId();
  useEffect(() => { if (brief) { briefPanel.current?.focus({ preventScroll: true }); briefPanel.current?.scrollIntoView({ block: "start" }); } }, [brief]);

  useEffect(() => {
    const generation = ++revision.current;
    request.current?.abort();
    setBrief(null); setPrevious(null); setBusy(false); setError(null);
    if (failed.current) { failed.current = false; setLoaded(false); }
    if (!listable) { setScopes([]); setLoaded(false); return; }
    // Listed again once CIGAR is running, so a slow start still shows saved folders.
    const controller = new AbortController(); request.current = controller;
    void listContextWorkspaces(controller.signal).then((values) => {
      if (revision.current === generation) { setScopes(values); setLoaded(true); }
    }).catch((cause) => {
      if (revision.current !== generation || controller.signal.aborted) return;
      // While CIGAR starts the list is asked again once it runs; a failure then is final.
      const reason = cause instanceof Error ? cause.message : "CIGAR could not list your projects. Try again.";
      failed.current = true; setError(ready ? reason : "Your folders appear once CIGAR is running."); setLoaded(true);
    });
    return () => { revision.current += 1; controller.abort(); };
  }, [listable, ready, generation]);

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
        setError(cause instanceof Error ? cause.message : "CIGAR could not finish that. Try again.");
      }
    } finally {
      if (revision.current === generation) setBusy(false);
    }
  }

  async function grant(input: AddProjectInput, credentials?: SettingsSaveProofCredentials): Promise<boolean> {
    // Guard keeps one pick per project, so a second one would only be refused.
    if (scopes.some((scope) => scope.app === "dashboard" && scope.workspace === input.workspace)) {
      setError("This project is already added. Remove it first to pick different files.");
      return false;
    }
    let granted = false;
    await perform(async (signal) => {
      // One pick on this page counts for every app's prompts, so it is never tied to one app.
      const scope = await grantContextWorkspace(input.workspace, input.files, credentials, signal);
      if (signal.aborted) return;
      setScopes((values) => [...values, scope]); granted = true;
      if (target) setSwarmContextTarget({ ...target, workspace: scope.workspace });
    });
    return granted;
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
      if (action === "clear" && !signal.aborted) { clearRecentProjects(); setCleared((value) => value + 1); }
    });
  }

  const refreshScopes = () => void perform(async (signal) => { const values = await listContextWorkspaces(signal); if (!signal.aborted) { setScopes(values); setLoaded(true); } });
  const locked = busy || !ready;
  const targetScopes = target ? scopes.filter((scope) => !scope.revoked && scope.workspace === target.workspace) : [];
  const targetScope = targetScopes.find((scope) => scope.app === "dashboard") ?? targetScopes.find((scope) => scope.app === target?.harness);
  const orderedScopes = targetScope ? [targetScope, ...scopes.filter((scope) => scope !== targetScope)] : scopes;
  return <div className="space-y-8">
    {target ? <SwarmContextPanel target={target} ready={ready} loaded={loaded} scope={targetScope}
      filesAllowed={documentsAllowed && agentsAllowed} allowFiles={allowFiles} /> : null}
    {ready && target && loaded && !targetScope ? <AddProjectPanel key={`${cleared}:${target.id}`} busy={busy} dirty={dirty} documentsAllowed={documentsAllowed} allowFiles={allowFiles}
      executionAllowed={executionAllowed} gate={gate} error={error} first={scopes.length === 0} initialWorkspace={target.workspace}
      active={scopes.filter((scope) => !scope.revoked).map((scope) => scope.workspace)} onGrant={grant} /> : null}
    <section className="space-y-4" aria-labelledby={`${id}-projects`} aria-busy={busy}>
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
        <div><h3 id={`${id}-projects`} className={versionHeading}>Your projects</h3>
          <p className={versionLead}>Prompts about these folders use the files listed under each one, in every AI app.</p></div>
        {ready ? <div className="flex flex-wrap gap-2">
          <button className={versionQuiet} type="button" disabled={locked} onClick={refreshScopes}><HiMiniArrowPath aria-hidden="true" className="size-4" />Refresh list</button>
          {scopes.length > 0 ? <button className={versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800"} type="button" disabled={locked} onClick={() => manage("clear")}>Remove all projects</button> : null}
        </div> : null}
      </div>
      {!listable ? <p className={empty}>Turn on CIGAR to pick project folders. Folders you already picked come back when it is on.</p> : <>
        {error ? <p role="alert" className="cigar-note">{error}</p> : null}
        {!ready ? <p role="status" className="text-sm text-brand-dark/70">CIGAR is starting. You can change folders once it is running.</p> : null}
        {!loaded ? <p role="status" className={empty}>Loading your folders…</p> : scopes.length === 0 ? !error && <div className={empty}><HiMiniFolderOpen aria-hidden="true" className="mx-auto mb-2 size-6 text-brand-dark/35" /><p>No projects yet.</p><p className="mt-1 text-xs text-brand-dark/60">Add one below only if you want to pick the exact files.</p></div> : <>
          <div><label htmlFor={`${id}-query`} className={fieldLabel}>Try it: what would you ask your AI?</label>
            <input id={`${id}-query`} className={versionField} maxLength={4096} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="For example: how do releases work?" /></div>
          <ul className="space-y-3">{orderedScopes.map((scope) => <li key={scope.scope_id}><section className={"space-y-3 rounded-2xl border p-4 sm:p-5 " + (scope.revoked ? "border-amber-300/70 bg-amber-50/40" : scope === targetScope ? "border-brand-blue/30 bg-white" : "border-brand-dark/10 bg-white")} aria-label={`Project ${scope.workspace}`}>
            <div className="flex flex-wrap items-start gap-3">
              <span aria-hidden="true" className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue"><HiMiniFolder className="size-4" /></span>
              <div className="min-w-0 flex-1 space-y-1.5">
                <p className="break-all font-mono text-sm font-semibold text-brand-dark">{scope.workspace}</p>
                <div className="flex flex-wrap gap-1.5">
                  {scope.revoked ? <Tag tone="amber">Turned off by policy</Tag> : <Tag tone="blue">{scope.app === "dashboard" ? "Every app" : harnessDisplayName(scope.app)}</Tag>}
                  {scope.native_policy_facts ? <Tag tone="slate">Guard safety facts</Tag> : null}
                  {scope.sharing?.mode === "shared_broker" ? <Tag tone="green">Shared notes</Tag> : null}
                </div>
              </div>
            </div>
            <div className="space-y-1 text-sm leading-6 text-brand-dark/70">
              {scope.revoked ? <p>A policy on this computer turned this project off. Add it again once that policy allows it.</p> : null}
              {scope.sharing?.mode === "shared_broker" ? <p>Shared notes · {scope.sharing.notes.read ? "it can read notes you approved" : "it cannot read shared notes"}{scope.sharing.notes.propose ? " and suggest new ones" : ""}. A connected app stays connected for five minutes at a time.</p> : null}
              {scope.receipt_window?.enabled ? <p>Remembers Guard's last {scope.receipt_window.retained} of up to 16 decisions in this folder, so your AI can see them. It is not a full history.</p> : null}
              {scope.receipt_window?.enabled && scope.receipt_window.dropped !== "0" ? <p role="status" className="text-amber-800">Some recent Guard decisions were missed, so CIGAR started these notes fresh. Guard's own records are unchanged.</p> : null}
            </div>
            {scope.sources.length ? <ul className="divide-y divide-brand-dark/[0.07] rounded-xl border border-brand-dark/[0.08]">
              {scope.sources.map((source) => <li key={source.source_id} className="flex flex-wrap items-center justify-between gap-2 py-1 pl-3 pr-1 text-sm">
                <span className="flex min-w-0 items-center gap-2 break-all font-mono text-xs text-brand-dark/80"><HiMiniDocumentText aria-hidden="true" className="size-4 shrink-0 text-brand-dark/40" />{source.path}</span>
                <button className={versionQuiet + " min-h-9 px-2.5 text-xs"} type="button" disabled={locked} aria-label={`Stop reading ${source.path}`} onClick={() => manage("withdraw", scope.scope_id, source.source_id)}>Stop reading</button>
              </li>)}
            </ul> : null}
            <div className="flex flex-wrap gap-2">
              <button className={versionPrimary} type="button" disabled={locked || dirty || scope.revoked} onClick={() => void perform(async (signal) => {
                const value = await compileWorkspaceContext(scope.scope_id, query, signal);
                if (!signal.aborted) {
                  if (brief) setPrevious(brief.value);
                  const current = value.scope ?? scope;
                  setBrief({ scope: current, value: value.brief });
                  setScopes((values) => values.map((item) => item.scope_id === current.scope_id ? current : item));
                }
              })}>Show what your AI would get</button>
              <button className={versionButton} type="button" disabled={locked || scope.revoked} onClick={() => manage("refresh", scope.scope_id)}>Read files again</button>
              <button className={versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800"} type="button" disabled={locked} onClick={() => manage("revoke", scope.scope_id)}>Remove project</button>
            </div>
            {!scope.revoked && scope.sharing?.mode === "shared_broker" && scope.sharing.notes.read ? <ContextNotesPanel scope={scope} disabled={locked || dirty} gate={gate}
              onChanged={() => { setBrief(null); setPrevious(null); refreshScopes(); }} /> : null}
          </section></li>)}</ul>
        </>}
        {brief ? <section ref={briefPanel} tabIndex={-1} aria-label="What your AI would get" className="guard-surface-in space-y-3 rounded-2xl border border-brand-blue/20 bg-brand-blue/[0.03] p-4 sm:p-5">
          <h4 className="text-sm font-semibold text-brand-dark">What your AI would get</h4>
          <p className="text-sm text-brand-dark/70">Checked just now. Try again after you change files or projects.</p>
          <div className="max-h-96 space-y-3 overflow-auto rounded-xl bg-white p-3 text-sm leading-6 text-slate-700">
            {brief.value.excerpts.map((excerpt, index) => <p key={index} className="whitespace-pre-wrap break-words">{excerpt.text}</p>)}
          </div>
          <details className="group"><summary className={summary}><HiMiniChevronRight aria-hidden="true" className="size-4 transition-transform group-open:rotate-90 motion-reduce:transition-none" />Where each part came from</summary>
            <ul className="mt-2 space-y-2 pl-5 text-sm">{brief.value.citations.map((citation, index) => <li key={`${citation.node_id}-${index}`}>
              {brief.scope.sources.find((source) => source.source_id === citation.source)?.path ?? (citation.source === "guard:notes" ? "Reviewed shared notes" : citation.source === "guard:receipts" ? "Guard's recent decisions" : "Guard's safety facts")}, lines {citation.start_line}–{citation.end_line}
              <span className="block break-all font-mono text-xs text-slate-500">{citation.document_digest}</span>
            </li>)}</ul>
          </details>
          {previous ? <details className="group/prev"><summary className={summary}><HiMiniChevronRight aria-hidden="true" className="size-4 transition-transform group-open/prev:rotate-90 motion-reduce:transition-none" />Compare with the last try</summary>
            <p className="my-2 pl-5 text-sm text-slate-600">From before your last change, so it may be out of date.</p>
            <div className="max-h-64 space-y-3 overflow-auto pl-5 text-sm">
              {previous.excerpts.map((excerpt, index) => <p key={index} className="whitespace-pre-wrap break-words">{excerpt.text}</p>)}
            </div>
          </details> : null}
        </section> : null}
      </>}
    </section>
    {ready && !target ? <AddProjectPanel key={cleared} busy={busy} dirty={dirty} documentsAllowed={documentsAllowed} allowFiles={allowFiles}
      executionAllowed={executionAllowed} gate={gate} error={error} first={scopes.length === 0}
      active={scopes.filter((scope) => !scope.revoked).map((scope) => scope.workspace)} onGrant={grant} /> : null}
    <ContextAgentsPanel ready={ready} enabled={agentsAllowed} dirty={dirty} generation={generation} scopes={scopes} gate={gate}
      sharingAllowed={sharingAllowed} onGranted={(scope) => setScopes((values) => [...values, scope])} />
  </div>;
}
