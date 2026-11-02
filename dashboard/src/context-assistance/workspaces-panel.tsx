import { useEffect, useId, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { ContextAgentsPanel } from "./agents-panel";
import { ContextNotesPanel } from "./notes-panel";
import type { SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { AddProjectPanel, type AddProjectInput } from "./add-project-panel";
import { HiMiniArrowPath, HiMiniChevronRight, HiMiniDocumentText, HiMiniFolder, HiMiniFolderOpen } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import { versionButton, versionField, versionHeading, versionLead, versionPrimary, versionQuiet } from "./versions-view";
import { compileWorkspaceContext, grantContextWorkspace, listContextWorkspaces, manageContextWorkspace,
  type ContextBrief, type ContextWorkspaceScope } from "./workspaces-api";

const fieldLabel = "text-sm font-medium text-brand-dark";
const empty = "rounded-2xl border border-dashed border-brand-dark/15 px-5 py-8 text-center text-sm text-brand-dark/70";
const summary = "inline-flex min-h-11 cursor-pointer list-none items-center gap-1.5 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark [&::-webkit-details-marker]:hidden";
type Props = { ready: boolean; generation: string | null; dirty: boolean; documentsAllowed: boolean; agentsAllowed: boolean; sharingAllowed?: boolean; executionAllowed?: boolean; gate: GuardApprovalGatePublicConfig | null };

export function ContextWorkspacesPanel({ ready, generation, dirty, documentsAllowed, agentsAllowed, sharingAllowed = false, executionAllowed = false, gate }: Props) {
  const [scopes, setScopes] = useState<ContextWorkspaceScope[]>([]);
  const [query, setQuery] = useState("");
  const [brief, setBrief] = useState<{ scope: ContextWorkspaceScope; value: ContextBrief } | null>(null);
  const [previous, setPrevious] = useState<ContextBrief | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);
  const id = useId();

  useEffect(() => {
    const generation = ++revision.current;
    request.current?.abort();
    setScopes([]); setBrief(null); setPrevious(null); setBusy(false); setError(null);
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

  async function grant(input: AddProjectInput, credentials?: SettingsSaveProofCredentials): Promise<boolean> {
    let granted = false;
    await perform(async (signal) => {
      const scope = await grantContextWorkspace(input.workspace, input.files, credentials, signal, input.app, input.notes);
      if (signal.aborted) return;
      setScopes((values) => [...values, scope]); granted = true;
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
    });
  }

  const refreshScopes = () => void perform(async (signal) => { const values = await listContextWorkspaces(signal); if (!signal.aborted) setScopes(values); });
  return <div className="space-y-8">
    <section className="space-y-4" aria-labelledby={`${id}-projects`} aria-busy={busy}>
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2">
        <div><h3 id={`${id}-projects`} className={versionHeading}>Your projects</h3>
          <p className={versionLead}>Folders CIGAR may read. Access ends when you turn CIGAR off.</p></div>
        {ready ? <div className="flex flex-wrap gap-2">
          <button className={versionQuiet} type="button" disabled={busy} onClick={refreshScopes}><HiMiniArrowPath aria-hidden="true" className="size-4" />Refresh context access</button>
          <button className={versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800"} type="button" disabled={busy || scopes.length === 0} onClick={() => manage("clear")}>Clear all context data</button>
        </div> : null}
      </div>
      {!ready ? <p className={empty}>Start a verified context runtime to manage sources. Existing Guard approvals remain available.</p> : <>
        {error ? <p role="alert" className="cigar-note">{error}</p> : null}
        {scopes.length === 0 ? <div className={empty}><HiMiniFolderOpen aria-hidden="true" className="mx-auto mb-2 size-6 text-brand-dark/35" /><p>No projects yet.</p><p className="mt-1 text-xs text-brand-dark/55">Choose a folder below to get started.</p></div> : <>
          <div><label htmlFor={`${id}-query`} className={fieldLabel}>What would you like context about?</label>
            <input id={`${id}-query`} className={versionField} maxLength={4096} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="For example: how releases are reviewed" /></div>
          <ul className="space-y-3">{scopes.map((scope) => <li key={scope.scope_id}><section className={"space-y-3 rounded-2xl border p-4 sm:p-5 " + (scope.revoked ? "border-amber-300/70 bg-amber-50/40" : "border-brand-dark/10 bg-white")} aria-label={`Context access for ${scope.workspace}`}>
            <div className="flex flex-wrap items-start gap-3">
              <span aria-hidden="true" className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue"><HiMiniFolder className="size-4" /></span>
              <div className="min-w-0 flex-1 space-y-1.5">
                <p className="break-all font-mono text-sm font-semibold text-brand-dark">{scope.workspace}</p>
                <div className="flex flex-wrap gap-1.5">
                  {scope.revoked ? <Tag tone="amber">Access revoked</Tag> : <Tag tone="blue">{scope.app === "dashboard" ? "Review context" : harnessDisplayName(scope.app)}</Tag>}
                  {!scope.revoked ? <Tag tone="slate">local memory</Tag> : null}
                  {scope.native_policy_facts ? <Tag tone="slate">Guard policy facts</Tag> : null}
                  {scope.sharing?.mode === "shared_broker" ? <Tag tone="green">Shared context</Tag> : null}
                </div>
              </div>
            </div>
            <div className="space-y-1 text-sm leading-6 text-brand-dark/70">
              {scope.revoked ? <p>Access revoked by policy. Grant access again to continue.</p> : null}
              {scope.sharing?.mode === "shared_broker" ? <p>Shared context · {scope.sharing.notes.read ? "reviewed notes allowed" : "shared notes not granted"}{scope.sharing.notes.propose ? " · connection proposals allowed" : ""}. Each paired connection has a five-minute lease.</p> : null}
              {scope.receipt_window?.enabled ? <p>Recent native receipt facts: {scope.receipt_window.retained} of at most 16 retained. This window covers recorded decisions in this exact workspace, not execution confirmation or a complete activity history.</p> : null}
              {scope.receipt_window?.enabled && scope.receipt_window.dropped !== "0" ? <p role="status" className="text-amber-800">Some optional receipt updates were missed. Earlier context was invalidated; durable Guard evidence is unchanged.</p> : null}
            </div>
            {scope.sources.length ? <ul className="divide-y divide-brand-dark/[0.07] rounded-xl border border-brand-dark/[0.08]">
              {scope.sources.map((source) => <li key={source.source_id} className="flex flex-wrap items-center justify-between gap-2 py-1 pl-3 pr-1 text-sm">
                <span className="flex min-w-0 items-center gap-2 break-all font-mono text-xs text-brand-dark/80"><HiMiniDocumentText aria-hidden="true" className="size-4 shrink-0 text-brand-dark/40" />{source.path}</span>
                <button className={versionQuiet + " min-h-9 px-2.5 text-xs"} type="button" disabled={busy} onClick={() => manage("withdraw", scope.scope_id, source.source_id)}>Withdraw {source.path}</button>
              </li>)}
            </ul> : null}
            <div className="flex flex-wrap gap-2">
              <button className={versionPrimary} type="button" disabled={busy || dirty || scope.revoked} onClick={() => void perform(async (signal) => {
                const value = await compileWorkspaceContext(scope.scope_id, query, signal);
                if (!signal.aborted) {
                  if (brief) setPrevious(brief.value);
                  const current = value.scope ?? scope;
                  setBrief({ scope: current, value: value.brief });
                  setScopes((values) => values.map((item) => item.scope_id === current.scope_id ? current : item));
                }
              })}>Prepare cited context</button>
              <button className={versionButton} type="button" disabled={busy || scope.revoked} onClick={() => manage("refresh", scope.scope_id)}>Refresh selected files</button>
              <button className={versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800"} type="button" disabled={busy} onClick={() => manage("revoke", scope.scope_id)}>Revoke workspace access</button>
            </div>
            {!scope.revoked && scope.sharing?.mode === "shared_broker" && scope.sharing.notes.read ? <ContextNotesPanel scope={scope} disabled={busy || dirty} gate={gate}
              onChanged={() => { setBrief(null); setPrevious(null); refreshScopes(); }} /> : null}
          </section></li>)}</ul>
        </>}
        {brief ? <section aria-label="Prepared context" className="guard-surface-in space-y-3 rounded-2xl border border-brand-blue/20 bg-brand-blue/[0.03] p-4 sm:p-5">
          <div className="flex flex-wrap items-center gap-2"><h4 className="text-sm font-semibold text-brand-dark">Cited context</h4><Tag tone="slate">{brief.value.rendered_tokens} tokens</Tag></div>
          <p className="text-sm text-brand-dark/70">Supporting data verified when prepared. Use a fresh context after files or access change.</p>
          <div className="max-h-96 space-y-3 overflow-auto rounded-xl bg-white p-3 text-sm leading-6 text-slate-700">
            {brief.value.excerpts.map((excerpt, index) => <p key={index} className="whitespace-pre-wrap break-words">{excerpt.text}</p>)}
          </div>
          <details className="group"><summary className={summary}><HiMiniChevronRight aria-hidden="true" className="size-4 transition-transform group-open:rotate-90 motion-reduce:transition-none" />Sources and revisions</summary>
            <ul className="mt-2 space-y-2 pl-5 text-sm">{brief.value.citations.map((citation, index) => <li key={`${citation.node_id}-${index}`}>
              {brief.scope.sources.find((source) => source.source_id === citation.source)?.path ?? (citation.source === "guard:notes" ? "Reviewed shared notes" : citation.source === "guard:receipts" ? "Native Guard receipt facts" : "Native Guard policy facts")}, lines {citation.start_line}–{citation.end_line}
              <span className="block break-all font-mono text-xs text-slate-500">{citation.document_digest}</span>
            </li>)}</ul>
          </details>
          {previous ? <details className="group/prev"><summary className={summary}><HiMiniChevronRight aria-hidden="true" className="size-4 transition-transform group-open/prev:rotate-90 motion-reduce:transition-none" />Compare with earlier context</summary>
            <p className="my-2 pl-5 text-sm text-slate-600">Earlier context is historical and may no longer apply.</p>
            <div className="max-h-64 space-y-3 overflow-auto pl-5 text-sm">
              {previous.excerpts.map((excerpt, index) => <p key={index} className="whitespace-pre-wrap break-words">{excerpt.text}</p>)}
            </div>
          </details> : null}
        </section> : null}
      </>}
    </section>
    {ready ? <AddProjectPanel busy={busy} dirty={dirty} documentsAllowed={documentsAllowed} agentsAllowed={agentsAllowed} sharingAllowed={sharingAllowed}
      executionAllowed={executionAllowed} gate={gate} error={error} first={scopes.length === 0}
      active={scopes.filter((scope) => !scope.revoked).map((scope) => scope.workspace)} onGrant={grant} /> : null}
    <ContextAgentsPanel ready={ready} enabled={agentsAllowed} dirty={dirty} generation={generation} scopes={scopes} gate={gate} />
  </div>;
}
