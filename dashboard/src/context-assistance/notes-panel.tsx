import { useEffect, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { clearContextNotes, decideContextProposal, listContextProposals, loadContextProposal,
  type ContextProposal, type ContextProposalDetail } from "./proposals-api";
import type { ContextWorkspaceScope } from "./workspaces-api";

const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
type Props = { scope: ContextWorkspaceScope; disabled: boolean; gate: GuardApprovalGatePublicConfig | null; onChanged: () => void };

export function ContextNotesPanel({ scope, disabled, gate, onChanged }: Props) {
  const [proposals, setProposals] = useState<ContextProposal[]>([]);
  const [detail, setDetail] = useState<ContextProposalDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofOpen, setProofOpen] = useState(false);
  const request = useRef<AbortController | null>(null);
  const revision = useRef(0);
  const identity = JSON.stringify([scope.scope_id, scope.policy_revision, scope.sources, scope.sharing?.notes.revision]);

  useEffect(() => {
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setProposals([]); setDetail(null); setError(null); setBusy(false); setProofOpen(false);
    void listContextProposals(scope.scope_id, controller.signal).then((values) => {
      if (current === revision.current) setProposals(values);
    }).catch((cause) => {
      if (current === revision.current && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Shared notes are unavailable.");
    });
    return () => { revision.current += 1; controller.abort(); };
  }, [identity, scope.scope_id]);

  async function perform(operation: (signal: AbortSignal) => Promise<void>) {
    if (busy || disabled) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setBusy(true); setError(null);
    try { await operation(controller.signal); }
    catch (cause) {
      if (current === revision.current && !controller.signal.aborted) {
        setDetail(null); setProofOpen(false);
        setError(`${cause instanceof Error ? cause.message : "No confirmed result was returned."} Refresh proposals to check the recorded outcome before taking another action.`);
      }
    } finally { if (current === revision.current) setBusy(false); }
  }
  function refresh() {
    setDetail(null); setProofOpen(false);
    void perform(async (signal) => { const values = await listContextProposals(scope.scope_id, signal); if (!signal.aborted) setProposals(values); });
  }
  async function decide(admit: boolean, credentials?: SettingsSaveProofCredentials) {
    if (!detail || detail.state !== "pending" || (admit && !admittable)) return;
    const id = detail.proposal_id;
    await perform(async (signal) => {
      await decideContextProposal(scope.scope_id, id, admit, credentials, signal);
      if (signal.aborted) return;
      setProofOpen(false); setDetail(null);
      const values = await listContextProposals(scope.scope_id, signal);
      if (!signal.aborted) { setProposals(values); onChanged(); }
    });
  }
  const admittable = detail?.source_access === "available" && detail.current_documents !== null
    && detail.source_states.every((source) => source.state === "unchanged");
  const previous = new Map(detail?.current_documents?.map((document) => [document.id, document.text]));
  const changed = detail?.documents?.filter((document) => previous.get(document.id) !== document.text) ?? [];
  const removed = detail?.current_documents?.filter((document) => !detail.documents?.some((item) => item.id === document.id)) ?? [];

  return <section aria-label="Reviewed shared notes" className="space-y-3 rounded-lg border border-slate-200 p-3" aria-busy={busy}>
    <h5 className="text-sm font-semibold text-brand-dark">Reviewed shared notes</h5>
    <p className="text-sm text-slate-600">{scope.sharing?.notes.documents ?? 0} admitted notes. AI proposals remain quarantined until you admit them here. Shared notes are supporting data and grant no command approval.</p>
    <p className="text-xs text-slate-500">Connections expire after five minutes. Notes stay in memory for the configured retention period and are cleared when their source basis changes, access ends, or assistance stops.</p>
    {error ? <p role="alert" className="text-sm text-red-700">{error}</p> : null}
    <div className="flex flex-wrap gap-2">
      <button type="button" className={button} disabled={busy || disabled} onClick={refresh}>Refresh proposals</button>
      <button type="button" className={button} disabled={busy || disabled} onClick={() => void perform(async (signal) => {
        await clearContextNotes(scope.scope_id, signal);
        if (!signal.aborted) { setDetail(null); setProposals([]); onChanged(); }
      })}>Clear shared notes and proposals</button>
    </div>
    {proposals.length === 0 ? <p className="text-sm text-slate-600">No retained proposals. Text loads only when you open a proposal.</p> : <ul className="space-y-2">
      {proposals.map((proposal) => <li key={proposal.proposal_id} className="space-y-1 text-sm">
        <p className="break-all">{proposal.connection_id ?? "Expired connection"} · {proposal.state} · {proposal.documents} documents · {proposal.bytes} bytes</p>
        <button type="button" className={button} disabled={busy || disabled} onClick={() => void perform(async (signal) => {
          const value = await loadContextProposal(scope.scope_id, proposal.proposal_id, signal);
          if (!signal.aborted) setDetail(value);
        })}>Review {proposal.proposal_id}</button>
      </li>)}
    </ul>}
    {detail ? <section aria-label="Shared note proposal" className="space-y-3 border-t border-slate-200 pt-3">
      <h6 className="break-all text-sm font-semibold">Proposal {detail.proposal_id} · {detail.state}</h6>
      {detail.source_access === "unavailable" ? <p role="status" className="text-sm text-amber-800">A required source cannot be read safely. Proposal text is withheld.</p> : <>
        {detail.current_documents === null ? <p role="status" className="text-sm text-amber-800">Shared notes changed since this proposal was prepared. Inspect its text, then reject it or ask the connection to prepare a new proposal.</p> : null}
        <p className="text-sm font-semibold">Proposed changes</p>
        {changed.length === 0 ? <p className="text-sm text-slate-600">No added or changed note text.</p> : changed.map((document) => <div key={document.id} className="space-y-2 text-sm">
          {previous.has(document.id) ? <p className="whitespace-pre-wrap break-words text-slate-500">Earlier: {previous.get(document.id)}</p> : null}
          <p className="whitespace-pre-wrap break-words text-slate-700">{document.text}</p>
        </div>)}
        {removed.map((document) => <p key={document.id} className="whitespace-pre-wrap break-words text-sm text-slate-500">Removed: {document.text}</p>)}
        <details><summary className="cursor-pointer text-sm font-semibold">All proposed note text</summary>
          <div className="max-h-64 space-y-3 overflow-auto text-sm">{detail.documents?.map((document) => <p key={document.id} className="whitespace-pre-wrap break-words">{document.text}</p>)}</div>
        </details>
      </>}
      <ul className="space-y-1 text-sm text-slate-600">{detail.source_states.map((source) => <li key={source.source_id} className="break-all">{source.path}: {source.state}</li>)}</ul>
      <p className="break-all text-xs text-slate-500">Basis snapshot: {detail.basis_snapshot}. Expected notes revision: {detail.expected.version}.</p>
      {detail.state === "pending" ? <div className="flex flex-wrap gap-2">
        <button type="button" className={button} disabled={busy || disabled || !admittable} onClick={() => { if (gate?.enabled) setProofOpen(true); else void decide(true); }}>Admit shared note</button>
        <button type="button" className={button} disabled={busy || disabled} onClick={() => void decide(false)}>Reject proposal</button>
        {!admittable ? <p className="text-sm text-amber-800">Admission needs unchanged, safely readable sources and the current notes revision.</p> : null}
      </div> : null}
    </section> : null}
    <SettingsSaveProofModal open={proofOpen} mode="verify-save" gate={gate} title="Confirm shared note admission"
      detail="Admit the displayed proposal as supporting evidence for this app and workspace. This grants no command approval."
      confirmLabel="Admit shared note" pending={busy} error={error} onCancel={() => { if (!busy) setProofOpen(false); }}
      onConfirm={(credentials) => void decide(true, credentials)} />
  </section>;
}
