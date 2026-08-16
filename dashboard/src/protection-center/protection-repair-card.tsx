import { useState } from "react";
import { HiMiniWrenchScrewdriver } from "react-icons/hi2";

import { ApprovalProofModal } from "../approval-proof-modal";
import { recoverExtensionControlAuthority, type EffectiveExtensionControls } from "../extension-controls-api";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";

export function ProtectionRepairCard(props: { effective: EffectiveExtensionControls; onRefresh: () => Promise<void> | void }) {
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required";
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  if (!repairable) return null;
  const begin = async () => {
    try { await resolveApprovalGate({ failClosed: true }); setError(null); setOpen(true); }
    catch { setError("Guard could not load the local approval gate. Repair was not started."); }
  };
  const repair = async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
    setBusy(true); setError(null);
    try { await recoverExtensionControlAuthority(credentials); setOpen(false); await props.onRefresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Guard could not repair settings integrity."); }
    finally { setBusy(false); }
  };
  return <section aria-labelledby="protection-repair-heading" className="guard-extensions-panel guard-extensions-tone-attention mt-5 p-5 sm:p-6"><div className="flex items-start gap-3"><HiMiniWrenchScrewdriver className="mt-0.5 size-5 shrink-0 text-amber-800" aria-hidden="true" /><div><h2 id="protection-repair-heading" className="font-semibold text-amber-950">Repair protection settings integrity</h2><p className="mt-1 text-sm leading-6 text-amber-900">Guard is staying fail-safe because the authenticated local settings state cannot be trusted. Repair rebuilds a protected local authority after explicit approval. Organization policy is not weakened.</p><button type="button" onClick={() => { void begin(); }} className="mt-4 min-h-11 rounded-xl bg-amber-900 px-4 text-sm font-semibold text-white">Repair safely</button>{error && !open ? <p role="alert" className="mt-3 text-sm text-red-800">{error}</p> : null}</div></div>{open ? <ApprovalProofModal title="Repair protection settings" detail="Authenticate this local recovery. Guard will rebuild settings integrity fail-safe and then reload the current protected state." confirmLabel="Repair settings" approvalGate={resolvedApprovalGate} busy={busy} error={error} onCancel={() => { if (!busy) setOpen(false); }} onConfirm={(credentials) => { void repair(credentials); }} /> : null}</section>;
}
