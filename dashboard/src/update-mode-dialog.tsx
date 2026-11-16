import type { ChangeEvent } from "react";
import { HiMiniXMark } from "react-icons/hi2";

import { ApprovalProofFieldInputs, isApprovalProofSubmitDisabled } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig, GuardUpdateStatus } from "./guard-types";

export type UpdateModeDialogProps = {
  mode: GuardUpdateStatus["update_mode"];
  draft: GuardUpdateStatus["update_mode"];
  pending: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  approvalPassword: string;
  approvalTotpCode: string;
  onDraftChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  onClose: () => void;
  onConfirm: () => void;
  onApprovalPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onApprovalTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
};

const MODE_COPY: Record<GuardUpdateStatus["update_mode"], string> = {
  automatic: "Guard checks periodically and installs Core updates in the background.",
  ask: "Guard checks periodically and waits for you to start an available Core update.",
  off: "Guard still shows available Core updates, but never installs them in the background.",
};

export function UpdateModeDialog({
  mode,
  draft,
  pending,
  error,
  approvalGate,
  approvalPassword,
  approvalTotpCode,
  onDraftChange,
  onClose,
  onConfirm,
  onApprovalPasswordChange,
  onApprovalTotpCodeChange,
}: UpdateModeDialogProps) {
  const confirmDisabled =
    pending ||
    draft === mode ||
    (approvalGate?.enabled === true &&
      isApprovalProofSubmitDisabled(approvalGate, { approvalPassword, approvalTotpCode }, false));
  return (
    <div className="rounded-lg bg-white shadow-xl">
      <div className="flex items-start justify-between gap-4 border-b border-slate-100 px-5 py-4">
        <div>
          <h2 className="text-base font-semibold text-brand-dark">Core update preferences</h2>
          <p className="mt-1 text-sm leading-relaxed text-brand-dark/70">Choose whether Guard can install Core updates without asking.</p>
        </div>
        <button type="button" onClick={onClose} disabled={pending} aria-label="Close Core update preferences" className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-brand-dark/55 transition-colors hover:bg-slate-100 hover:text-brand-dark disabled:cursor-not-allowed disabled:opacity-50">
          <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>
      <div className="space-y-3 px-5 py-4 text-sm leading-relaxed text-brand-dark/75">
        <label className="block text-sm font-semibold text-brand-dark" htmlFor="guard-update-mode">Install behavior</label>
        <select id="guard-update-mode" value={draft} onChange={onDraftChange} disabled={pending} className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark">
          <option value="automatic">Automatic</option>
          <option value="ask">Ask first</option>
          <option value="off">Off</option>
        </select>
        <p>{MODE_COPY[draft]}</p>
        {draft !== mode ? <p>Changing this preference only saves the setting. It does not install an update immediately.</p> : null}
        {approvalGate?.enabled ? (
          <div className="rounded-lg border border-brand-blue/20 bg-brand-blue/[0.04] p-3">
            <p className="mb-3 text-sm font-semibold text-brand-dark">Confirm this preference change</p>
            <ApprovalProofFieldInputs approvalGate={approvalGate} approvalPassword={approvalPassword} approvalTotpCode={approvalTotpCode} onApprovalPasswordChange={onApprovalPasswordChange} onApprovalTotpCodeChange={onApprovalTotpCodeChange} />
          </div>
        ) : null}
        {error ? <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p> : null}
      </div>
      <div className="flex flex-col-reverse gap-2 border-t border-slate-100 px-5 py-4 sm:flex-row sm:justify-end">
        <button type="button" onClick={onClose} disabled={pending} className="min-h-10 rounded-lg border border-slate-200 px-4 py-2 text-sm font-semibold text-brand-dark transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50">Cancel</button>
        <button type="button" onClick={onConfirm} disabled={confirmDisabled} className="min-h-10 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90 disabled:cursor-not-allowed disabled:opacity-60">{pending ? "Saving…" : "Save preference"}</button>
      </div>
    </div>
  );
}
