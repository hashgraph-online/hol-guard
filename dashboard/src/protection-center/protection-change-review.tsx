import { useCallback, useState } from "react";
import { HiMiniXMark } from "react-icons/hi2";

import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import type { ExtensionCatalogItem } from "../extension-controls-api";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { useModalDialog } from "../use-modal-dialog";

type ExtensionMutationTarget = Pick<ExtensionCatalogItem, "extension_id" | "name">;
export type ProtectionPendingChange = { extension: ExtensionMutationTarget; enabled: boolean } | { globalLockdown: boolean };

export function ReviewModal(props: {
  change: ProtectionPendingChange;
  busy: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change
    ? `${props.change.globalLockdown ? "Enable" : "Disable"} Emergency Lockdown`
    : `${props.change.enabled ? "Permit" : "Block"} ${props.change.extension.name}`;
  const current = "globalLockdown" in props.change
    ? props.change.globalLockdown ? "Off" : "Active"
    : props.change.enabled ? "Blocked" : "Allowed";
  const requested = "globalLockdown" in props.change
    ? props.change.globalLockdown ? "Active" : "Off"
    : props.change.enabled ? "Allowed within Guard safety rules" : "Blocked";
  const handlePassword = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setTotp(event.target.value);
  }, []);
  const handleSubmit = useCallback((event: React.FormEvent) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, props.busy);
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm">
      <form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="protection-review-title" onSubmit={handleSubmit} className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Review protection change</p>
            <h2 id="protection-review-title" className="mt-2 text-xl font-semibold text-brand-dark">{title}</h2>
          </div>
          <button type="button" disabled={props.busy} onClick={props.onCancel} aria-label="Close review" className="grid size-11 place-items-center rounded-full text-brand-dark hover:bg-white/70 disabled:opacity-50">
            <HiMiniXMark className="size-5" />
          </button>
        </div>
        <div className="mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-[rgba(85,153,254,0.08)] p-4 text-sm text-brand-dark">
          <span>Current</span><span aria-hidden="true">→</span><strong>Requested</strong>
          <span>{current}</span><span /><span>{requested}</span>
        </div>
        <p className="mt-4 text-sm leading-6 text-brand-dark">Guard's built-in minimum safety rules and organization policy remain active. This change does not disable detection.</p>
        <div className="mt-5">
          <ApprovalProofFieldInputs approvalGate={props.approvalGate} approvalPassword={password} approvalTotpCode={totp} onApprovalPasswordChange={handlePassword} onApprovalTotpCodeChange={handleTotp} />
        </div>
        {props.error ? <p role="alert" className="mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">{props.error}</p> : null}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" disabled={props.busy} onClick={props.onCancel} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark hover:bg-white/70 disabled:opacity-50">Cancel</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60">{props.busy ? "Verifying…" : "Confirm change"}</button>
        </div>
      </form>
    </div>
  );
}
