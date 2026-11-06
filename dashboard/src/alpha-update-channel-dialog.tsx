import type { ChangeEvent } from "react";
import { HiMiniXMark } from "react-icons/hi2";

import { ApprovalProofFieldInputs, isApprovalProofSubmitDisabled } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

export type AlphaChannelDialogProps = {
  useAlpha: boolean;
  pending: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  approvalPassword: string;
  approvalTotpCode: string;
  onClose: () => void;
  onConfirm: () => void;
  onApprovalPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onApprovalTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
};

export function AlphaChannelDialog({
  useAlpha,
  pending,
  error,
  approvalGate,
  approvalPassword,
  approvalTotpCode,
  onClose,
  onConfirm,
  onApprovalPasswordChange,
  onApprovalTotpCodeChange,
}: AlphaChannelDialogProps) {
  const title = useAlpha ? "Return to stable updates" : "Try alpha updates";
  const description = useAlpha
    ? "Stable updates receive the most thoroughly tested Guard releases. You can enable alpha updates again whenever you need early access."
    : "Alpha releases arrive before stable builds. They can include unfinished changes and may require a restart.";
  const confirmLabel = useAlpha ? "Use stable updates" : "Enable alpha updates";
  const confirmDisabled =
    pending ||
    (approvalGate?.enabled === true &&
      isApprovalProofSubmitDisabled(approvalGate, { approvalPassword, approvalTotpCode }, false));

  return (
    <div className="rounded-lg bg-white shadow-xl">
      <div className="flex items-start justify-between gap-4 border-b border-slate-100 px-5 py-4">
        <div>
          <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
          <p className="mt-1 text-sm leading-relaxed text-brand-dark/70">{description}</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          disabled={pending}
          aria-label="Close update channel dialog"
          className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-brand-dark/55 transition-colors hover:bg-slate-100 hover:text-brand-dark disabled:cursor-not-allowed disabled:opacity-50"
        >
          <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>
      <div className="space-y-3 px-5 py-4 text-sm leading-relaxed text-brand-dark/75">
        {!useAlpha ? (
          <p>Guard will keep stable updates until you confirm this change. This does not install an update immediately.</p>
        ) : null}
        {approvalGate?.enabled ? (
          <div className="rounded-lg border border-brand-blue/20 bg-brand-blue/[0.04] p-3">
            <p className="mb-3 text-sm font-semibold text-brand-dark">Confirm this channel change</p>
            <ApprovalProofFieldInputs
              approvalGate={approvalGate}
              approvalPassword={approvalPassword}
              approvalTotpCode={approvalTotpCode}
              onApprovalPasswordChange={onApprovalPasswordChange}
              onApprovalTotpCodeChange={onApprovalTotpCodeChange}
            />
          </div>
        ) : null}
        {error ? <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p> : null}
      </div>
      <div className="flex flex-col-reverse gap-2 border-t border-slate-100 px-5 py-4 sm:flex-row sm:justify-end">
        <button
          type="button"
          onClick={onClose}
          disabled={pending}
          className="min-h-10 rounded-lg border border-slate-200 px-4 py-2 text-sm font-semibold text-brand-dark transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onConfirm}
          disabled={confirmDisabled}
          className="min-h-10 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {pending ? "Saving…" : confirmLabel}
        </button>
      </div>
    </div>
  );
}
