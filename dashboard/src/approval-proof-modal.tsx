import { useCallback, useState } from "react";
import type { ChangeEvent } from "react";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { ApprovalProofFieldInputs, buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

type ApprovalProofModalProps = {
  title: string;
  detail: string;
  confirmLabel: string;
  approvalGate: GuardApprovalGatePublicConfig | null;
  busy?: boolean;
  error?: string | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
};

export function ApprovalProofModal(props: ApprovalProofModalProps) {
  const { title, detail, confirmLabel, approvalGate, busy = false, error = null, onCancel, onConfirm } = props;
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");

  const handlePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);

  const handleTotpChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotpCode(event.target.value);
  }, []);

  const handleConfirm = useCallback(() => {
    onConfirm(buildApprovalProofCredentials(approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }));
  }, [approvalGate, onConfirm, password, totpCode]);

  const confirmDisabled = isApprovalProofSubmitDisabled(
    approvalGate,
    { approvalPassword: password, approvalTotpCode: totpCode },
    busy,
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/30 px-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="approval-proof-modal-title"
        className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl"
      >
        <SectionLabel>Approval required</SectionLabel>
        <h2 id="approval-proof-modal-title" className="mt-2 text-base font-semibold text-brand-dark">{title}</h2>
        <p className="mt-1 text-sm text-slate-500">{detail}</p>
        <div className="mt-4">
          <ApprovalProofFieldInputs
            approvalGate={approvalGate}
            approvalPassword={password}
            approvalTotpCode={totpCode}
            onApprovalPasswordChange={handlePasswordChange}
            onApprovalTotpCodeChange={handleTotpChange}
          />
        </div>
        {error ? (
          <p role="alert" className="mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.06] px-3 py-2 text-sm text-brand-attention">
            {error}
          </p>
        ) : null}
        <div className="mt-5 flex justify-end gap-2">
          <ActionButton variant="outline" onClick={onCancel} disabled={busy}>
            Cancel
          </ActionButton>
          <ActionButton onClick={handleConfirm} disabled={confirmDisabled}>
            {busy ? "Repairing…" : confirmLabel}
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
