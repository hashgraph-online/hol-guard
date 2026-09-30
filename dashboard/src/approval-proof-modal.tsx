import { useCallback, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import {
  ApprovalProofFieldInputs,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { useFocusTrap } from "./use-focus-trap";

type ApprovalProofModalProps = {
  title: string;
  detail: string;
  confirmLabel: string;
  approvalGate: GuardApprovalGatePublicConfig | null;
  busy?: boolean;
  busyLabel?: string;
  error?: string | null;
  requireFreshTotp?: boolean;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
};

export function ApprovalProofModal(props: ApprovalProofModalProps) {
  const {
    title,
    detail,
    confirmLabel,
    approvalGate,
    busy = false,
    busyLabel = "Repairing…",
    error = null,
    requireFreshTotp = false,
    onCancel,
    onConfirm,
  } = props;
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const formRef = useRef<HTMLFormElement>(null);
  useFocusTrap(true, formRef);

  const handlePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);

  const handleTotpChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotpCode(event.target.value);
  }, []);

  const confirmDisabled = isApprovalProofSubmitDisabled(
    approvalGate,
    { approvalPassword: password, approvalTotpCode: totpCode },
    busy,
    requireFreshTotp,
  );

  const handleSubmit = useCallback((event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (confirmDisabled) {
      return;
    }
    onConfirm(buildApprovalProofCredentials(
      approvalGate,
      { approvalPassword: password, approvalTotpCode: totpCode },
      requireFreshTotp,
    ));
  }, [approvalGate, confirmDisabled, onConfirm, password, requireFreshTotp, totpCode]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/30 px-4">
      <form
        ref={formRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="approval-proof-modal-title"
        aria-describedby="approval-proof-modal-detail"
        className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl"
        onSubmit={handleSubmit}
      >
        <SectionLabel>Approval required</SectionLabel>
        <h2 id="approval-proof-modal-title" className="mt-2 text-base font-semibold text-brand-dark">{title}</h2>
        <p id="approval-proof-modal-detail" className="mt-1 text-sm text-slate-500">{detail}</p>
        <div className="mt-4">
          <ApprovalProofFieldInputs
            approvalGate={approvalGate}
            approvalPassword={password}
            approvalTotpCode={totpCode}
            requireFreshTotp={requireFreshTotp}
            onApprovalPasswordChange={handlePasswordChange}
            onApprovalTotpCodeChange={handleTotpChange}
          />
        </div>
        {error ? (
          <p role="alert" className="mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.06] px-3 py-2 text-sm text-brand-attention">
            {error}
          </p>
        ) : null}
        {busy ? (
          <p
            role="status"
            tabIndex={0}
            className="mt-4 text-sm font-medium text-brand-dark focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40"
          >
            {busyLabel}
          </p>
        ) : null}
        <div className="mt-5 flex justify-end gap-2">
          <ActionButton type="button" variant="outline" onClick={onCancel} disabled={busy}>
            Cancel
          </ActionButton>
          <ActionButton type="submit" disabled={confirmDisabled}>
            {busy ? busyLabel : confirmLabel}
          </ActionButton>
        </div>
      </form>
    </div>
  );
}
