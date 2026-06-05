import { useCallback, useState } from "react";
import type { ChangeEvent } from "react";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

type ApprovalProofModalProps = {
  title: string;
  detail: string;
  confirmLabel: string;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
};

export function ApprovalProofModal(props: ApprovalProofModalProps) {
  const { title, detail, confirmLabel, approvalGate, onCancel, onConfirm } = props;
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");

  const handlePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);

  const handleTotpChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotpCode(event.target.value);
  }, []);

  const handleConfirm = useCallback(() => {
    onConfirm({
      approval_password: password,
      ...(approvalGate?.totp_enabled === true ? { approval_totp_code: totpCode } : {}),
    });
  }, [approvalGate, onConfirm, password, totpCode]);

  const confirmDisabled =
    password.trim() === "" || (approvalGate?.totp_enabled === true && totpCode.trim() === "");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 px-4">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl">
        <SectionLabel>Approval required</SectionLabel>
        <h2 className="mt-2 text-base font-semibold text-brand-dark">{title}</h2>
        <p className="mt-1 text-sm text-slate-500">{detail}</p>
        <label className="mt-4 block">
          <span className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
            Approval password
          </span>
          <input
            type="password"
            value={password}
            onChange={handlePasswordChange}
            autoComplete="current-password"
            className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        {approvalGate?.totp_enabled === true && (
          <label className="mt-3 block">
            <span className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">
              Authenticator code
            </span>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={totpCode}
              onChange={handleTotpChange}
              className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            />
          </label>
        )}
        <div className="mt-5 flex justify-end gap-2">
          <ActionButton variant="outline" onClick={onCancel}>
            Cancel
          </ActionButton>
          <ActionButton onClick={handleConfirm} disabled={confirmDisabled}>
            {confirmLabel}
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
