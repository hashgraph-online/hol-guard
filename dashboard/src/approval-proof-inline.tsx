import { useCallback, useEffect, useRef } from "react";
import type { ChangeEvent, KeyboardEvent, RefObject } from "react";
import { HiMiniKey } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

type ApprovalProofFieldInputsProps = {
  approvalGate: GuardApprovalGatePublicConfig | null;
  approvalPassword: string;
  approvalTotpCode: string;
  passwordRef?: RefObject<HTMLInputElement | null>;
  onApprovalPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onApprovalTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
};

export function approvalProofRequiresTotp(gate: GuardApprovalGatePublicConfig | null | undefined): boolean {
  return gate?.totp_enabled === true;
}

export function isApprovalProofSubmitDisabled(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  credentials: { approvalPassword: string; approvalTotpCode: string },
  busy: boolean,
): boolean {
  if (busy) {
    return true;
  }
  return credentials.approvalPassword.trim() === ""
    || (approvalProofRequiresTotp(gate) && credentials.approvalTotpCode.trim() === "");
}

export function buildApprovalProofCredentials(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  credentials: { approvalPassword: string; approvalTotpCode: string },
): { approval_password?: string; approval_totp_code?: string } {
  return {
    approval_password: credentials.approvalPassword,
    ...(approvalProofRequiresTotp(gate) ? { approval_totp_code: credentials.approvalTotpCode } : {}),
  };
}

export function ApprovalProofFieldInputs(props: ApprovalProofFieldInputsProps) {
  const needsTotp = approvalProofRequiresTotp(props.approvalGate);
  return (
    <div className="space-y-3">
      <label className="block">
        <span className="text-sm font-semibold text-brand-dark">Approval password</span>
        <input
          ref={props.passwordRef}
          type="password"
          autoComplete="current-password"
          value={props.approvalPassword}
          onChange={props.onApprovalPasswordChange}
          className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </label>
      {needsTotp ? (
        <label className="block">
          <span className="text-sm font-semibold text-brand-dark">Authenticator code</span>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            autoComplete="one-time-code"
            value={props.approvalTotpCode}
            onChange={props.onApprovalTotpCodeChange}
            className="mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
      ) : null}
    </div>
  );
}

type ApprovalProofInlineProps = {
  approvalGate: GuardApprovalGatePublicConfig | null;
  approvalPassword: string;
  approvalTotpCode: string;
  error: string | null;
  submitLabel: string;
  submitBusy: boolean;
  onApprovalPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onApprovalTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onSubmit: () => void;
  onBack: () => void;
};

export function ApprovalProofInline(props: ApprovalProofInlineProps) {
  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      passwordRef.current?.focus();
    }, 50);
    return () => window.clearTimeout(timer);
  }, []);

  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    {
      approvalPassword: props.approvalPassword,
      approvalTotpCode: props.approvalTotpCode,
    },
    props.submitBusy,
  );

  const handleKeyDown = useCallback(
    (event: KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Enter" && !submitDisabled) {
        event.preventDefault();
        props.onSubmit();
      }
    },
    [props.onSubmit, submitDisabled],
  );

  return (
    <div className="space-y-5" onKeyDown={handleKeyDown}>
      <div className="rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-4 py-4">
        <div className="flex items-start gap-3">
          <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-blue/10">
            <HiMiniKey className="h-5 w-5 text-brand-blue" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-brand-dark">Approval proof required</h3>
            <p className="mt-1 text-sm leading-relaxed text-slate-600">
              Enter your local approval proof before Guard syncs supply-chain intel on this device.
            </p>
          </div>
        </div>
      </div>

      <ApprovalProofFieldInputs
        approvalGate={props.approvalGate}
        approvalPassword={props.approvalPassword}
        approvalTotpCode={props.approvalTotpCode}
        passwordRef={passwordRef}
        onApprovalPasswordChange={props.onApprovalPasswordChange}
        onApprovalTotpCodeChange={props.onApprovalTotpCodeChange}
      />

      {props.error !== null ? (
        <p className="text-sm text-brand-attention" role="alert">
          {props.error}
        </p>
      ) : null}

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <ActionButton variant="primary" onClick={props.onSubmit} disabled={submitDisabled}>
          {props.submitLabel}
        </ActionButton>
        <ActionButton variant="outline" onClick={props.onBack} disabled={props.submitBusy}>
          Go back
        </ActionButton>
      </div>
    </div>
  );
}
