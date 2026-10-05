import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import { HiMiniCheck, HiMiniXMark, HiMiniKey } from "react-icons/hi2";
import type { GuardApprovalRequest, GuardApprovalGatePublicConfig } from "./guard-types";
import { approvalGateCooldownLabel, approvalGateLockRemainingSeconds } from "./approval-gate-utils";
import {
  ApprovalProofFieldInputs,
  approvalProofRecentlySatisfied,
  approvalProofRequiresPassword,
  isApprovalProofSubmitDisabled,
} from "./approval-proof-inline";

type WhyThisPausedProps = {
  item: GuardApprovalRequest;
};

export function WhyThisPaused(props: WhyThisPausedProps) {
  const signals = props.item.decision_v2_json?.signals ?? [];
  const plainReasons = signals
    .filter((s) => s.plain_reason.trim().length > 0)
    .map((s) => s.plain_reason);
  const fallbackReasons = props.item.why_now ? [props.item.why_now] : [];
  const reasons = plainReasons.length > 0 ? plainReasons : fallbackReasons;

  if (reasons.length === 0) return null;

  return (
    <div className="mt-3 space-y-1">
      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
        Why this was paused
      </p>
      <ul className="space-y-1">
        {reasons.map((reason) => (
          <li key={reason} className="flex items-start gap-2 text-sm text-brand-dark/80">
            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-purple/60" />
            {reason}
          </li>
        ))}
      </ul>
    </div>
  );
}

type ApproveConsequenceProps = {
  retryInstruction: string | null;
  isCodex?: boolean;
};

export function ApproveConsequence(props: ApproveConsequenceProps) {
  const text =
    props.isCodex === true
      ? "If you approve: Codex will continue the paused action automatically."
      : props.retryInstruction !== null
        ? `If you approve: ${props.retryInstruction}`
        : "If you approve: HOL Guard will let this action run and remember your choice within the selected scope.";
  return (
    <div className="flex items-start gap-2">
      <HiMiniCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
      <p className="text-xs leading-5 text-muted-foreground">{text}</p>
    </div>
  );
}

export function BlockConsequence(props: { isCodex?: boolean }) {
  const text =
    props.isCodex === true
      ? "If you block: Codex will stop here. Return to your terminal to continue with a different approach."
      : "If you block: HOL Guard will stop this action and you can allow it again any time from the Review Queue.";
  return (
    <div className="flex items-start gap-2">
      <HiMiniXMark className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-purple" aria-hidden="true" />
      <p className="text-xs leading-5 text-muted-foreground">
        {text}
      </p>
    </div>
  );
}

export function KeyboardHints() {
  return (
    <div className="mt-4 hidden items-center gap-4 text-xs text-muted-foreground md:flex">
      <span className="flex items-center gap-1.5">
        <kbd className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px]">
          A
        </kbd>
        Approve
      </span>
      <span className="flex items-center gap-1.5">
        <kbd className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px]">
          B
        </kbd>
        Block
      </span>
      <span className="text-slate-400">·</span>
      <span>Keyboard shortcuts available after reviewing above</span>
    </div>
  );
}

type ApprovalPasswordModalProps = {
  gate: GuardApprovalGatePublicConfig;
  approvalPassword: string;
  approvalTotpCode: string;
  useCooldown: boolean;
  onApprovalPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onApprovalTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onUseCooldownChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onSubmit: () => void;
  onCancel: () => void;
  submitLabel: string;
  busy?: boolean;
};

function approvalProofModalTitle(locked: boolean, recentlySatisfied: boolean, needsPassword: boolean): string {
  if (locked) return "Approval gate temporarily locked";
  if (recentlySatisfied) return "Recently confirmed";
  if (needsPassword) return "Approval password required";
  return "Authenticator code required";
}

export function ApprovalPasswordModal(props: ApprovalPasswordModalProps) {
  const passwordRef = useRef<HTMLInputElement>(null);
  const [now, setNow] = useState(() => Date.now());
  const recentlySatisfied = approvalProofRecentlySatisfied(props.gate);
  const needsPassword = approvalProofRequiresPassword(props.gate);
  const lockRemainingSeconds = approvalGateLockRemainingSeconds(props.gate, now);
  const gateLocked = lockRemainingSeconds > 0;
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.gate,
    { approvalPassword: props.approvalPassword, approvalTotpCode: props.approvalTotpCode },
    props.busy === true,
  );
  useEffect(() => {
    if (!gateLocked) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [gateLocked]);
  useEffect(() => {
    if (recentlySatisfied) return undefined;
    const timer = setTimeout(() => {
      passwordRef.current?.focus();
    }, 50);
    return () => window.clearTimeout(timer);
  }, [recentlySatisfied]);

  let modalDescription = "Guard needs a fresh proof before it can save this decision.";
  if (recentlySatisfied) {
    modalDescription = "A new authenticator code is not needed yet.";
  }
  if (gateLocked) {
    modalDescription = `Approval gate is temporarily locked. Try again in ${lockRemainingSeconds} seconds.`;
  }

  const showCooldownOption =
    props.gate.cooldown_seconds > 0 &&
    !props.gate.cooldown_active &&
    props.gate.totp_enabled !== true;

  const handleBackdropClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target === e.currentTarget && props.busy !== true) props.onCancel();
    },
    [props.onCancel, props.busy]
  );

  const handleSubmit = useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!submitDisabled) props.onSubmit();
    },
    [props.onSubmit, submitDisabled]
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm"
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="approval-password-modal-title"
    >
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl">
        <div className="flex items-center gap-3">
          <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-brand-blue/10">
            <HiMiniKey className="h-5 w-5 text-brand-blue" aria-hidden="true" />
          </span>
          <div>
            <h2
              id="approval-password-modal-title"
              className="text-lg font-semibold tracking-tight text-brand-dark"
            >
              {approvalProofModalTitle(gateLocked, recentlySatisfied, needsPassword)}
            </h2>
            <p className="text-sm text-brand-dark/70">{modalDescription}</p>
          </div>
        </div>

        <div className="mt-5 space-y-3">
          {gateLocked ? (
            <p className="rounded-xl border border-brand-attention/25 bg-brand-attention/[0.06] px-4 py-3 text-sm leading-relaxed text-brand-dark" role="status">
              Guard will accept a new approval proof after the lock expires. No decision was saved.
            </p>
          ) : (
            <>
              <ApprovalProofFieldInputs
                approvalGate={props.gate}
                approvalPassword={props.approvalPassword}
                approvalTotpCode={props.approvalTotpCode}
                passwordRef={passwordRef}
                onApprovalPasswordChange={props.onApprovalPasswordChange}
                onApprovalTotpCodeChange={props.onApprovalTotpCodeChange}
              />
              {showCooldownOption && (
                <label className="flex cursor-pointer items-center gap-2 text-sm text-brand-dark">
                  <input
                    type="checkbox"
                    checked={props.useCooldown}
                    onChange={props.onUseCooldownChange}
                    className="h-4 w-4 accent-brand-blue"
                  />
                  Skip password for next {approvalGateCooldownLabel(props.gate.cooldown_seconds).toLowerCase()} (use cooldown)
                </label>
              )}
            </>
          )}
        </div>

        <div className="mt-6 flex flex-col gap-2 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={props.onCancel}
            disabled={props.busy === true}
            className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
          >
            Go back
          </button>
          <button
            type="submit"
            disabled={submitDisabled}
            className="rounded-full bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {props.submitLabel}
          </button>
        </div>
      </form>
    </div>
  );
}

type ConfirmModalProps = {
  action: "allow" | "block";
  scopeLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmModal(props: ConfirmModalProps) {
  const handleBackdropClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target === e.currentTarget) props.onCancel();
    },
    [props.onCancel]
  );

  const isAllow = props.action === "allow";
  const titleText = isAllow ? "Broad approval — are you sure?" : "Broad block — are you sure?";
  const confirmText = isAllow ? "Confirm approval" : "Confirm block";
  const confirmClass = isAllow
    ? "rounded-full bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90"
    : "rounded-full bg-brand-purple px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-purple/90";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm"
      onClick={handleBackdropClick}
    >
      <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl">
        <h2 className="text-lg font-semibold tracking-tight text-brand-dark">
          {titleText}
        </h2>
        <p className="mt-3 text-sm leading-6 text-brand-dark/70">
          This will remember your choice for {props.scopeLabel}. This is harder to undo.
        </p>
        <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={props.onCancel}
            className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
          >
            Go back
          </button>
          <button
            type="button"
            onClick={props.onConfirm}
            className={confirmClass}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
