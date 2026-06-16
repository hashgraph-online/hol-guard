import type { ChangeEvent } from "react";
import { HiMiniCheckCircle, HiMiniExclamationTriangle } from "react-icons/hi2";
import {
  buildBulkApproveConsequenceCopy,
  summarizeBulkApproveSelection,
} from "./approval-center-utils";
import type { BulkGateCredentials } from "./approval-gate-utils";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { bulkApproveActionCount, type QueueGroup } from "./queue-state";

export type BulkApproveFlowStep = "collapsed" | "select" | "review" | "submitting" | "completed";

export function isBulkApproveGateReady(
  gate: GuardApprovalGatePublicConfig | null | undefined,
): boolean {
  return gate?.enabled === true && gate?.configured === true;
}

export function validateBulkApproveCredentials(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  credentials: { password: string; totpCode: string },
): string | null {
  if (!isBulkApproveGateReady(gate)) {
    return "Set up an approval password in Settings before bulk approval.";
  }
  if (!credentials.password.trim()) {
    return "Enter your approval password to continue.";
  }
  if (gate?.totp_enabled === true && !credentials.totpCode.trim()) {
    return "Enter your authenticator code to continue.";
  }
  return null;
}

export type QueueBulkApproveFlowProps = {
  step: BulkApproveFlowStep;
  eligibleGroups: QueueGroup[];
  selectedGroups: QueueGroup[];
  completedActionCount: number | null;
  sensitiveFileReadCount: number;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  settingsHref: string;
  bulkApprovePassword: string;
  bulkApproveTotpCode: string;
  errorMessage: string | null;
  onStart: () => void;
  onSelectAll: () => void;
  onClearSelection: () => void;
  onContinueToReview: () => void;
  onBackToSelect: () => void;
  onCancel: () => void;
  onConfirmApprove: () => void;
  onBulkApprovePasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onBulkApproveTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
};

export function QueueBulkApproveFlow(props: QueueBulkApproveFlowProps) {
  if (props.step === "completed") {
    const approvedCount = props.completedActionCount ?? 0;
    const approvedUnit = approvedCount === 1 ? "action was" : "actions were";
    return (
      <div className="mb-4 rounded-xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3">
        <div className="flex items-start gap-2">
          <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-green-text">
            {approvedCount} read-only {approvedUnit} approved. This bulk approval cannot be repeated.
          </p>
        </div>
      </div>
    );
  }

  if (props.eligibleGroups.length < 2) {
    return null;
  }

  const selectedActionCount = bulkApproveActionCount(props.selectedGroups);
  const riskLines = summarizeBulkApproveSelection(props.selectedGroups);
  const gateReady = isBulkApproveGateReady(props.approvalGate);
  const credentialError = validateBulkApproveCredentials(props.approvalGate, {
    password: props.bulkApprovePassword,
    totpCode: props.bulkApproveTotpCode,
  });
  const confirmDisabled =
    props.step === "submitting" ||
    (props.step === "review" && credentialError !== null);

  if (props.step === "collapsed") {
    if (!gateReady) {
      return (
        <div className="mb-4 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-3">
          <p className="text-sm font-semibold text-brand-dark">Bulk approve once requires an approval password</p>
          <p className="mt-1 text-xs leading-5 text-brand-dark/70">
            Set up your local approval gate before allowing multiple read-only file reads in one pass.
            Bulk approval always uses approve once and cannot remember future reads.
          </p>
          <a
            href={props.settingsHref}
            className="mt-3 inline-flex rounded-full border border-brand-blue/30 bg-white px-4 py-2 text-sm font-medium text-brand-blue no-underline transition-colors hover:bg-brand-blue/5"
          >
            Open Settings
          </a>
        </div>
      );
    }
    return (
      <div className="mb-4 space-y-2">
        <button
          type="button"
          onClick={props.onStart}
          className="rounded-full border border-brand-blue/30 bg-white px-4 py-2 text-sm font-medium text-brand-blue shadow-sm transition-colors hover:bg-brand-blue/5"
        >
          Approve once for multiple read-only reads
        </button>
        {props.sensitiveFileReadCount > 0 && (
          <p className="text-xs text-brand-attention">
            {props.sensitiveFileReadCount} sensitive file{" "}
            {props.sensitiveFileReadCount === 1 ? "read is" : "reads are"} excluded from bulk approval.
            Review those individually.
          </p>
        )}
      </div>
    );
  }

  const previewLines = riskLines.slice(0, 5);
  const hiddenCount = Math.max(0, riskLines.length - previewLines.length);
  const selectedCount = props.selectedGroups.length;
  const selectedUnit = selectedActionCount === 1 ? "action" : "actions";
  const stepHeading =
    props.step === "select"
      ? "Select read-only file reads"
      : `Review ${selectedActionCount} selected ${selectedUnit}`;
  const confirmLabel =
    props.step === "submitting"
      ? "Approving..."
      : `Approve once (${selectedActionCount} ${selectedUnit})`;

  return (
    <div className="mb-4 space-y-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-semibold text-brand-dark">
          {stepHeading}
        </p>
        <p className="text-xs text-muted-foreground">
          Step {props.step === "select" ? "1" : "2"} of 2
        </p>
      </div>

      {props.step === "select" && (
        <>
          <p className="text-xs leading-5 text-muted-foreground">
            Choose the non-sensitive file reads you want to allow in one pass. Sensitive paths stay in the queue for
            individual review.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={props.onSelectAll}
              className="rounded-full border border-brand-blue/30 px-3 py-1.5 text-xs font-medium text-brand-blue transition-colors hover:bg-brand-blue/5"
            >
              Select all eligible ({props.eligibleGroups.length})
            </button>
            <button
              type="button"
              onClick={props.onClearSelection}
              disabled={selectedCount === 0}
              className="rounded-full px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:text-brand-dark disabled:opacity-50"
            >
              Clear selection
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={props.onContinueToReview}
              disabled={selectedCount === 0}
              className="rounded-full bg-brand-blue px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-blue/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Continue ({selectedCount} selected)
            </button>
            <button
              type="button"
              onClick={props.onCancel}
              className="rounded-full px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:text-brand-dark"
            >
              Cancel
            </button>
          </div>
        </>
      )}

      {(props.step === "review" || props.step === "submitting") && (
        <>
          <p className="text-xs leading-5 text-muted-foreground">
            {buildBulkApproveConsequenceCopy(selectedActionCount)}
          </p>
          <ul className="space-y-2 rounded-lg bg-slate-50 px-3 py-2">
            {previewLines.map((line) => (
              <li key={line.requestId} className="text-xs text-brand-dark">
                <span className="font-medium">{line.harnessLabel}</span>
                {line.path !== null ? (
                  <span className="mt-0.5 block truncate font-mono text-[11px] text-brand-dark/70">{line.path}</span>
                ) : (
                  <span className="mt-0.5 block text-brand-dark/70">{line.title}</span>
                )}
                {line.duplicateCount > 0 && (
                  <span className="mt-0.5 block text-muted-foreground">
                    Includes {line.duplicateCount} duplicate {line.duplicateCount === 1 ? "retry" : "retries"}.
                  </span>
                )}
              </li>
            ))}
            {hiddenCount > 0 && (
              <li className="text-xs text-muted-foreground">and {hiddenCount} more selected reads</li>
            )}
          </ul>
          {props.sensitiveFileReadCount > 0 && (
            <div className="flex items-start gap-2 rounded-lg bg-brand-attention/[0.06] px-3 py-2">
              <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
              <p className="text-xs text-brand-attention">
                {props.sensitiveFileReadCount} sensitive file{" "}
                {props.sensitiveFileReadCount === 1 ? "read remains" : "reads remain"} in the queue and will not be
                approved here.
              </p>
            </div>
          )}
          <div className="flex items-start gap-2 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2">
            <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
            <p className="text-xs leading-5 text-brand-dark/80">
              Mass approval is risky. You are allowing multiple file reads without opening each request. Bulk approval
              only supports approve once and never remembers future reads.
            </p>
          </div>
          {gateReady && (
            <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
              <p className="text-xs font-medium text-brand-dark">Confirm with your approval password</p>
              <label className="block">
                <span className="sr-only">Approval password</span>
                <input
                  type="password"
                  value={props.bulkApprovePassword}
                  onChange={props.onBulkApprovePasswordChange}
                  placeholder="Approval password"
                  autoComplete="current-password"
                  disabled={props.step === "submitting"}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:opacity-60"
                />
              </label>
              {props.approvalGate?.totp_enabled === true && (
                <label className="block">
                  <span className="sr-only">Authenticator code</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    value={props.bulkApproveTotpCode}
                    onChange={props.onBulkApproveTotpCodeChange}
                    placeholder="Authenticator code"
                    disabled={props.step === "submitting"}
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:opacity-60"
                  />
                </label>
              )}
            </div>
          )}
          {props.errorMessage !== null && (
            <p className="text-xs text-brand-purple" role="alert">
              {props.errorMessage}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={props.onConfirmApprove}
              disabled={confirmDisabled}
              className="rounded-full bg-brand-blue px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-blue/90 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {confirmLabel}
            </button>
            <button
              type="button"
              onClick={props.onBackToSelect}
              disabled={props.step === "submitting"}
              className="rounded-full border border-slate-300 px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
            >
              Back
            </button>
            <button
              type="button"
              onClick={props.onCancel}
              disabled={props.step === "submitting"}
              className="rounded-full px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:text-brand-dark disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

export function buildBulkGateCredentials(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  password: string,
  totpCode: string,
): BulkGateCredentials | undefined {
  if (!isBulkApproveGateReady(gate)) {
    return undefined;
  }
  return {
    approval_password: password.trim(),
    approval_totp_code: totpCode.trim(),
    approval_gate_use_cooldown: false,
  };
}
