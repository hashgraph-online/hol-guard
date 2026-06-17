import type { ChangeEvent } from "react";
import {
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniShieldCheck,
  HiMiniXMark,
  HiMiniKey,
} from "react-icons/hi2";
import {
  buildBulkApproveConsequenceCopy,
  summarizeBulkApproveSelection,
} from "./approval-center-utils";
import { approvalGateCooldownLabel } from "./approval-gate-utils";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import type { QueueGroup } from "./queue-state";
import type {
  BulkRiskDisclosure,
  BulkRiskTier,
  BulkRiskTone,
} from "./queue-bulk-risk-disclosure";

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

export function buildBulkGateCredentials(
  gate: GuardApprovalGatePublicConfig | null | undefined,
  password: string,
  totpCode: string,
) {
  if (!isBulkApproveGateReady(gate)) {
    return undefined;
  }
  return {
    approval_password: password.trim(),
    approval_totp_code: totpCode.trim(),
    approval_gate_use_cooldown: false,
  };
}

const TIER_LABEL: Record<BulkRiskTier, string> = {
  low: "Low risk",
  elevated: "Elevated risk",
  high: "High risk",
};

function toneRing(tone: BulkRiskTone): string {
  if (tone === "attention") {
    return "border-brand-attention/30 bg-brand-attention/[0.06]";
  }
  if (tone === "amber") {
    return "border-amber-300/60 bg-amber-50/70";
  }
  return "border-brand-green/30 bg-brand-green-bg/40";
}

function toneChip(tone: BulkRiskTone): string {
  if (tone === "attention") {
    return "bg-brand-attention/10 text-brand-attention";
  }
  if (tone === "amber") {
    return "bg-amber-100 text-amber-800";
  }
  return "bg-brand-green/15 text-brand-green-text";
}

function toneIcon(tone: BulkRiskTone) {
  if (tone === "attention" || tone === "amber") {
    return HiMiniExclamationTriangle;
  }
  return HiMiniShieldCheck;
}

export type QueueBulkStickyBarProps = {
  visible: boolean;
  selectedGroupCount: number;
  selectedActionCount: number;
  riskTier: BulkRiskTier;
  riskTone: BulkRiskTone;
  gateReady: boolean;
  onStartReview: () => void;
  onClearSelection: () => void;
};

export function QueueBulkStickyBar(props: QueueBulkStickyBarProps) {
  if (!props.visible) return null;
  const unit = props.selectedActionCount === 1 ? "read" : "reads";
  const ChipIcon = toneIcon(props.riskTone);
  return (
    <div
      className="sticky top-2 z-20 mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-slate-200 bg-white/95 px-4 py-3 shadow-md backdrop-blur"
      role="region"
      aria-label="Bulk approval selection"
    >
      <span
        className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] ${toneChip(props.riskTone)}`}
      >
        <ChipIcon className="h-3.5 w-3.5" aria-hidden="true" />
        {TIER_LABEL[props.riskTier]}
      </span>
      <p className="min-w-0 flex-1 text-sm font-medium text-brand-dark">
        <span className="font-mono text-base font-semibold">{props.selectedActionCount}</span>
        {" "}
        {unit} selected · approve once
      </p>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={props.onStartReview}
          className="inline-flex min-h-9 items-center rounded-full bg-brand-blue px-4 py-1.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90"
        >
          Review &amp; approve
        </button>
        <button
          type="button"
          onClick={props.onClearSelection}
          className="inline-flex min-h-9 items-center rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-slate-50 hover:text-brand-dark"
        >
          Clear
        </button>
      </div>
    </div>
  );
}

export type QueueBulkStatusBannerProps = {
  visible: boolean;
  sensitiveFileReadCount: number;
};

export function QueueBulkStatusBanner(props: QueueBulkStatusBannerProps) {
  if (!props.visible) return null;
  return (
    <div className="mb-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2">
      <p className="text-xs text-brand-attention">
        {props.sensitiveFileReadCount} sensitive file{" "}
        {props.sensitiveFileReadCount === 1 ? "read" : "reads"} in queue — review each path before approving.
      </p>
    </div>
  );
}

export type QueueBulkDrawerProps = {
  open: boolean;
  step: "review" | "submitting" | "completed";
  selectedGroups: QueueGroup[];
  selectedActionCount: number;
  sensitiveFileReadCount: number;
  riskDisclosure: BulkRiskDisclosure;
  approvalGate: GuardApprovalGatePublicConfig | null;
  settingsHref: string;
  bulkApprovePassword: string;
  bulkApproveTotpCode: string;
  typedConfirm: string;
  confirmMatches: boolean;
  canConfirm: boolean;
  completedActionCount: number | null;
  errorMessage: string | null;
  onBulkApprovePasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onBulkApproveTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTypedConfirmChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onConfirmApprove: () => void;
  onCancel: () => void;
};

export function QueueBulkDrawer(props: QueueBulkDrawerProps) {
  if (!props.open) return null;

  if (props.step === "completed") {
    const approved = props.completedActionCount ?? 0;
    const unit = approved === 1 ? "action was" : "actions were";
    return (
      <BulkDrawerShell onClose={props.onCancel} labelledBy="guard-bulk-drawer-title">
        <div className="flex items-start gap-3 rounded-xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3">
          <HiMiniCheckCircle className="mt-0.5 h-5 w-5 shrink-0 text-brand-green" aria-hidden="true" />
          <div>
            <h2 id="guard-bulk-drawer-title" className="text-base font-semibold text-brand-dark">
              {approved} read-only {unit} approved
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              This bulk approval cannot be repeated. Reload the queue to see the latest state.
            </p>
          </div>
        </div>
        <div className="mt-5 flex justify-end">
          <button
            type="button"
            onClick={props.onCancel}
            className="rounded-full bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90"
          >
            Done
          </button>
        </div>
      </BulkDrawerShell>
    );
  }

  const disclosure = props.riskDisclosure;
  const DisclosureIcon = toneIcon(disclosure.tone);
  const riskLines = summarizeBulkApproveSelection(props.selectedGroups);
  const previewLines = riskLines.slice(0, 5);
  const hiddenCount = Math.max(0, riskLines.length - previewLines.length);
  const unit = props.selectedActionCount === 1 ? "action" : "actions";
  const submitLabel =
    props.step === "submitting"
      ? "Approving…"
      : `Approve once (${props.selectedActionCount} ${unit})`;

  return (
    <BulkDrawerShell onClose={props.onCancel} labelledBy="guard-bulk-drawer-title">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-brand-blue">
            Bulk approval
          </p>
          <h2 id="guard-bulk-drawer-title" className="mt-1 text-lg font-semibold text-brand-dark">
            Review {props.selectedActionCount} selected {unit}
          </h2>
        </div>
        <button
          type="button"
          onClick={props.onCancel}
          aria-label="Close bulk approval"
          className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-slate-400 transition-colors hover:bg-slate-100 hover:text-brand-dark"
        >
          <HiMiniXMark className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {/* Risk disclosure — escalates with selection size and composition */}
      <section
        aria-label="Risk disclosure"
        className={`mt-4 rounded-xl border p-4 ${toneRing(disclosure.tone)}`}
      >
        <div className="flex items-start gap-2.5">
          <DisclosureIcon
            className={`mt-0.5 h-5 w-5 shrink-0 ${
              disclosure.tone === "attention"
                ? "text-brand-attention"
                : disclosure.tone === "amber"
                  ? "text-amber-600"
                  : "text-brand-green"
            }`}
            aria-hidden="true"
          />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold text-brand-dark">{disclosure.headline}</h3>
              <span
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${toneChip(disclosure.tone)}`}
              >
                {TIER_LABEL[disclosure.tier]}
              </span>
            </div>
            <p className="mt-1.5 text-xs leading-5 text-brand-dark/80">{disclosure.body}</p>
            {disclosure.bullets.length > 0 && (
              <ul className="mt-2 space-y-1">
                {disclosure.bullets.map((bullet) => (
                  <li
                    key={bullet}
                    className="flex items-start gap-1.5 text-xs leading-5 text-brand-dark/85"
                  >
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-current opacity-60" aria-hidden="true" />
                    <span>{bullet}</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-2 text-[11px] leading-4 text-muted-foreground">
              {buildBulkApproveConsequenceCopy(props.selectedActionCount)}
            </p>
          </div>
        </div>
      </section>

      <div className="mt-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          What you are approving
        </p>
        <ul className="mt-2 space-y-2 rounded-lg bg-slate-50 px-3 py-2">
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
      </div>

      {props.sensitiveFileReadCount > 0 && (
        <div className="mt-3 flex items-start gap-2 rounded-lg bg-brand-attention/[0.06] px-3 py-2">
          <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
          <p className="text-xs text-brand-attention">
            {props.sensitiveFileReadCount} sensitive file{" "}
            {props.sensitiveFileReadCount === 1 ? "read remains" : "reads remain"} in the queue and will not be
            approved here.
          </p>
        </div>
      )}

      {isBulkApproveGateReady(props.approvalGate) ? (
        <div className="mt-4 space-y-3 rounded-lg border border-slate-200 bg-white p-3">
          <div className="flex items-center gap-2">
            <HiMiniKey className="h-4 w-4 text-brand-blue" aria-hidden="true" />
            <p className="text-xs font-semibold text-brand-dark">Confirm with your approval password</p>
          </div>
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
          {props.approvalGate?.cooldown_seconds && props.approvalGate.cooldown_seconds > 0 ? (
            <p className="text-[11px] text-muted-foreground">
              Bulk approval never uses the cooldown shortcut ({approvalGateCooldownLabel(props.approvalGate.cooldown_seconds).toLowerCase()}).
            </p>
          ) : null}
        </div>
      ) : (
        <div className="mt-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-3">
          <p className="text-sm font-semibold text-brand-dark">Approval password required</p>
          <p className="mt-1 text-xs leading-5 text-brand-dark/70">
            Set up your local approval gate before approving multiple reads at once.
          </p>
          <a
            href={props.settingsHref}
            className="mt-2 inline-flex rounded-full border border-brand-blue/30 bg-white px-3 py-1.5 text-xs font-medium text-brand-blue no-underline transition-colors hover:bg-brand-blue/5"
          >
            Open Settings
          </a>
        </div>
      )}

      {disclosure.requiresTypedConfirm && isBulkApproveGateReady(props.approvalGate) && (
        <div className="mt-3 space-y-1.5 rounded-lg border border-brand-attention/25 bg-brand-attention/[0.05] px-3 py-2.5">
          <label className="block">
            <span className="text-xs font-semibold text-brand-dark">
              Type <span className="font-mono font-bold text-brand-attention">{disclosure.confirmPhrase}</span> to confirm
            </span>
            <input
              type="text"
              value={props.typedConfirm}
              onChange={props.onTypedConfirmChange}
              autoComplete="off"
              spellCheck={false}
              disabled={props.step === "submitting"}
              aria-invalid={!props.confirmMatches}
              className="mt-1.5 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 font-mono text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:opacity-60"
              placeholder={disclosure.confirmPhrase}
            />
          </label>
          <p className="text-[11px] text-muted-foreground">
            High-impact bulk approval: retype the phrase to enable the confirm button.
          </p>
        </div>
      )}

      {props.errorMessage !== null && (
        <p className="mt-3 text-xs text-brand-purple" role="alert">
          {props.errorMessage}
        </p>
      )}

      <div className="mt-5 flex flex-wrap justify-end gap-2">
        <button
          type="button"
          onClick={props.onCancel}
          disabled={props.step === "submitting"}
          className="rounded-full border border-slate-300 px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={props.onConfirmApprove}
          disabled={props.step === "submitting" || !props.canConfirm}
          className="rounded-full bg-brand-blue px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitLabel}
        </button>
      </div>
    </BulkDrawerShell>
  );
}

function BulkDrawerShell(props: {
  onClose: () => void;
  labelledBy: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-black/30 p-0 backdrop-blur-sm sm:items-center sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={props.labelledBy}
      onClick={(event) => {
        if (event.target === event.currentTarget) props.onClose();
      }}
    >
      <div className="guard-fade-in max-h-[92vh] w-full max-w-lg overflow-y-auto rounded-t-2xl border border-slate-200 bg-white p-5 shadow-2xl sm:rounded-2xl sm:p-6">
        {props.children}
      </div>
    </div>
  );
}
