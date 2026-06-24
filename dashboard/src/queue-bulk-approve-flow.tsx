import { useMemo, type ChangeEvent } from "react";
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
    return "Set up an approval gate in Settings before bulk approval.";
  }
  if (gate?.totp_enabled === true) {
    return credentials.totpCode.trim() ? null : "Enter your authenticator code to continue.";
  }
  if (!credentials.password.trim()) {
    return "Enter your approval password to continue.";
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
  if (gate?.totp_enabled === true) {
    return {
      approval_totp_code: totpCode.trim(),
      approval_gate_use_cooldown: false,
    };
  }
  return {
    approval_password: password.trim(),
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

export type QueueBulkGatePromptProps = {
  visible: boolean;
  eligibleActionCount: number;
  settingsHref: string;
};

/**
 * Discovery prompt shown when eligible reads exist in the queue but the
 * approval gate is not configured. Ambient selection (and the bulk drawer)
 * require the gate, so without this banner users would never learn that bulk
 * approval is available once they set up an approval password.
 */
export function QueueBulkGatePrompt(props: QueueBulkGatePromptProps) {
  if (!props.visible) return null;
  const unit = props.eligibleActionCount === 1 ? "read" : "reads";
  return (
    <div className="mb-4 rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-4 py-3">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-brand-dark">
            Approve {props.eligibleActionCount} {unit} at once
          </p>
          <p className="mt-1 text-xs leading-5 text-brand-dark/70">
            Set up a local approval password to unlock bulk approval for read-only file reads.
            Bulk approval always approves once and never remembers future reads.
          </p>
        </div>
        <a
          href={props.settingsHref}
          className="inline-flex shrink-0 rounded-full border border-brand-blue/30 bg-white px-4 py-2 text-sm font-medium text-brand-blue no-underline transition-colors hover:bg-brand-blue/5"
        >
          Open Settings
        </a>
      </div>
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
    const doneFooter = (
      <div className="flex justify-end">
        <button
          type="button"
          onClick={props.onCancel}
          className="min-h-11 rounded-full bg-brand-blue px-6 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90"
        >
          Done
        </button>
      </div>
    );
    return (
      <BulkDrawerShell onClose={props.onCancel} labelledBy="guard-bulk-drawer-title" footer={doneFooter}>
        <div className="flex items-start gap-3 rounded-xl border border-brand-green/25 bg-brand-green-bg/30 p-4">
          <HiMiniCheckCircle className="mt-0.5 h-5 w-5 shrink-0 text-brand-green" aria-hidden="true" />
          <div>
            <h2 id="guard-bulk-drawer-title" className="text-base font-semibold text-brand-dark">
              {approved} {unit} approved
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Each approved once. This bulk approval cannot be repeated. Reload the queue to see the latest state.
            </p>
          </div>
        </div>
      </BulkDrawerShell>
    );
  }

  const disclosure = props.riskDisclosure;
  const DisclosureIcon = toneIcon(disclosure.tone);
  const riskLines = summarizeBulkApproveSelection(props.selectedGroups);
  const unit = props.selectedActionCount === 1 ? "action" : "actions";
  const submitLabel =
    props.step === "submitting"
      ? "Approving…"
      : `Approve once (${props.selectedActionCount} ${unit})`;

  // Group preview lines by category label so the operator sees the action mix
  // at a glance: "File reads (3)", "Shell commands (2)" instead of a flat list.
  // Group the first 8 preview lines by category label so the operator sees the
  // action mix at a glance: "File reads (3)", "Shell commands (2)" instead of a
  // flat list. Slice before grouping so the preview count and hidden count stay
  // mathematically consistent.
  const PREVIEW_LIMIT = 8;
  const shownGroups = useMemo(() => {
    const map = new Map<string, typeof riskLines>();
    for (const line of riskLines.slice(0, PREVIEW_LIMIT)) {
      const bucket = map.get(line.categoryLabel) ?? [];
      bucket.push(line);
      map.set(line.categoryLabel, bucket);
    }
    return Array.from(map.entries());
  }, [riskLines]);
  const hiddenCount = Math.max(0, riskLines.length - PREVIEW_LIMIT);
  const gateReady = isBulkApproveGateReady(props.approvalGate);

  const actionFooter = (
    <div className="flex flex-wrap items-center justify-end gap-2">
      <button
        type="button"
        onClick={props.onCancel}
        disabled={props.step === "submitting"}
        className="min-h-11 rounded-full border border-slate-300 px-5 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
      >
        Cancel
      </button>
      <button
        type="button"
        onClick={props.onConfirmApprove}
        disabled={props.step === "submitting" || !props.canConfirm}
        className="min-h-11 rounded-full bg-brand-blue px-6 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {submitLabel}
      </button>
    </div>
  );

  return (
    <BulkDrawerShell onClose={props.onCancel} labelledBy="guard-bulk-drawer-title" footer={actionFooter}>
      {/* Header zone — generous top space, clear count hierarchy */}
      <header className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${toneChip(disclosure.tone)}`}
            >
              {TIER_LABEL[disclosure.tier]}
            </span>
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              Bulk approval
            </p>
          </div>
          <h2 id="guard-bulk-drawer-title" className="mt-2 text-xl font-semibold tracking-tight text-brand-dark">
            Review {props.selectedActionCount} selected {unit}
          </h2>
        </div>
        <button
          type="button"
          onClick={props.onCancel}
          aria-label="Close bulk approval"
          className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-slate-400 transition-colors hover:bg-slate-100 hover:text-brand-dark"
        >
          <HiMiniXMark className="h-4 w-4" aria-hidden="true" />
        </button>
      </header>

      {/* Risk disclosure zone — the clear disclosure surface, given breathing room */}
      <section
        aria-label="Risk disclosure"
        className={`mt-6 rounded-2xl border p-5 ${toneRing(disclosure.tone)}`}
      >
        <div className="flex items-start gap-3">
          <span
            className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${
              disclosure.tone === "attention"
                ? "bg-brand-attention/10"
                : disclosure.tone === "amber"
                  ? "bg-amber-100"
                  : "bg-brand-green/10"
            }`}
          >
            <DisclosureIcon
              className={`h-5 w-5 ${
                disclosure.tone === "attention"
                  ? "text-brand-attention"
                  : disclosure.tone === "amber"
                    ? "text-amber-600"
                    : "text-brand-green"
              }`}
              aria-hidden="true"
            />
          </span>
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-semibold text-brand-dark">{disclosure.headline}</h3>
            <p className="mt-1.5 text-[13px] leading-relaxed text-brand-dark/75">{disclosure.body}</p>
            {disclosure.bullets.length > 0 && (
              <ul className="mt-3 space-y-1.5">
                {disclosure.bullets.map((bullet) => (
                  <li
                    key={bullet}
                    className="flex items-start gap-2 text-xs leading-5 text-brand-dark/85"
                  >
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-current opacity-50" aria-hidden="true" />
                    <span>{bullet}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>

      {/* What you're approving zone — grouped by category for scannability */}
      <section aria-label="Selected actions" className="mt-6">
        <div className="flex items-baseline justify-between">
          <h3 className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            What you are approving
          </h3>
          <span className="font-mono text-[11px] text-muted-foreground">
            {props.selectedActionCount} {unit}
          </span>
        </div>
        <div className="mt-2.5 space-y-3 rounded-xl bg-slate-50/80 px-4 py-3">
          {shownGroups.map(([categoryLabel, lines]) => (
            <div key={categoryLabel}>
              <p className="text-[11px] font-semibold text-brand-dark/70">
                {categoryLabel}{" "}
                <span className="font-normal text-muted-foreground">
                  ({lines.length + lines.reduce((sum, l) => sum + l.duplicateCount, 0)})
                </span>
              </p>
              <ul className="mt-1.5 space-y-1.5">
                {lines.slice(0, 3).map((line) => (
                  <li key={line.requestId} className="text-xs text-brand-dark">
                    <span className="font-medium">{line.harnessLabel}</span>
                    {line.path !== null ? (
                      <span className="mt-0.5 block truncate font-mono text-[11px] text-brand-dark/60">{line.path}</span>
                    ) : (
                      <span className="mt-0.5 block text-brand-dark/60">{line.title}</span>
                    )}
                  </li>
                ))}
                {lines.length > 3 && (
                  <li className="text-[11px] text-muted-foreground">+ {lines.length - 3} more</li>
                )}
              </ul>
            </div>
          ))}
          {hiddenCount > 0 && (
            <p className="text-[11px] text-muted-foreground">and {hiddenCount} more selected {unit}</p>
          )}
        </div>
      </section>

      {props.sensitiveFileReadCount > 0 && (
        <p className="mt-3 text-[11px] leading-5 text-brand-attention">
          {props.sensitiveFileReadCount} sensitive{" "}
          {props.sensitiveFileReadCount === 1 ? "action stays" : "actions stay"} in the queue for individual review.
        </p>
      )}

      {/* Confirmation zone — visually separated commit step */}
      <section aria-label="Confirm approval" className="mt-6">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Step 2 of 2
          </span>
          <span className="h-px flex-1 bg-slate-200" aria-hidden="true" />
        </div>

        {gateReady ? (
          <div className="mt-3 space-y-3 rounded-xl border border-slate-200 bg-white p-4">
            {props.approvalGate?.totp_enabled === true && (
              <>
                <div className="flex items-center gap-2">
                  <HiMiniKey className="h-4 w-4 text-brand-blue" aria-hidden="true" />
                  <label htmlFor="guard-bulk-approval-totp" className="text-sm font-semibold text-brand-dark">
                    Authenticator code
                  </label>
                </div>
                <input
                  id="guard-bulk-approval-totp"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={props.bulkApproveTotpCode}
                  onChange={props.onBulkApproveTotpCodeChange}
                  placeholder="6-digit code"
                  disabled={props.step === "submitting"}
                  className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:opacity-60"
                />
              </>
            )}
            {props.approvalGate?.totp_enabled !== true && (
              <>
                <div className="flex items-center gap-2">
                  <HiMiniKey className="h-4 w-4 text-brand-blue" aria-hidden="true" />
                  <label htmlFor="guard-bulk-approval-password" className="text-sm font-semibold text-brand-dark">
                    Approval password
                  </label>
                </div>
                <input
                  id="guard-bulk-approval-password"
                  type="password"
                  value={props.bulkApprovePassword}
                  onChange={props.onBulkApprovePasswordChange}
                  placeholder="Enter your approval password"
                  autoComplete="current-password"
                  disabled={props.step === "submitting"}
                  className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:opacity-60"
                />
              </>
            )}
            {disclosure.requiresTypedConfirm && (
              <div className="rounded-lg bg-brand-attention/[0.05] px-3 py-2.5">
                <label htmlFor="guard-bulk-typed-confirm" className="block text-xs font-semibold text-brand-dark">
                  Type{" "}
                  <span className="font-mono font-bold text-brand-attention">{disclosure.confirmPhrase}</span>{" "}
                  to confirm
                </label>
                <input
                  id="guard-bulk-typed-confirm"
                  type="text"
                  value={props.typedConfirm}
                  onChange={props.onTypedConfirmChange}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={props.step === "submitting"}
                  aria-invalid={props.typedConfirm.length > 0 && !props.confirmMatches}
                  className="mt-2 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 font-mono text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:opacity-60"
                  placeholder={disclosure.confirmPhrase}
                />
              </div>
            )}
            <p className="text-[11px] leading-4 text-muted-foreground">
              {buildBulkApproveConsequenceCopy(props.selectedActionCount)}
            </p>
          </div>
        ) : (
          <div className="mt-3 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-3">
            <p className="text-sm font-semibold text-brand-dark">Approval password required</p>
            <p className="mt-1 text-xs leading-5 text-brand-dark/70">
              Set up your local approval gate before approving multiple actions at once.
            </p>
            <a
              href={props.settingsHref}
              className="mt-2.5 inline-flex rounded-full border border-brand-blue/30 bg-white px-3.5 py-1.5 text-xs font-medium text-brand-blue no-underline transition-colors hover:bg-brand-blue/5"
            >
              Open Settings
            </a>
          </div>
        )}

        {props.errorMessage !== null && (
          <p className="mt-3 text-xs text-brand-purple" role="alert">
            {props.errorMessage}
          </p>
        )}
      </section>
    </BulkDrawerShell>
  );
}

function BulkDrawerShell(props: {
  onClose: () => void;
  labelledBy: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
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
      <div className="guard-fade-in flex max-h-[92vh] w-full max-w-xl flex-col overflow-hidden rounded-t-2xl border border-slate-200 bg-white shadow-2xl sm:rounded-2xl">
        <div className="flex-1 overflow-y-auto px-5 py-6 sm:px-7">{props.children}</div>
        {props.footer ? (
          <div className="border-t border-slate-100 bg-white/95 px-5 py-3.5 backdrop-blur sm:px-7">
            {props.footer}
          </div>
        ) : null}
      </div>
    </div>
  );
}
