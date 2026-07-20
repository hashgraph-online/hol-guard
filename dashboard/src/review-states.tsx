import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import { ActionButton, GuardHero, ProofStrip, SectionLabel } from "./approval-center-primitives";
import {
  buildCodexResumeUx,
  buildPrimaryReviewAction,
  harnessDisplayName,
} from "./approval-center-utils";
import type {
  GuardApprovalRequest,
  GuardCodexResumeResult,
  GuardProtectionState,
  GuardRuntimeSnapshot,
} from "./guard-types";
import { LoggedActionPanel } from "./logged-action-panel";
import { protectionHealthFor, unavailableProtectionHealth } from "./protection-health";

const PROTECTION_APPEARANCE = {
  protected: {
    Icon: HiMiniShieldCheck,
    cardClass: "border-emerald-200/60 bg-emerald-50/30",
    iconClass: "bg-brand-green/10 text-brand-green",
  },
  partial: {
    Icon: HiMiniInformationCircle,
    cardClass: "border-brand-blue/20 bg-brand-blue/[0.04]",
    iconClass: "bg-brand-blue/10 text-brand-blue",
  },
  degraded: {
    Icon: HiMiniExclamationTriangle,
    cardClass: "border-brand-attention/20 bg-brand-attention/[0.04]",
    iconClass: "bg-brand-attention/10 text-brand-attention",
  },
} satisfies Record<GuardProtectionState, {
  Icon: typeof HiMiniShieldCheck;
  cardClass: string;
  iconClass: string;
}>;

type ReviewCodexResumePanelProps = {
  resume: GuardCodexResumeResult;
  onRetry?: () => void;
};

function ReviewCodexResumePanel({ resume, onRetry }: ReviewCodexResumePanelProps) {
  const ux = buildCodexResumeUx(resume);
  const isPending = resume.status === "pending" || resume.status === "in_progress";
  const isSuccess = resume.status === "sent" || resume.status === "already_sent";
  const isFailed = resume.status === "failed";

  const borderClass = isFailed
    ? "border-brand-purple/25 bg-brand-purple/[0.05]"
    : isSuccess
    ? "border-brand-green/25 bg-brand-green-bg/30"
    : isPending
    ? "border-brand-blue/25 bg-brand-blue/[0.04]"
    : "border-slate-200/60 bg-slate-50/40";

  const iconClass = isFailed
    ? "text-brand-purple"
    : isSuccess
    ? "text-brand-green"
    : "text-brand-blue";

  return (
    <div className={`flex items-start gap-3 rounded-2xl border px-4 py-3 ${borderClass}`}>
      {isPending && (
        <HiMiniArrowPath className={`mt-0.5 h-4 w-4 shrink-0 animate-spin ${iconClass}`} aria-hidden="true" />
      )}
      {isSuccess && (
        <HiMiniCheckCircle className={`mt-0.5 h-4 w-4 shrink-0 ${iconClass}`} aria-hidden="true" />
      )}
      {isFailed && (
        <HiMiniExclamationTriangle className={`mt-0.5 h-4 w-4 shrink-0 ${iconClass}`} aria-hidden="true" />
      )}
      {!isPending && !isSuccess && !isFailed && (
        <HiMiniInformationCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
      )}
      <div className="flex-1 space-y-1">
        <p className="text-sm font-medium text-brand-dark">{ux.headline}</p>
        {ux.body !== null && (
          <p className="text-xs text-muted-foreground">{ux.body}</p>
        )}
        {isFailed && onRetry !== undefined && (
          <div className="mt-2">
            <ActionButton variant="outline" onClick={onRetry}>
              Retry resume
            </ActionButton>
          </div>
        )}
      </div>
    </div>
  );
}

export function ReviewEmptyState({ runtime, resolutionMessage, codexResume, onRetryResume }: { runtime: GuardRuntimeSnapshot | null; resolutionMessage: string | null; codexResume: GuardCodexResumeResult | null; onRetryResume?: () => void }) {
  const protectionHealth = runtime ? protectionHealthFor(runtime) : unavailableProtectionHealth();
  const protectedAppsCount = protectionHealth.apps.filter((app) => app.state === "protected").length;
  const heroStatus = protectionHealth.state === "protected" ? "clear" : protectionHealth.state;
  const {
    Icon: ProtectionIcon,
    cardClass: healthCardClass,
    iconClass: healthIconClass,
  } = PROTECTION_APPEARANCE[protectionHealth.state];

  return (
    <div className="space-y-6">
      <GuardHero
        status={heroStatus}
        headline="Nothing to review"
        subheadline={`No actions need your decision right now. ${protectionHealth.detail}`}
      />

      <ProofStrip
        items={[
          { label: "Queue", value: "All clear", tone: "green" },
          { label: "Protection", value: protectionHealth.label, tone: protectionHealth.state === "protected" ? "green" : "slate" },
          { label: "Apps protected", value: protectedAppsCount, tone: protectedAppsCount > 0 ? "green" : "slate" },
        ]}
      />

      {codexResume !== null && (
        <ReviewCodexResumePanel resume={codexResume} onRetry={onRetryResume} />
      )}

      {codexResume === null && resolutionMessage && (
        <div className="flex items-start gap-3 rounded-2xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3">
          <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-green-text">{resolutionMessage}</p>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <div className={`rounded-xl border p-4 sm:p-5 ${healthCardClass}`}>
          <div className="flex items-start gap-3">
            <span className={`inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${healthIconClass}`}>
              <ProtectionIcon className="h-5 w-5" aria-hidden="true" />
            </span>
            <div>
              <SectionLabel>{protectionHealth.label}</SectionLabel>
              <p className="mt-2 text-sm text-muted-foreground">
                {protectionHealth.detail} When something needs review, it will appear here.
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <SectionLabel>What Guard does</SectionLabel>
          <ul className="mt-3 space-y-2">
            {[
              "Pauses risky file reads and writes",
              "Blocks commands that could delete data",
              "Warns about new network connections",
              "Stops credential sharing",
            ].map((item) => (
              <li key={item} className="flex items-start gap-2 text-sm text-brand-dark">
                <HiMiniCheckCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

export function PrimaryActionCard({ item }: { item: GuardApprovalRequest }) {
  const action = buildPrimaryReviewAction(item);

  return (
    <div className="mt-5 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <SectionLabel>What was stopped</SectionLabel>
          {action.detail !== null && (
            <p className="mt-1 text-sm text-brand-dark/70">
              {action.detail}
            </p>
          )}
        </div>
        <span className="rounded-full border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-brand-blue">
          {action.label}
        </span>
      </div>
      <div className="mt-3">
        <LoggedActionPanel
          key={item.request_id}
          label={action.label}
          text={action.text}
          copyAriaLabel="Copy full stopped action to clipboard"
          expandAriaLabel="Expand full stopped action"
          collapseAriaLabel="Collapse full stopped action"
        />
      </div>
    </div>
  );
}

export function buildWhatWouldHappen(item: GuardApprovalRequest): string | null {
  const type = item.artifact_type;
  if (type?.includes("file_write") || type?.includes("file_read")) {
    return `Without Guard, ${harnessDisplayName(item.harness)} would access "${item.artifact_name ?? item.artifact_id}" immediately. Guard paused it so you can review first.`;
  }
  if (type?.includes("shell") || type?.includes("command")) {
    return `Without Guard, this shell command would run immediately. Guard paused it so you can review what it does first.`;
  }
  if (type?.includes("network") || type?.includes("request")) {
    return `Without Guard, this request would go to the network immediately. Guard paused it so you can review the destination first.`;
  }
  if (type?.includes("mcp") || type?.includes("tool")) {
    return `Without Guard, this tool would execute immediately. Guard paused it so you can review what data it accesses.`;
  }
  return `Without Guard, this action would run immediately. Guard paused it so you can review and decide.`;
}

export function pastDecisionVerb(decision: string): string {
  if (decision === "allow") {
    return "allowed";
  }
  if (decision === "block") {
    return "blocked";
  }
  return "reviewed";
}
