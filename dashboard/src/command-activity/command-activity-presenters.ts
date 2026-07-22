import { harnessDisplayName } from "../approval-center-utils";
import type {
  CommandActivityAnalytics,
  CommandActivityItem,
  CommandActivityMatch,
  CommandExecutionStatus,
  CommandFeedbackLabel,
  CommandProofLevel,
  GuardAction,
} from "./command-activity-types";

const DECISION_LABELS: Record<GuardAction, string> = {
  allow: "Allowed",
  warn: "Allowed with warning",
  review: "Review required",
  "require-reapproval": "Reapproval required",
  "sandbox-required": "Sandbox required",
  block: "Blocked",
};

const EXECUTION_LABELS: Record<CommandExecutionStatus, string> = {
  attempted: "Attempt recorded",
  prevented: "Prevented before execution",
  allowed_unconfirmed: "Allowed; execution not confirmed",
  confirmed_success: "Execution confirmed successful",
  confirmed_failure: "Execution confirmed failed",
  unpaired_post: "Execution observed; initial decision unavailable",
};

const PROOF_LABELS: Record<CommandProofLevel, string> = {
  pre_hook: "Pre-execution check only",
  post_hook: "Post-execution proof recorded",
  unpaired_post: "Unpaired post-execution proof",
};

const REASON_LABELS: Record<string, string> = {
  no_match: "No command rule controlled the decision",
  extension_match: "A command rule controlled the decision",
  uncertainty: "Uncertainty retained a stricter review floor",
  policy: "A saved policy controlled the decision",
  approval_reuse: "A prior approval was evaluated for reuse",
  containment: "Verified containment evidence controlled the decision",
  capability: "A workflow capability controlled the decision",
};

const EFFECT_LABELS: Record<string, string> = {
  "workspace-or-public-read": "Workspace or public read",
  "sensitive-read": "Sensitive read",
  "workspace-write": "Workspace write",
  "external-filesystem-write": "External filesystem write",
  "process-execution": "Process execution",
  "network-read": "Network read",
  "network-write": "Network write",
  "remote-state-read": "Remote state read",
  "remote-state-mutation": "Remote state mutation",
  "permission-or-access-change": "Permission or access change",
  "credential-or-secret-operation": "Credential or secret operation",
  "system-or-privilege-operation": "System or privilege operation",
  "package-or-source-installation": "Package or source installation",
  "destructive-or-irreversible-operation": "Destructive or irreversible operation",
  "guard-control-operation": "Guard control operation",
};

export const FEEDBACK_LABELS: Record<CommandFeedbackLabel, string> = {
  should_not_have_interrupted: "Should not have interrupted",
  expected_guard_to_stop_this: "Expected Guard to stop this",
};

export function commandDecisionLabel(action: GuardAction | null): string {
  return action === null ? "Decision unavailable" : DECISION_LABELS[action];
}

export function commandExecutionLabel(status: CommandExecutionStatus): string {
  return EXECUTION_LABELS[status];
}

export function commandProofLabel(level: CommandProofLevel): string {
  return PROOF_LABELS[level];
}

export function commandReasonLabel(reason: string | null): string {
  if (reason === null) return "Reason unavailable";
  return REASON_LABELS[reason] ?? "Other recorded reason";
}

export function commandInteractionLabel(item: CommandActivityItem): string {
  return item.prompted ? "Guard asked for review" : "No review prompt recorded";
}

export function safeEvidenceId(value: string | null): string {
  if (value === null || value.length > 256 || !/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/.test(value)) {
    return "Unavailable";
  }
  return value;
}

export function safeVersion(value: string): string {
  return value.length <= 64 && /^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][a-z0-9.-]+)?$/i.test(value) ? value : "Unavailable";
}

export function commandEffectLabels(match: CommandActivityMatch): string[] {
  return match.effect_classes.map((effect) => EFFECT_LABELS[effect]).filter((label): label is string => label !== undefined);
}

export function analyticsBucketCount(
  analytics: CommandActivityAnalytics,
  dimension: keyof CommandActivityAnalytics["dimensions"],
  value: string,
): number {
  return analytics.dimensions[dimension].find((bucket) => bucket.value === value)?.count ?? 0;
}

export function commandMetricSummary(analytics: CommandActivityAnalytics): {
  commandsChecked: number;
  prompted: number;
  postProof: number;
  unconfirmed: number;
} {
  return {
    commandsChecked: analytics.commands_checked,
    prompted: analyticsBucketCount(analytics, "prompt_status", "prompted"),
    postProof: analyticsBucketCount(analytics, "proof_level", "post_hook"),
    unconfirmed: analyticsBucketCount(analytics, "execution_status", "allowed_unconfirmed"),
  };
}

export function commandBreakdownsAreGlobalOnly(analytics: CommandActivityAnalytics): boolean {
  return analytics.scope.dimension !== null && analytics.dimension_breakdowns_scope === "global";
}

export function commandProofCoveragePercent(analytics: CommandActivityAnalytics): number {
  if (analytics.commands_checked === 0) return 0;
  const postProof = analyticsBucketCount(analytics, "proof_level", "post_hook");
  return Math.round((postProof / analytics.commands_checked) * 100);
}

export function commandTrendPoints(
  analytics: CommandActivityAnalytics,
  limit = 14,
): CommandActivityAnalytics["trend"] {
  if (!Number.isInteger(limit) || limit < 1 || limit > 397) return [];
  const through = new Date(`${analytics.window.through}T00:00:00Z`);
  if (Number.isNaN(through.valueOf())) return analytics.trend.slice(-limit);
  const counts = new Map(analytics.trend.map((point) => [point.day, point.count]));
  return Array.from({ length: limit }, (_, index) => {
    const day = new Date(through);
    day.setUTCDate(day.getUTCDate() - (limit - index - 1));
    const key = day.toISOString().slice(0, 10);
    return { day: key, count: counts.get(key) ?? 0 };
  });
}

export function commandExecutionEvidenceCopy(harness: string | null, hasPostProof: boolean): string {
  if (harness === null) {
    return hasPostProof
      ? "This view includes correlated post-execution evidence on this page."
      : "No correlated post-execution evidence appears on this page. Allowed commands remain unconfirmed unless post-execution proof is recorded.";
  }
  const source = harnessDisplayName(harness);
  if (hasPostProof) return `${source} includes correlated post-execution evidence on this page.`;
  return `No correlated post-execution evidence from ${source} appears on this page. Allowed commands remain unconfirmed unless post-execution proof is recorded.`;
}

export function homeCommandActivityModel(analytics: CommandActivityAnalytics): {
  metrics: ReturnType<typeof commandMetricSummary>;
  health: string | null;
  window: string;
} | null {
  if (analytics.commands_checked === 0) return null;
  return {
    metrics: commandMetricSummary(analytics),
    health: commandHealthCopy(analytics),
    window: commandWindowLabel(analytics),
  };
}

export function commandHealthCopy(analytics: CommandActivityAnalytics): string | null {
  if (analytics.health.status === "healthy") return null;
  return "Command activity evidence is degraded. Counts may be incomplete.";
}

export function commandWindowLabel(analytics: CommandActivityAnalytics): string {
  return `${analytics.window.days}-day window ending ${analytics.window.through}`;
}
