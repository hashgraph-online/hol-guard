import type {
  GuardApprovalRequest,
  GuardTemporaryMcpApproval,
  GuardTemporaryMcpGrantDuration,
  GuardTemporaryMcpGrantTarget,
} from "./guard-types";

const TARGETS = new Set<GuardTemporaryMcpGrantTarget>(["exact", "category", "server"]);
const DURATIONS = new Set<GuardTemporaryMcpGrantDuration>(["once", "15m", "1h", "5h"]);

export type TemporaryMcpApprovalOptions = Omit<GuardTemporaryMcpApproval, "eligible">;

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validTargets(value: unknown): GuardTemporaryMcpGrantTarget[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is GuardTemporaryMcpGrantTarget => TARGETS.has(item as GuardTemporaryMcpGrantTarget)))];
}

function validDurations(value: unknown): GuardTemporaryMcpGrantDuration[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is GuardTemporaryMcpGrantDuration => DURATIONS.has(item as GuardTemporaryMcpGrantDuration)))];
}

export function parseTemporaryMcpApproval(value: unknown): GuardTemporaryMcpApproval | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const raw = value as Record<string, unknown>;
  if (
    raw.eligible !== true ||
    !nonEmpty(raw.server_name) ||
    !nonEmpty(raw.server_identity_hash) ||
    !nonEmpty(raw.category)
  ) {
    return undefined;
  }
  const allowedTargets = validTargets(raw.allowed_targets);
  const allowedDurations = validDurations(raw.allowed_durations);
  if (allowedTargets.length === 0 || allowedDurations.length === 0) return undefined;
  return {
    eligible: true,
    server_name: raw.server_name.trim(),
    server_identity_hash: raw.server_identity_hash,
    category: raw.category.trim(),
    target_label: nonEmpty(raw.target_label) ? raw.target_label.trim() : null,
    allowed_targets: allowedTargets,
    allowed_durations: allowedDurations,
    hard_risk_exclusions: Array.isArray(raw.hard_risk_exclusions)
      ? raw.hard_risk_exclusions.filter(nonEmpty).map((entry) => entry.trim())
      : [],
  };
}

export function temporaryMcpApprovalOptions(item: GuardApprovalRequest): TemporaryMcpApprovalOptions | null {
  const value = parseTemporaryMcpApproval(item.temporary_mcp_approval);
  if (value === undefined) return null;
  const { eligible: _, ...options } = value;
  return options;
}

export function defaultTemporaryMcpTarget(options: TemporaryMcpApprovalOptions): GuardTemporaryMcpGrantTarget {
  if (options.allowed_targets.includes("category")) return "category";
  return options.allowed_targets[0];
}

export function defaultTemporaryMcpDuration(options: TemporaryMcpApprovalOptions): GuardTemporaryMcpGrantDuration {
  if (options.allowed_durations.includes("1h")) return "1h";
  return options.allowed_durations[0];
}

export function temporaryMcpTargetLabel(
  target: GuardTemporaryMcpGrantTarget,
  options: TemporaryMcpApprovalOptions,
): string {
  if (target === "exact") return "This exact call";
  if (target === "category") return "This browser capability";
  return `All routine calls from ${options.server_name}`;
}

export function browserCapabilityLabel(category: string): string {
  const labels: Record<string, string> = {
    browser_navigation: "Navigate",
    browser_inspection: "Inspect",
    browser_interaction: "Interact",
  };
  return labels[category] ?? category.replace(/^browser_/, "").replaceAll("_", " ");
}

export function temporaryMcpDurationLabel(duration: GuardTemporaryMcpGrantDuration): string {
  return { once: "Once", "15m": "15 min", "1h": "1 hour", "5h": "5 hours" }[duration];
}

export function temporaryMcpAllowButtonLabel(duration: GuardTemporaryMcpGrantDuration): string {
  return duration === "once" ? "Approve once" : `Allow for ${temporaryMcpDurationLabel(duration)}`;
}

export function temporaryMcpExpiryLabel(
  duration: GuardTemporaryMcpGrantDuration,
  now: Date = new Date(),
): string | null {
  if (duration === "once") return null;
  const milliseconds = { "15m": 15 * 60_000, "1h": 60 * 60_000, "5h": 5 * 60 * 60_000 }[duration];
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(now.getTime() + milliseconds));
}

export function temporaryMcpSummary(
  options: TemporaryMcpApprovalOptions,
  target: GuardTemporaryMcpGrantTarget,
  duration: GuardTemporaryMcpGrantDuration,
): string {
  const coverage = target === "server" ? "Routine tools" : browserCapabilityLabel(options.category);
  return ["Allow", options.server_name, coverage, options.target_label, temporaryMcpDurationLabel(duration)]
    .filter(nonEmpty)
    .join(" · ");
}

export function buildTemporaryMcpResolutionFields(
  options: TemporaryMcpApprovalOptions | null,
  target: GuardTemporaryMcpGrantTarget,
  duration: GuardTemporaryMcpGrantDuration,
): { mcp_grant_target: GuardTemporaryMcpGrantTarget; mcp_grant_duration: GuardTemporaryMcpGrantDuration } | Record<string, never> {
  if (
    options === null ||
    duration === "once" ||
    !options.allowed_targets.includes(target) ||
    !options.allowed_durations.includes(duration)
  ) {
    return {};
  }
  return { mcp_grant_target: target, mcp_grant_duration: duration };
}
