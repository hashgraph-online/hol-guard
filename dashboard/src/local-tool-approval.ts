import type {
  GuardApprovalRequest,
  GuardLocalToolApproval,
  GuardLocalToolGrantDuration,
  GuardLocalToolGrantTarget,
} from "./guard-types";

const TARGETS = new Set<GuardLocalToolGrantTarget>(["capability", "version"]);
const DURATIONS = new Set<GuardLocalToolGrantDuration>(["once", "15m", "1h", "5h", "version", "always"]);

export type LocalToolApprovalOptions = Omit<GuardLocalToolApproval, "eligible">;

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validTargets(value: unknown): GuardLocalToolGrantTarget[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(
    value.filter((item): item is GuardLocalToolGrantTarget =>
      TARGETS.has(item as GuardLocalToolGrantTarget),
    ),
  )];
}

function validDurations(value: unknown): GuardLocalToolGrantDuration[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(
    value.filter((item): item is GuardLocalToolGrantDuration =>
      DURATIONS.has(item as GuardLocalToolGrantDuration),
    ),
  )];
}

export function parseLocalToolApproval(value: unknown): GuardLocalToolApproval | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const raw = value as Record<string, unknown>;
  if (
    raw.eligible !== true ||
    !nonEmpty(raw.tool_name) ||
    !nonEmpty(raw.tool_identity_hash) ||
    !nonEmpty(raw.capability) ||
    !nonEmpty(raw.read_only_reason)
  ) {
    return undefined;
  }
  const allowedTargets = validTargets(raw.allowed_targets);
  const allowedDurations = validDurations(raw.allowed_durations);
  if (allowedTargets.length === 0 || allowedDurations.length === 0) return undefined;
  return {
    eligible: true,
    tool_name: raw.tool_name.trim(),
    tool_identity_hash: raw.tool_identity_hash,
    capability: raw.capability.trim(),
    read_only_reason: raw.read_only_reason.trim(),
    trust_basis: raw.trust_basis === "package-profile" ? "package-profile" : "verified-files",
    indefinite_allowed: raw.indefinite_allowed === true,
    allowed_targets: allowedTargets,
    allowed_durations: allowedDurations,
    hard_risk_exclusions: Array.isArray(raw.hard_risk_exclusions)
      ? raw.hard_risk_exclusions.filter(nonEmpty).map((entry) => entry.trim())
      : [],
  };
}

export function localToolApprovalOptions(item: GuardApprovalRequest): LocalToolApprovalOptions | null {
  const value = parseLocalToolApproval(item.local_tool_approval);
  if (value === undefined) return null;
  const { eligible: _, ...options } = value;
  return options;
}

export function defaultLocalToolTarget(options: LocalToolApprovalOptions): GuardLocalToolGrantTarget {
  if (options.allowed_targets.includes("capability")) return "capability";
  return options.allowed_targets[0];
}

export function defaultLocalToolDuration(options: LocalToolApprovalOptions): GuardLocalToolGrantDuration {
  if (options.allowed_durations.includes("once")) return "once";
  return options.allowed_durations[0];
}

export function validLocalToolSelection(
  options: LocalToolApprovalOptions | null,
  target: GuardLocalToolGrantTarget,
  duration: GuardLocalToolGrantDuration,
): { target: GuardLocalToolGrantTarget; duration: GuardLocalToolGrantDuration } {
  if (options === null) return { target: "capability", duration: "once" };
  return {
    target: options.allowed_targets.includes(target) ? target : defaultLocalToolTarget(options),
    duration: options.allowed_durations.includes(duration) ? duration : defaultLocalToolDuration(options),
  };
}

export function localToolTargetLabel(
  target: GuardLocalToolGrantTarget,
  options: LocalToolApprovalOptions,
): string {
  return target === "capability"
    ? `Only ${options.capability} calls`
    : "All recognized read-only calls";
}

export function localToolDurationLabel(duration: GuardLocalToolGrantDuration): string {
  const labels: Record<GuardLocalToolGrantDuration, string> = {
    once: "Once",
    "15m": "15 min",
    "1h": "1 hour",
    "5h": "5 hours",
    version: "Until tool changes",
    always: "Always",
  };
  return labels[duration];
}

export function localToolReadOnlyReasonLabel(reason: string): string {
  if (reason.startsWith("http_")) {
    return `an HTTP ${reason.slice(5).toUpperCase()} request`;
  }
  if (reason.startsWith("operation_")) {
    return `the read-only ${reason.slice(10)} operation`;
  }
  return "a recognized read-only operation";
}

export function localToolAllowButtonLabel(duration: GuardLocalToolGrantDuration): string {
  if (duration === "once") return "Approve once";
  if (duration === "version") return "Trust this version";
  if (duration === "always") return "Always trust safe calls";
  return `Allow for ${localToolDurationLabel(duration)}`;
}

export function localToolExpiryLabel(
  duration: GuardLocalToolGrantDuration,
  now: Date = new Date(),
): string | null {
  if (duration === "once" || duration === "version" || duration === "always") return null;
  const milliseconds = { "15m": 15 * 60_000, "1h": 60 * 60_000, "5h": 5 * 60 * 60_000 }[duration];
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(now.getTime() + milliseconds));
}

export function localToolSummary(
  options: LocalToolApprovalOptions,
  target: GuardLocalToolGrantTarget,
  duration: GuardLocalToolGrantDuration,
): string {
  const coverage = target === "capability" ? options.capability : "recognized read-only calls";
  return ["Allow", options.tool_name, coverage, localToolDurationLabel(duration)].join(" · ");
}

export function buildLocalToolResolutionFields(
  options: LocalToolApprovalOptions | null,
  target: GuardLocalToolGrantTarget,
  duration: GuardLocalToolGrantDuration,
):
  | {
      local_tool_grant_target: GuardLocalToolGrantTarget;
      local_tool_grant_duration: Exclude<GuardLocalToolGrantDuration, "once">;
    }
  | Record<string, never> {
  if (
    options === null ||
    duration === "once" ||
    !options.allowed_targets.includes(target) ||
    !options.allowed_durations.includes(duration)
  ) {
    return {};
  }
  return {
    local_tool_grant_target: target,
    local_tool_grant_duration: duration,
  };
}
