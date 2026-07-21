import type {
  GuardProtectionAppHealth,
  GuardProtectionCheck,
  GuardProtectionCheckStatus,
  GuardProtectionHealth,
  GuardProtectionState,
  GuardHeadlineState,
  GuardRuntimeSnapshot,
} from "./guard-types";

export const PROTECTION_CHECK_IDS = [
  "harness_hooks",
  "daemon",
  "policy_engine",
  "rule_packs",
  "decision_plane_compatibility",
  "containment_compatibility",
  "sandbox",
  "decision_stream",
  "tamper_checks",
] as const;

const CORE_CHECK_IDS = PROTECTION_CHECK_IDS.filter((checkId) => checkId !== "decision_stream");
const STABLE_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function copyForState(state: GuardProtectionState): { label: string; detail: string } {
  if (state === "protected") {
    return { label: "Protected", detail: "All required protection checks have current proof." };
  }
  if (state === "partial") {
    return { label: "Partially protected", detail: "Core protection passes, but decision-stream evidence is incomplete." };
  }
  return { label: "Degraded", detail: "One or more required protection checks failed or remain unproven." };
}

function deriveState(checks: GuardProtectionCheck[]): GuardProtectionState {
  const byId = new Map(checks.map((check) => [check.check_id, check.status]));
  if (checks.some((check) => check.status === "fail")) return "degraded";
  if (!CORE_CHECK_IDS.every((checkId) => byId.get(checkId) === "pass")) return "degraded";
  return byId.get("decision_stream") === "pass" ? "protected" : "partial";
}

function normalizeCheck(value: unknown): GuardProtectionCheck | null {
  if (!isRecord(value)) return null;
  const checkId = value.check_id;
  const status = value.status;
  const reasonCode = value.reason_code;
  if (typeof checkId !== "string" || !PROTECTION_CHECK_IDS.some((candidate) => candidate === checkId)) return null;
  if (status !== "pass" && status !== "unknown" && status !== "fail") return null;
  if (typeof reasonCode !== "string" || reasonCode.length > 96 || !STABLE_ID.test(reasonCode)) return null;
  return {
    check_id: checkId,
    status: status as GuardProtectionCheckStatus,
    reason_code: reasonCode,
  };
}

function normalizeChecks(value: unknown): GuardProtectionCheck[] | null {
  if (!Array.isArray(value) || value.length !== PROTECTION_CHECK_IDS.length) return null;
  const checks = value.map(normalizeCheck);
  if (checks.some((check) => check === null)) return null;
  const complete = checks as GuardProtectionCheck[];
  const ids = new Set(complete.map((check) => check.check_id));
  return ids.size === PROTECTION_CHECK_IDS.length ? complete : null;
}

function healthFromChecks(checks: GuardProtectionCheck[]): Omit<GuardProtectionHealth, "schema_version" | "apps"> {
  const state = deriveState(checks);
  const copy = copyForState(state);
  return {
    state,
    ...copy,
    evidence_gap: checks.some((check) => check.status === "unknown"),
    checks,
    reason_codes: checks.map((check) => check.reason_code),
  };
}

function fallbackChecks(): GuardProtectionCheck[] {
  return PROTECTION_CHECK_IDS.map((checkId) => ({
    check_id: checkId,
    status: "unknown",
    reason_code: "proof_unavailable",
  }));
}

export function unavailableProtectionHealth(): GuardProtectionHealth {
  return {
    schema_version: "guard.protection-health.v1",
    ...healthFromChecks(fallbackChecks()),
    apps: [],
  };
}

function normalizeApp(value: unknown): GuardProtectionAppHealth | null {
  if (!isRecord(value)) return null;
  const harness = value.harness;
  if (typeof harness !== "string" || harness.length > 64 || !STABLE_ID.test(harness)) return null;
  const checks = normalizeChecks(value.checks);
  if (checks === null) return null;
  return { harness, ...healthFromChecks(checks) };
}

export function normalizeProtectionHealth(value: unknown): GuardProtectionHealth {
  if (!isRecord(value) || value.schema_version !== "guard.protection-health.v1") {
    return unavailableProtectionHealth();
  }
  const checks = normalizeChecks(value.checks);
  if (checks === null || !Array.isArray(value.apps) || value.apps.length > 100) {
    return unavailableProtectionHealth();
  }
  const apps = value.apps.map(normalizeApp);
  if (apps.some((app) => app === null)) return unavailableProtectionHealth();
  const appIds = new Set((apps as GuardProtectionAppHealth[]).map((app) => app.harness));
  if (appIds.size !== apps.length) return unavailableProtectionHealth();
  return {
    schema_version: "guard.protection-health.v1",
    ...healthFromChecks(checks),
    apps: apps as GuardProtectionAppHealth[],
  };
}

export function protectionHeadlineFor(input: {
  health: GuardProtectionHealth;
  runtimeActive: boolean;
  pendingCount: number;
}): {
  headline_state: GuardHeadlineState;
  headline_label: string;
  headline_detail: string;
} {
  if (!input.runtimeActive) {
    return {
      headline_state: "setup",
      headline_label: "Setup required",
      headline_detail: "The local Guard runtime is offline. Start the daemon or rerun hol-guard bootstrap.",
    };
  }
  if (input.pendingCount > 0) {
    return {
      headline_state: "blocked",
      headline_label: "Blocked",
      headline_detail: "A blocked launch is waiting for review in the current request queue.",
    };
  }
  return {
    headline_state: input.health.state,
    headline_label: input.health.label,
    headline_detail: input.health.detail,
  };
}

export function protectionHealthFor(
  snapshot: Pick<GuardRuntimeSnapshot, "protection_health">,
): GuardProtectionHealth;
export function protectionHealthFor(
  snapshot: Pick<GuardRuntimeSnapshot, "protection_health">,
  harness: string,
): GuardProtectionAppHealth;
export function protectionHealthFor(
  snapshot: Pick<GuardRuntimeSnapshot, "protection_health">,
  harness: string | null = null,
): GuardProtectionHealth | GuardProtectionAppHealth {
  const health = normalizeProtectionHealth(snapshot.protection_health);
  if (harness === null) return health;
  const scoped = health.apps.find((app) => app.harness === harness);
  if (scoped) return scoped;
  const fallback = healthFromChecks(fallbackChecks());
  return { harness: STABLE_ID.test(harness) && harness.length <= 64 ? harness : "unknown", ...fallback };
}
