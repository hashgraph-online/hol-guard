import type { GuardOperatorHealth } from "./guard-types";

function nonNegativeNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function normalizeOperatorHealth(raw: unknown): GuardOperatorHealth | undefined {
  if (!isRecord(raw)) {
    return undefined;
  }
  const state = raw["state"];
  const cause = raw["cause"];
  const automaticRecovery = raw["automatic_recovery"];
  if (
    !["healthy", "backlogged", "saturated", "store-contended"].includes(String(state))
    || typeof cause !== "string"
    || typeof automaticRecovery !== "string"
  ) {
    return undefined;
  }
  return {
    state: state as GuardOperatorHealth["state"],
    cause,
    automatic_recovery: automaticRecovery,
    repairable: raw["repairable"] === true,
    queue_depth: nonNegativeNumber(raw["queue_depth"]),
    queue_limit: nonNegativeNumber(raw["queue_limit"]),
    oldest_wait_ms: nonNegativeNumber(raw["oldest_wait_ms"]),
    workers_busy: nonNegativeNumber(raw["workers_busy"]),
    workers_ready: nonNegativeNumber(raw["workers_ready"]),
    workers_configured: nonNegativeNumber(raw["workers_configured"]),
  };
}
