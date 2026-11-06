import { PROTECTION_CATEGORIES } from "./model/protection-categories";

export const PROTECTION_TELEMETRY_EVENTS = [
  "protection_center_viewed",
  "protection_density_changed",
  "protection_cloud_value_viewed",
  "protection_test_lab_checked",
] as const;

export type ProtectionTelemetryEvent = (typeof PROTECTION_TELEMETRY_EVENTS)[number];
export type ProtectionTelemetryTarget = { dispatchEvent(event: Event): boolean };

export const PROTECTION_TELEMETRY_EVENT_NAME = "guard:protection-telemetry";

const ALLOWED_FIELDS = new Set([
  "density",
  "plan_id",
  "cloud_state",
  "result",
  "category",
]);

const ALLOWED_PLAN_IDS = new Set(["free", "solo", "pro", "team", "enterprise", "unknown"]);
const ALLOWED_DENSITIES = new Set(["simple", "advanced", "developer"]);
const ALLOWED_CLOUD_STATES = new Set(["local_only", "paired_waiting", "paired_active", "unavailable"]);
const ALLOWED_RESULTS = new Set(["allowed", "ask-first", "blocked", "unavailable"]);
const ALLOWED_CATEGORIES = new Set<string>(PROTECTION_CATEGORIES.map((category) => category.id));

function boundedToken(value: unknown, max = 48): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length > max || !/^[a-z0-9_.-]+$/.test(normalized)) return null;
  return normalized;
}

export function sanitizeProtectionTelemetry(fields: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, raw] of Object.entries(fields)) {
    if (!ALLOWED_FIELDS.has(key)) continue;
    const value = boundedToken(raw);
    if (value === null) continue;
    if (key === "plan_id" && !ALLOWED_PLAN_IDS.has(value)) continue;
    if (key === "density" && !ALLOWED_DENSITIES.has(value)) continue;
    if (key === "cloud_state" && !ALLOWED_CLOUD_STATES.has(value)) continue;
    if (key === "result" && !ALLOWED_RESULTS.has(value)) continue;
    if (key === "category" && !ALLOWED_CATEGORIES.has(value)) continue;
    result[key] = value;
  }
  return result;
}

/**
 * Returns a privacy-safe telemetry envelope. The caller chooses whether and
 * where to emit it. Raw commands, paths, proof material, module/rule IDs,
 * tokens, and arbitrary metadata cannot enter the envelope.
 */
export function protectionTelemetryEnvelope(
  event: ProtectionTelemetryEvent,
  fields: Record<string, unknown> = {},
) {
  if (!PROTECTION_TELEMETRY_EVENTS.includes(event)) throw new Error("unsupported Protection Center telemetry event");
  return {
    schema_version: "guard.protection-center.telemetry.v1" as const,
    event,
    fields: sanitizeProtectionTelemetry(fields),
  };
}

/**
 * Emits only the sanitized envelope as an in-app DOM event. There is no
 * network transport here, and observer failure is ignored so local protection
 * can never depend on analytics availability.
 */
export function emitProtectionTelemetry(
  event: ProtectionTelemetryEvent,
  fields: Record<string, unknown> = {},
  target: ProtectionTelemetryTarget | null = typeof window === "undefined" ? null : window,
): boolean {
  if (!target) return false;
  try {
    return target.dispatchEvent(new CustomEvent(PROTECTION_TELEMETRY_EVENT_NAME, {
      detail: protectionTelemetryEnvelope(event, fields),
    }));
  } catch {
    return false;
  }
}
