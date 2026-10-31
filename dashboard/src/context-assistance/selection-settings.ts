import type { GuardContextAssistanceConfig, GuardSettings } from "../guard-types";
function ordered(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(ordered);
  if (value !== null && typeof value === "object") {
    const fields = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(fields).sort().map((key) => [key, ordered(fields[key])]));
  }
  return value;
}
/** Native JSON and settings projections may serialize identical keys in a different order. */
const defaults = (value: GuardContextAssistanceConfig) => ({ ...value,
  features: { ...value.features, execution_context: value.features.execution_context === true } });
export const sameCigarPreferences = (a: GuardContextAssistanceConfig, b: GuardContextAssistanceConfig) =>
  JSON.stringify(ordered(defaults(a))) === JSON.stringify(ordered(defaults(b)));
const same = sameCigarPreferences;
/** Replace only native CIGAR preferences; unrelated settings and pending edits survive. */
export function withCigarSelection(
  settings: GuardSettings, native: GuardContextAssistanceConfig,
  previous: GuardContextAssistanceConfig, draft = false,
): GuardSettings {
  if (same(native, previous)) return settings;
  const current = settings.context_assistance;
  if (!current) return settings;
  if (!draft && !same(current, previous)) return settings;
  if (draft && current.runtime_id !== previous.runtime_id) return settings;
  const config = !draft || same(current, previous) ? native
    : { ...current, runtime_id: native.runtime_id, enabled: current.enabled && native.enabled };
  return { ...settings, context_assistance: config,
    ...(settings.context_assistance_requested !== undefined ? { context_assistance_requested: native } : {}) };
}
