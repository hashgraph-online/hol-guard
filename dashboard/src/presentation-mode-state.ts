import type { GuardPresentationMode, GuardResolvedPresentation, GuardSettings } from "./guard-types";

const SOURCES = new Set(["default", "local-explicit", "migrated", "session-preview", "cloud-profile", "read-error"]);
const DIAGNOSTICS = new Set([
  "presentation_not_supported_by_core", "presentation_settings_unavailable",
  "unsupported_presentation_schema_fell_back_to_everyday", "unknown_presentation_mode_fell_back_to_everyday",
  "legacy_presentation_mode_migrated",
]);
const READ_ONLY_DIAGNOSTICS = new Set([
  "presentation_not_supported_by_core", "presentation_settings_unavailable",
  "unsupported_presentation_schema_fell_back_to_everyday",
]);
const PRESENTATION_KEYS = [
  "presentation_mode", "presentation_mode_explicit", "presentation_schema_version",
  "presentation_revision", "presentation", "presentation_diagnostic",
] as const;

export function unavailablePresentation(diagnostic = "presentation_settings_unavailable"): GuardResolvedPresentation {
  return { value: "everyday", source: "read-error", explicit: false, writable: false,
    schema_version: 1, revision: 0, diagnostic };
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function readPresentationSettings(settings: unknown): GuardResolvedPresentation {
  if (!record(settings) || !record(settings.presentation)) {
    return unavailablePresentation("presentation_not_supported_by_core");
  }
  const value = settings.presentation;
  const allowed = new Set(["value", "source", "explicit", "writable", "schema_version", "revision", "diagnostic"]);
  if (Object.keys(value).some((key) => !allowed.has(key))
    || (value.value !== "everyday" && value.value !== "technical")
    || typeof value.source !== "string" || !SOURCES.has(value.source)
    || typeof value.explicit !== "boolean" || typeof value.writable !== "boolean"
    || value.schema_version !== 1 || !Number.isSafeInteger(value.revision) || Number(value.revision) < 0
    || (value.diagnostic !== null && (typeof value.diagnostic !== "string" || !DIAGNOSTICS.has(value.diagnostic)))) {
    return unavailablePresentation("presentation_not_supported_by_core");
  }
  const result = value as GuardResolvedPresentation;
  if (result.source === "read-error") return unavailablePresentation();
  return { ...result, writable: result.writable && !READ_ONLY_DIAGNOSTICS.has(result.diagnostic ?? "") };
}

export function presentationWritePayload(
  current: GuardResolvedPresentation, mode: GuardPresentationMode,
): Partial<GuardSettings> {
  if (!current.writable || current.schema_version !== 1 || !Number.isSafeInteger(current.revision)
    || current.revision < 0 || (mode !== "everyday" && mode !== "technical")) {
    throw new Error("Reload the local display preference before changing it.");
  }
  if ((current.value !== mode || !current.explicit) && current.revision === Number.MAX_SAFE_INTEGER) {
    throw new Error("The display preference revision is exhausted.");
  }
  return { presentation_mode: mode, presentation_schema_version: 1, presentation_revision: current.revision };
}

export function confirmsPresentationWrite(
  before: GuardResolvedPresentation, saved: GuardResolvedPresentation, mode: GuardPresentationMode,
): boolean {
  const minimum = before.revision + Number(before.value !== mode || !before.explicit);
  return saved.writable && saved.explicit && saved.value === mode && Number.isSafeInteger(saved.revision)
    && saved.revision >= minimum;
}

export function withoutPresentationSettings(settings: Partial<GuardSettings>): Partial<GuardSettings> {
  const result = { ...settings };
  for (const key of PRESENTATION_KEYS) delete result[key];
  return result;
}
