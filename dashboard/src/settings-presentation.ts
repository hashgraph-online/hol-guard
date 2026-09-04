import type {
  GuardPresentationMode,
  GuardResolvedPresentation,
  GuardSettings,
} from "./guard-types";
import {
  PRESENTATION_SCHEMA_VERSION,
  resolvePresentationMode,
  type ResolvedGuardPresentationMode,
} from "./presentation-mode";

export { PRESENTATION_SCHEMA_VERSION } from "./presentation-mode";

export const presentationModeOptions = [
  { value: "everyday", label: "Everyday Mode - clear summaries" },
  { value: "technical", label: "Technical Mode - show more detail" },
];

export function resolveSettingsPresentation(settings: GuardSettings): ResolvedGuardPresentationMode {
  const resolved = resolvePresentationMode({
    value: settings.presentation_mode,
    explicit: settings.presentation_mode_explicit,
    schemaVersion: settings.presentation_schema_version,
    revision: settings.presentation_revision,
    writable: settings.presentation?.writable ?? true,
  });
  const authoritative = settings.presentation;
  if (isAuthoritativePresentation(authoritative, resolved)) {
    return {
      ...resolved,
      source: authoritative.source,
      writable: authoritative.writable,
      diagnostic: authoritative.diagnostic,
    };
  }
  return resolved;
}

function isAuthoritativePresentation(
  presentation: GuardResolvedPresentation | undefined,
  resolved: ResolvedGuardPresentationMode,
): presentation is GuardResolvedPresentation {
  return (
    presentation !== undefined
    && presentation.value === resolved.value
    && presentation.explicit === resolved.explicit
    && presentation.schema_version === resolved.schemaVersion
    && presentation.revision === resolved.revision
  );
}

export function buildSettingsUpdatePayload(
  draft: GuardSettings,
  saved: GuardSettings | null,
): Partial<GuardSettings> {
  const previous = saved ?? draft;
  const presentationChanged = (
    draft.presentation_mode !== previous.presentation_mode
    || draft.presentation_mode_explicit !== previous.presentation_mode_explicit
  );
  const payload: Partial<GuardSettings> = { ...draft };
  delete payload.presentation;
  delete payload.presentation_diagnostic;
  delete payload.presentation_mode;
  delete payload.presentation_mode_explicit;
  delete payload.presentation_schema_version;
  delete payload.presentation_revision;
  if (presentationChanged) {
    payload.presentation_mode = draft.presentation_mode;
    payload.presentation_mode_explicit = true;
    payload.presentation_schema_version = PRESENTATION_SCHEMA_VERSION;
    payload.presentation_revision = previous.presentation_revision;
  }
  return payload;
}

export function normalizePresentationSettings(settings: GuardSettings): GuardSettings {
  const presentation = resolveSettingsPresentation(settings);
  return {
    ...settings,
    presentation_mode: presentation.value,
    presentation_mode_explicit: presentation.explicit,
    presentation_schema_version: presentation.schemaVersion,
    presentation_revision: presentation.revision,
    presentation: {
      value: presentation.value,
      source: presentation.source,
      explicit: presentation.explicit,
      writable: presentation.writable,
      schema_version: presentation.schemaVersion,
      revision: presentation.revision,
      diagnostic: presentation.diagnostic,
    },
    presentation_diagnostic: presentation.diagnostic,
  };
}

export function parsePresentationMode(value: string): GuardPresentationMode | null {
  if (value === "everyday" || value === "technical") {
    return value;
  }
  return null;
}

export function applyPresentationMode(
  settings: GuardSettings,
  mode: GuardPresentationMode,
): GuardSettings {
  return {
    ...settings,
    presentation_mode: mode,
    presentation_mode_explicit: true,
    presentation_schema_version: PRESENTATION_SCHEMA_VERSION,
  };
}

export function presentationModeStatus(presentation: ResolvedGuardPresentationMode): string {
  if (presentation.source === "migrated") {
    return presentation.explicit
      ? "Chosen on this device. Your previous display preference was migrated."
      : "Recommended default. Your previous display preference was migrated.";
  }
  return presentation.explicit ? "Chosen on this device." : "Recommended default.";
}

const PRESENTATION_PAYLOAD_KEYS: ReadonlySet<string> = new Set([
  "presentation_mode",
  "presentation_mode_explicit",
  "presentation_schema_version",
  "presentation_revision",
]);

function settingsValueEquals(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => settingsValueEquals(item, b[index]));
  }
  if (a !== null && b !== null && typeof a === "object" && typeof b === "object") {
    const aRecord = a as Record<string, unknown>;
    const bRecord = b as Record<string, unknown>;
    const aKeys = Object.keys(aRecord);
    const bKeys = Object.keys(bRecord);
    if (aKeys.length !== bKeys.length) {
      return false;
    }
    return aKeys.every((key) => settingsValueEquals(aRecord[key], bRecord[key]));
  }
  return false;
}

/**
 * A save is presentation-only when the presentation preference changed and no
 * other settings value (including the approval gate and risk actions) differs
 * from the saved settings. The daemon accepts such a save without the
 * high-risk settings gate, so the UI must send only the presentation keys.
 */
export function isPresentationOnlyChange(draft: GuardSettings, saved: GuardSettings | null): boolean {
  const previous = saved ?? draft;
  const presentationChanged = (
    draft.presentation_mode !== previous.presentation_mode
    || draft.presentation_mode_explicit !== previous.presentation_mode_explicit
  );
  if (!presentationChanged) {
    return false;
  }
  for (const key of Object.keys(draft) as (keyof GuardSettings)[]) {
    if (key === "presentation" || key === "presentation_diagnostic") {
      continue;
    }
    if (PRESENTATION_PAYLOAD_KEYS.has(key)) {
      continue;
    }
    if (!settingsValueEquals(draft[key], previous[key])) {
      return false;
    }
  }
  return true;
}

/**
 * The exact request body for a presentation-only save, or null when the save
 * is not presentation-only. The daemon grants the settings-gate bypass only
 * when the request carries nothing beyond the presentation keys.
 */
export function presentationOnlySavePayload(
  draft: GuardSettings,
  saved: GuardSettings | null,
): Partial<GuardSettings> | null {
  if (!isPresentationOnlyChange(draft, saved)) {
    return null;
  }
  const base = buildSettingsUpdatePayload(draft, saved);
  return {
    presentation_mode: base.presentation_mode,
    presentation_mode_explicit: base.presentation_mode_explicit,
    presentation_schema_version: base.presentation_schema_version,
    presentation_revision: base.presentation_revision,
  };
}
