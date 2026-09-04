export const PRESENTATION_SCHEMA_VERSION = 1 as const;
export type GuardPresentationMode = "everyday" | "technical";
export type GuardPresentationSource =
  | "default"
  | "local-explicit"
  | "session-preview"
  | "cloud-profile"
  | "read-error";

export type ResolvedGuardPresentationMode = {
  value: GuardPresentationMode;
  source: GuardPresentationSource;
  explicit: boolean;
  writable: boolean;
  schemaVersion: typeof PRESENTATION_SCHEMA_VERSION;
  revision: number;
  diagnostic: string | null;
};


export function resolvePresentationMode(input: {
  value?: unknown;
  explicit?: unknown;
  schemaVersion?: unknown;
  revision?: unknown;
  sessionPreview?: unknown;
  cloudProfile?: unknown;
  writable?: boolean;
  readError?: boolean;
}): ResolvedGuardPresentationMode {
  const revision = typeof input.revision === "number" && Number.isSafeInteger(input.revision) && input.revision >= 0
    ? input.revision
    : 0;
  const writable = input.writable !== false;
  const resolved = (
    value: GuardPresentationMode,
    source: GuardPresentationSource,
    explicit: boolean,
    diagnostic: string | null = null,
  ): ResolvedGuardPresentationMode => ({
    value, source, explicit, writable, schemaVersion: PRESENTATION_SCHEMA_VERSION, revision, diagnostic,
  });
  if (input.readError) return resolved("everyday", "read-error", false, "presentation_settings_unavailable");
  if (input.sessionPreview === "everyday" || input.sessionPreview === "technical") {
    return resolved(input.sessionPreview, "session-preview", true);
  }
  if (input.schemaVersion !== undefined && input.schemaVersion !== PRESENTATION_SCHEMA_VERSION) {
    return resolved("everyday", "default", false, "unsupported_presentation_schema_fell_back_to_everyday");
  }
  const persistedMode = input.value === "everyday" || input.value === "technical"
    ? input.value
    : null;
  if (persistedMode !== null && input.explicit === true) {
    return resolved(persistedMode, "local-explicit", true);
  }
  const invalidDiagnostic =
    input.value !== undefined &&
    input.value !== null &&
    input.value !== "" &&
    persistedMode === null
      ? "unknown_presentation_mode_fell_back_to_everyday"
      : null;
  if (input.cloudProfile === "everyday" || input.cloudProfile === "technical") {
    return resolved(input.cloudProfile, "cloud-profile", false, invalidDiagnostic);
  }
  if (invalidDiagnostic !== null) {
    return resolved("everyday", "default", false, invalidDiagnostic);
  }
  if (persistedMode !== null) {
    return resolved(persistedMode, "default", false);
  }
  return resolved("everyday", "default", false);
}

export type TechnicalDisclosureState = { open: boolean; source: "mode-default" | "user" | "required" };

export function defaultTechnicalDisclosure(mode: GuardPresentationMode, required = false): TechnicalDisclosureState {
  if (required) return { open: true, source: "required" };
  return { open: mode === "technical", source: "mode-default" };
}
