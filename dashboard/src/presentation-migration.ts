import type { GuardPresentationMode } from "./presentation-mode";

const LEGACY_PRESENTATION_MODE_MAP: Readonly<Record<string, GuardPresentationMode>> = {
  simple: "everyday",
  advanced: "technical",
  developer: "technical",
};

export function migrateLegacyPresentationMode(value: unknown): GuardPresentationMode | null {
  return typeof value === "string" ? LEGACY_PRESENTATION_MODE_MAP[value] ?? null : null;
}
