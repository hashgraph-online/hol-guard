import { ContextAssistanceApiError } from "./api";
import type { CigarUpdatePreferences } from "./versions-api";
export type CigarUpdateSettings = {
  requested: CigarUpdatePreferences; effective: CigarUpdatePreferences; revision: string;
  diagnostic: string | null; locked_settings: string[];
  capabilities: { modes: CigarUpdatePreferences["mode"][]; automatic_preparation: boolean; automatic_selection: boolean; retention_reduction: boolean };
};
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const id = (v: unknown): v is string => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const mode = (v: unknown): v is CigarUpdatePreferences["mode"] => typeof v === "string" && ["manual", "notify", "prepare"].includes(v);
function invalid(): never { throw new ContextAssistanceApiError("versions_preferences_invalid", "Guard returned incompatible CIGAR update preferences. Refresh preferences."); }
function preferences(v: unknown): CigarUpdatePreferences {
  if (!object(v) || !mode(v.mode) || typeof v.allow_preview !== "boolean" || typeof v.retain_last_good !== "boolean"
    || !(v.pinned_build === undefined || v.pinned_build === null || id(v.pinned_build))) invalid();
  return { mode: v.mode, allow_preview: v.allow_preview, retain_last_good: v.retain_last_good,
    ...(typeof v.pinned_build === "string" ? { pinned_build: v.pinned_build } : {}) };
}
export function parseCigarUpdateSettings(v: unknown): CigarUpdateSettings {
  if (!object(v) || v.schema !== "guard-cigar-update-preferences.v1" || typeof v.revision !== "string"
    || !/^sha256:[a-f0-9]{64}$/.test(v.revision) || !(v.diagnostic === null || typeof v.diagnostic === "string" && /^[a-z0-9_]{1,160}$/.test(v.diagnostic))
    || !Array.isArray(v.locked_settings) || v.locked_settings.length > 64
    || !v.locked_settings.every((k) => typeof k === "string" && k.length <= 256 && /^context_assistance_updates(?:\.[a-z_]+)?$/.test(k))
    || !object(v.capabilities) || !Array.isArray(v.capabilities.modes) || v.capabilities.modes.length > 3
    || !v.capabilities.modes.every(mode) || new Set(v.capabilities.modes).size !== v.capabilities.modes.length
    || typeof v.capabilities.automatic_preparation !== "boolean" || typeof v.capabilities.automatic_selection !== "boolean"
    || typeof v.capabilities.retention_reduction !== "boolean") invalid();
  return { requested: preferences(v.requested), effective: preferences(v.effective), revision: v.revision,
    diagnostic: v.diagnostic, locked_settings: [...v.locked_settings] as string[],
    capabilities: { modes: [...v.capabilities.modes], automatic_preparation: v.capabilities.automatic_preparation,
      automatic_selection: v.capabilities.automatic_selection, retention_reduction: v.capabilities.retention_reduction } };
}
