import type { LocalCliCommand, LocalCliItem } from "./local-cli-api";

const BRAND_PATTERN = /^[a-z0-9-]{1,40}$/;
const PROFILE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** Optional profile metadata; invalid fields are dropped so the item itself still renders. */
export function normalizeProfileFields(value: Record<string, unknown>): Partial<LocalCliItem> {
  const result: Partial<LocalCliItem> = {};
  if (typeof value.profile_id === "string" && PROFILE_ID_PATTERN.test(value.profile_id)) {
    result.profile_id = value.profile_id;
  }
  if (typeof value.brand === "string" && BRAND_PATTERN.test(value.brand)) result.brand = value.brand;
  if (typeof value.display_name === "string") {
    const name = value.display_name.trim().slice(0, 120);
    if (name) result.display_name = name;
  }
  if (typeof value.seeded === "boolean") result.seeded = value.seeded;
  if (typeof value.installed === "boolean") result.installed = value.installed;
  return result;
}

export function normalizeSuggestedState(value: unknown): Pick<LocalCliCommand, "suggested_state"> {
  return value === "inherit" || value === "allow" || value === "review" || value === "block"
    ? { suggested_state: value }
    : {};
}
