import type { GuardBrowserProviderFindingV1 } from "../guard-types";

/**
 * Provider finding rows (PRD 6.8). Core builds each row from the provider's compiled manifest, so
 * the name and reason labels are manifest text, never what a provider answered. This parser still
 * refuses anything outside the closed shapes, and caps labels at three, before a row is drawn.
 */

type Verdict = GuardBrowserProviderFindingV1["verdict"];
type State = GuardBrowserProviderFindingV1["state"];

const PROVIDER_ID = /^provider\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const MAX_REASON_LABELS = 3;
const MAX_TEXT = 80;

export const VERDICT_TEXT: Record<Verdict, string> = {
  danger: "Flagged as dangerous",
  caution: "Flagged for caution",
  ok: "No problems found",
  unknown: "No verdict",
};

/** Why a row has no fresh verdict. A non-fresh row never shows the verdict it carries. */
export const STATE_TEXT: Record<Exclude<State, "fresh">, string> = {
  stale: "Answer out of date",
  unavailable: "Could not reach the provider",
  rate_limited: "Provider is limiting requests",
  key_invalid: "Provider rejected the key",
  disabled: "Provider turned off",
};

const CAPABILITY_TEXT: Record<string, string> = {
  "browser.origin-reputation": "Site reputation",
  "browser.script-integrity": "Script integrity",
  "browser.page-data-risk": "Page data risk",
  "browser.download-reputation": "Download reputation",
  "browser.site-policy": "Site policy",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function plainText(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  // Control and format characters could reorder or hide the row; such text is dropped, not cleaned.
  if (text.length === 0 || text.length > MAX_TEXT || /[\p{Cc}\p{Cf}]/u.test(text)) return null;
  return text;
}

function parseRow(value: unknown): GuardBrowserProviderFindingV1 | null {
  if (!isRecord(value)) return null;
  const id = value.provider_id;
  const name = plainText(value.provider_name);
  const capability = value.capability;
  const verdict = value.verdict;
  const state = value.state;
  const observed = value.observed_at_ms;
  if (typeof id !== "string" || !PROVIDER_ID.test(id) || name === null) return null;
  if (typeof capability !== "string" || !Object.hasOwn(CAPABILITY_TEXT, capability)) return null;
  if (typeof verdict !== "string" || !Object.hasOwn(VERDICT_TEXT, verdict)) return null;
  if (typeof state !== "string" || (state !== "fresh" && !Object.hasOwn(STATE_TEXT, state))) return null;
  if (typeof observed !== "number" || !Number.isSafeInteger(observed) || observed < 0) return null;
  const labels = Array.isArray(value.reason_labels) ? value.reason_labels.map(plainText) : [];
  return {
    provider_id: id,
    provider_name: name,
    capability,
    verdict: verdict as Verdict,
    state: state as State,
    reason_labels: [...new Set(labels.filter((label): label is string => label !== null))].slice(0, MAX_REASON_LABELS),
    observed_at_ms: observed,
    sponsored: value.sponsored === true,
  };
}

/** The rows Core attached, in Core's order. A malformed row is left off; the rest still show. */
export function parseProviderFindings(value: unknown): GuardBrowserProviderFindingV1[] {
  if (!Array.isArray(value)) return [];
  return value.map(parseRow).filter((row): row is GuardBrowserProviderFindingV1 => row !== null);
}

export function providerCapabilityText(capability: string): string {
  return CAPABILITY_TEXT[capability] ?? "Provider check";
}

/** "checked 40 s ago". A clock behind the answer reads as just now. */
export function checkedAgo(observedAtMs: number, nowMs: number): string {
  const seconds = Math.max(0, Math.floor((nowMs - observedAtMs) / 1000));
  if (seconds < 5) return "checked just now";
  if (seconds < 60) return `checked ${seconds} s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `checked ${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `checked ${hours} h ago`;
  return `checked ${Math.floor(hours / 24)} d ago`;
}
