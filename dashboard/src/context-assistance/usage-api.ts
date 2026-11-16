import { fetchWithGuardAuth } from "../guard-api";
import { ContextAssistanceApiError } from "./api";

/** Token counts the way each tool's own usage record reports them. */
export type UsageTotals = {
  uncached_input_tokens: number;
  cached_input_tokens: number;
  cache_write_tokens: number;
  output_tokens: number;
  requests: number;
  compactions: number;
};
export type UsageSession = { last_active: string; model: string | null; folder: string | null; totals: UsageTotals };
export type UsageTool = { harness: string; sessions: number; totals: UsageTotals; recent: UsageSession[] };
/** What CIGAR did for helped sessions: measured counts and one labeled estimate. */
export type SavingsTotals = {
  sessions: number;
  prompts: number;
  context_tokens: number;
  files_shown: number;
  /** Files shown in sessions Guard could read; only these say what the AI reopened. */
  files_checked: number;
  files_opened_anyway: number;
  measured_sessions: number;
  used_tokens: number;
  estimated_saved_tokens: number;
};
export type SavingsApp = SavingsTotals & { app: string; rate_percent: number };
export type Savings = { window_days: number; total: SavingsTotals; apps: SavingsApp[] };
export type UsageMeter = {
  state: "ready" | "counting" | "unavailable";
  window_days: number;
  today: UsageTool[];
  week: UsageTool[];
  unread: string[];
  /** True while a newer count runs behind the totals shown. */
  refreshing?: boolean;
  /** Null when the estimate could not be read; the meter still shows. */
  savings?: Savings | null;
};

const PATH = "/v1/context-assistance/usage";
export const USAGE_FIELDS = ["uncached_input_tokens", "cached_input_tokens", "cache_write_tokens", "output_tokens", "requests", "compactions"] as const;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const count = (v: unknown) => typeof v === "number" && Number.isFinite(v) && v >= 0;
const text = (v: unknown) => v === null || typeof v === "string";

function totals(v: unknown): v is UsageTotals {
  return object(v) && USAGE_FIELDS.every((field) => count(v[field]));
}

function tool(v: unknown): v is UsageTool {
  return object(v) && typeof v.harness === "string" && count(v.sessions) && totals(v.totals) && Array.isArray(v.recent)
    && v.recent.every((s) => object(s) && typeof s.last_active === "string" && text(s.model) && text(s.folder) && totals(s.totals));
}

const SAVINGS_FIELDS = ["sessions", "prompts", "context_tokens", "files_shown", "files_checked", "files_opened_anyway", "measured_sessions", "used_tokens", "estimated_saved_tokens"] as const;

function savingsTotals(v: unknown): v is SavingsTotals {
  return object(v) && SAVINGS_FIELDS.every((field) => count(v[field]));
}

function savingsApp(v: unknown): v is SavingsApp {
  return savingsTotals(v) && object(v) && typeof v.app === "string" && count(v.rate_percent) && (v.rate_percent as number) < 100;
}

/** The estimate, or null when it is missing or not understood: a bad estimate never hides the measured usage. */
export function parseSavings(v: unknown): Savings | null {
  if (!object(v) || v.schema !== "guard-cigar-savings.v1" || v.estimate !== true || !count(v.window_days) || !savingsTotals(v.total)
    || !Array.isArray(v.apps) || !v.apps.every(savingsApp)) {
    return null;
  }
  return { window_days: v.window_days as number, total: v.total, apps: v.apps as SavingsApp[] };
}

export function parseUsageMeter(body: unknown): UsageMeter {
  if (!object(body) || (body.state !== "ready" && body.state !== "counting" && body.state !== "unavailable")
    || !count(body.window_days) || !Array.isArray(body.today) || !body.today.every(tool)
    || !Array.isArray(body.week) || !body.week.every(tool)
    || !Array.isArray(body.unread) || !body.unread.every((name) => typeof name === "string")
    || (body.refreshing !== undefined && typeof body.refreshing !== "boolean")) {
    throw new ContextAssistanceApiError("usage_payload_invalid", "Guard returned usage numbers this page does not understand.");
  }
  return { ...(body as UsageMeter), savings: parseSavings(body.savings) };
}

export async function readUsageMeter(signal?: AbortSignal): Promise<UsageMeter> {
  // A cold start runs Guard's helper process and the savings estimate (up to 8 s) before answering.
  const timeout = AbortSignal.timeout(30_000);
  const response = await fetchWithGuardAuth(PATH, { method: "GET", cache: "no-store", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new ContextAssistanceApiError("usage_unavailable", "Guard could not read usage right now. Try again in a moment.");
  }
  // A reply cut off mid-body (dropped connection, timeout) rejects here and is retried;
  // only a complete reply that is not JSON or has the wrong shape is "numbers this page does not understand".
  const text = await response.text();
  let body: unknown = null;
  try {
    body = JSON.parse(text);
  } catch {
    // Complete but not JSON: parseUsageMeter reports usage_payload_invalid.
  }
  return parseUsageMeter(body);
}
