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
export type UsageMeter = {
  state: "ready" | "counting" | "unavailable";
  window_days: number;
  today: UsageTool[];
  week: UsageTool[];
  unread: string[];
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

export function parseUsageMeter(body: unknown): UsageMeter {
  if (!object(body) || (body.state !== "ready" && body.state !== "counting" && body.state !== "unavailable")
    || !count(body.window_days) || !Array.isArray(body.today) || !body.today.every(tool)
    || !Array.isArray(body.week) || !body.week.every(tool)
    || !Array.isArray(body.unread) || !body.unread.every((name) => typeof name === "string")) {
    throw new ContextAssistanceApiError("usage_payload_invalid", "Guard returned usage numbers this page does not understand.");
  }
  return body as UsageMeter;
}

export async function readUsageMeter(signal?: AbortSignal): Promise<UsageMeter> {
  const timeout = AbortSignal.timeout(12_000);
  const response = await fetchWithGuardAuth(PATH, { method: "GET", cache: "no-store", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) throw new ContextAssistanceApiError("usage_unavailable", "Guard could not read usage right now. Try again in a moment.");
  return parseUsageMeter(body);
}
