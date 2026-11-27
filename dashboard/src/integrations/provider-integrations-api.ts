import { fetchProviderIntegrationApi } from "../guard-api";

/** Mirrors `ProviderConnectionStateV1`. */
export type ProviderState = "not_connected" | "connected" | "key_invalid" | "disabled";
export type ProviderEffect = "observe" | "tighten" | "enforce";

export type ProviderSummary = {
  id: string;
  name: string;
  summary: string;
  verified: boolean;
  state: ProviderState;
  capabilities: string[];
};

export type ProviderCapabilitySetting = {
  capability: string;
  effect: ProviderEffect;
  requireFreshCheck: boolean;
};

/** Mirrors `ProviderDetailV1`, minus fields this page does not show. Holds no secret material. */
export type ProviderDetail = {
  summary: ProviderSummary;
  publisherName: string;
  publisherUrl: string | null;
  surfaces: string[];
  hosts: string[];
  privacyUrl: string;
  termsUrl: string;
  obtainUrl: string | null;
  shares: string[];
  enabledOptInFacts: string[];
  settings: ProviderCapabilitySetting[];
  lastVerifiedAtMs: number | null;
};

export class ProviderIntegrationApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number) {
    super(code);
    this.name = "ProviderIntegrationApiError";
    this.code = code;
    this.status = status;
  }
}

const STATES: readonly ProviderState[] = ["not_connected", "connected", "key_invalid", "disabled"];
const EFFECTS: readonly ProviderEffect[] = ["observe", "tighten", "enforce"];
const PROVIDER_ID = /^provider\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error("Invalid provider list field");
  return value.map((item) => {
    if (typeof item !== "string") throw new Error("Invalid provider list item");
    return item;
  });
}

function text(value: unknown): string {
  if (typeof value !== "string") throw new Error("Invalid provider text field");
  return value;
}

function optionalText(value: unknown): string | null {
  return value === null || value === undefined ? null : text(value);
}

/** Only `https:` links leave the dashboard; anything else is dropped rather than rendered. */
export function safeHttpsUrl(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password ? url.toString() : null;
  } catch {
    return null;
  }
}

export function isProviderId(value: string): boolean {
  return PROVIDER_ID.test(value);
}

export function normalizeProviderSummary(value: unknown): ProviderSummary {
  if (!isRecord(value)) throw new Error("Invalid provider summary");
  const id = text(value.id);
  if (!isProviderId(id)) throw new Error("Invalid provider id");
  const state = text(value.state) as ProviderState;
  if (!STATES.includes(state)) throw new Error("Invalid provider state");
  if (typeof value.verified !== "boolean") throw new Error("Invalid provider verification");
  return {
    id,
    name: text(value.name),
    summary: text(value.summary),
    verified: value.verified,
    state,
    capabilities: strings(value.capabilities),
  };
}

export function normalizeProviderList(value: unknown): ProviderSummary[] {
  if (!isRecord(value) || !Array.isArray(value.providers)) throw new Error("Invalid provider list");
  return value.providers.map(normalizeProviderSummary);
}

function normalizeSetting(value: unknown): ProviderCapabilitySetting {
  if (!isRecord(value)) throw new Error("Invalid provider setting");
  const effect = text(value.effect) as ProviderEffect;
  if (!EFFECTS.includes(effect)) throw new Error("Invalid provider effect");
  if (typeof value.require_fresh_check !== "boolean") throw new Error("Invalid fresh-check setting");
  return { capability: text(value.capability), effect, requireFreshCheck: value.require_fresh_check };
}

export function normalizeProviderDetail(value: unknown): ProviderDetail {
  if (!isRecord(value)) throw new Error("Invalid provider detail");
  if (!Array.isArray(value.settings)) throw new Error("Invalid provider settings");
  const verifiedAt = value.last_verified_at_ms;
  return {
    summary: normalizeProviderSummary(value.summary),
    publisherName: text(value.publisher_name),
    publisherUrl: safeHttpsUrl(optionalText(value.publisher_url)),
    surfaces: strings(value.surfaces),
    hosts: strings(value.hosts),
    privacyUrl: text(value.privacy_url),
    termsUrl: text(value.terms_url),
    obtainUrl: safeHttpsUrl(optionalText(value.obtain_url)),
    shares: strings(value.shares),
    enabledOptInFacts: strings(value.enabled_opt_in_facts),
    settings: value.settings.map(normalizeSetting),
    lastVerifiedAtMs: typeof verifiedAt === "number" && Number.isFinite(verifiedAt) ? verifiedAt : null,
  };
}

async function readProviderJson(response: Response): Promise<unknown> {
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : "provider_request_failed";
    throw new ProviderIntegrationApiError(code, response.status);
  }
  return payload;
}

export async function fetchProviderList(): Promise<ProviderSummary[]> {
  return normalizeProviderList(await readProviderJson(await fetchProviderIntegrationApi("/v1/integrations/providers")));
}

export async function fetchProviderDetail(providerId: string): Promise<ProviderDetail> {
  if (!isProviderId(providerId)) throw new ProviderIntegrationApiError("provider_not_found", 404);
  const response = await fetchProviderIntegrationApi(`/v1/integrations/providers/${providerId}`);
  return normalizeProviderDetail(await readProviderJson(response));
}
