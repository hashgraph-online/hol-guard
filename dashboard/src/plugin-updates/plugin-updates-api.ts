import { fetchPluginUpdatesApi } from "../guard-api";
import { isGuardDemoMode } from "../guard-demo";

/**
 * Plugin update prompts. The daemon downloads HOL's public plugin and release
 * indexes and the native runtime compares them with the plugins installed on
 * this machine, so this module only checks the shape of the answer and keeps
 * links on hol.org.
 */

export type PluginUpdateReason = "security_fix" | "installed_high_severity";

export type PluginUpdate = {
  slug: string;
  runtime: string;
  installedVersion: string;
  latestVersion: string;
  urgent: boolean;
  reason: PluginUpdateReason | null;
  releasesUrl: string | null;
};

export type PluginUpdatesResult =
  | { status: "ok"; updates: PluginUpdate[]; dismissed: number }
  | { status: "failed"; message: string };

const FALLBACK_FAILURE = "Guard could not check for plugin updates. Try again in a minute.";
const MAX_UPDATES = 200;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= 512 ? value : null;
}

/** Only hol.org release pages are linked; anything else renders without a link. */
export function safeReleasesUrl(value: unknown): string | null {
  const raw = text(value);
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" && url.hostname === "hol.org" && !url.username && !url.password
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

export function parsePluginUpdate(value: unknown): PluginUpdate | null {
  if (!isRecord(value)) return null;
  const slug = text(value.slug);
  const runtime = text(value.runtime);
  const installedVersion = text(value.installedVersion);
  const latestVersion = text(value.latestVersion);
  if (!slug || !runtime || !installedVersion || !latestVersion) return null;
  const reason =
    value.reason === "security_fix" || value.reason === "installed_high_severity" ? value.reason : null;
  return {
    slug,
    runtime,
    installedVersion,
    latestVersion,
    urgent: value.urgent === true || reason !== null,
    reason,
    releasesUrl: safeReleasesUrl(value.releasesUrl),
  };
}

async function failureMessage(response: Response): Promise<string> {
  try {
    const payload: unknown = await response.json();
    if (isRecord(payload) && typeof payload.message === "string" && payload.message.length <= 300) {
      return payload.message;
    }
  } catch {
    // Fall through to the generic message.
  }
  return FALLBACK_FAILURE;
}

export async function checkPluginUpdates(signal?: AbortSignal): Promise<PluginUpdatesResult> {
  // The demo never reads or changes the real Guard home.
  if (isGuardDemoMode()) return { status: "ok", updates: [], dismissed: 0 };
  let response: Response;
  try {
    response = await fetchPluginUpdatesApi("/v1/plugins/updates", { cache: "no-store", signal });
  } catch (error) {
    if (signal?.aborted) throw error;
    return { status: "failed", message: FALLBACK_FAILURE };
  }
  if (!response.ok) return { status: "failed", message: await failureMessage(response) };
  const payload: unknown = await response.json().catch(() => null);
  if (!isRecord(payload) || !Array.isArray(payload.updates)) {
    return { status: "failed", message: FALLBACK_FAILURE };
  }
  const updates = payload.updates
    .slice(0, MAX_UPDATES)
    .map(parsePluginUpdate)
    .filter((update): update is PluginUpdate => update !== null)
    .sort((left, right) => Number(right.urgent) - Number(left.urgent) || left.slug.localeCompare(right.slug));
  const dismissed =
    typeof payload.dismissed === "number" && Number.isInteger(payload.dismissed) && payload.dismissed >= 0
      ? payload.dismissed
      : 0;
  return { status: "ok", updates, dismissed };
}

export async function dismissPluginUpdate(update: Pick<PluginUpdate, "slug" | "latestVersion">): Promise<void> {
  if (isGuardDemoMode()) return;
  const response = await fetchPluginUpdatesApi("/v1/plugins/updates/dismiss", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ slug: update.slug, version: update.latestVersion }),
  });
  if (!response.ok) throw new Error(await failureMessage(response));
}
