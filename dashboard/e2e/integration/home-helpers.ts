import type { Locator, Page } from "@playwright/test";

import { daemonApi, type IntegrationState } from "./fixtures";

export type HomeSeed = {
  workspace: string;
  activeApps: string[];
  inactiveApps: string[];
  receipts: Record<string, { id: string; harness: string; decision: string; name: string }>;
};

export function homeSeed(state: IntegrationState): HomeSeed {
  return state.seeded.home as unknown as HomeSeed;
}

type LiveReceipt = {
  receipt_id: string;
  harness: string;
  policy_decision: string;
  artifact_name?: string | null;
  timestamp: string;
  user_override?: string | null;
};

type PackageManagerProtection = {
  path_status?: string;
  shim_dir?: string;
  installed_managers: string[];
  protected_managers: string[];
  unprotected_managers: string[];
};

export type LiveRuntime = {
  pending_count: number;
  receipt_count: number;
  cloud_state: string;
  latest_receipts: LiveReceipt[];
  managed_installs?: Array<{ harness: string; active: boolean }>;
  protection_health?: { state: "protected" | "partial" | "degraded" };
  supply_chain?: { package_manager_protection?: PackageManagerProtection };
};

export type LiveHome = {
  runtime: LiveRuntime;
  // The same count Home shows: the larger of the runtime counter and the list.
  queued: number;
  analytics: { daily_activity: Array<{ date_key: string; total: number }> };
};

// What Home reads on load, fetched straight from the daemon. Home also sums
// every other area's records, so specs compare the page with this rather than
// with fixed numbers.
export async function loadLiveHome(state: IntegrationState): Promise<LiveHome> {
  const [runtime, requests, analytics] = await Promise.all([
    daemonApi<LiveRuntime>(state, "/v1/runtime"),
    daemonApi<{ items: unknown[] }>(state, "/v1/requests"),
    daemonApi<LiveHome["analytics"]>(state, "/v1/receipts/analytics?activity_days=90&trend_days=7&top_limit=8"),
  ]);
  return { runtime, queued: Math.max(runtime.pending_count, requests.items.length), analytics };
}

export type ExpectedHero = {
  headline: string;
  badge: string;
  cta: string;
  // Path the call to action opens.
  target: "/inbox" | "/protect" | "/evidence";
};

// Mirrors deriveHomeState for a machine that has active installs (the home
// seed guarantees that). A "checking" state can show for a few seconds while
// proofs load, so specs wait on the settled value.
export function expectedHero(live: LiveHome): ExpectedHero {
  if (live.queued > 0) {
    return {
      headline: live.queued === 1 ? "1 action needs review" : `${live.queued} actions need review`,
      badge: "Needs your choice",
      cta: "Review now",
      target: "/inbox",
    };
  }
  switch (live.runtime.protection_health?.state) {
    case "degraded":
      return { headline: "Protection is degraded", badge: "Degraded", cta: "Review protection", target: "/protect" };
    case "partial":
      return { headline: "Protection is partial", badge: "Partially protected", cta: "Review protection", target: "/protect" };
    case "protected":
      return { headline: "All clear", badge: "Protected", cta: "View history", target: "/evidence" };
    default:
      throw new Error("runtime snapshot carries no protection health state");
  }
}

export function formatCount(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  return String(count);
}

// The page's date keys come from the browser's local day. Specs run the
// browser in UTC, which is also how the daemon keys its daily activity.
export function startOfTodayUtc(): number {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
}

export function actionsCheckedToday(live: LiveHome): number {
  const todayKey = new Date().toISOString().slice(0, 10);
  const fromAnalytics = live.analytics.daily_activity.find((day) => day.date_key === todayKey)?.total;
  if (fromAnalytics !== undefined) return fromAnalytics;
  return live.runtime.latest_receipts.filter((receipt) => Date.parse(receipt.timestamp) >= startOfTodayUtc()).length;
}

const ALLOWED = new Set(["allow", "warn"]);
const REVIEWED = new Set(["review", "require-reapproval", "sandbox-required"]);

// Mirrors buildDailyStory for the receipts the daemon returned.
export function expectedDailyStory(live: LiveHome): string | null {
  if (live.queued > 0) {
    const actionText = live.queued === 1 ? "1 action is" : `${live.queued} actions are`;
    return `${actionText} waiting for review. Guard paused ${live.queued === 1 ? "it" : "them"} to keep you safe.`;
  }
  const today = live.runtime.latest_receipts.filter((receipt) => Date.parse(receipt.timestamp) >= startOfTodayUtc());
  const allowed = today.filter((receipt) => ALLOWED.has(receipt.policy_decision)).length;
  const blocked = today.filter((receipt) => receipt.policy_decision === "block").length;
  const reviewed = today.filter((receipt) => REVIEWED.has(receipt.policy_decision)).length;
  const clauses: string[] = [];
  if (allowed > 0) clauses.push(`allowed ${allowed} action${allowed !== 1 ? "s" : ""}`);
  if (blocked > 0) clauses.push(`blocked ${blocked}`);
  if (reviewed > 0) clauses.push(`sent ${reviewed} for review`);
  if (clauses.length === 0) return null;
  const story =
    clauses.length > 1 ? `${clauses.slice(0, -1).join(", ")} and ${clauses[clauses.length - 1]}` : clauses[0];
  return `Guard ${story}.`;
}

const APP_NAMES: Record<string, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  copilot: "Copilot",
  cursor: "Cursor",
  gemini: "Gemini",
  grok: "Grok",
  opencode: "OpenCode",
};

export function appName(harness: string): string {
  return APP_NAMES[harness] ?? harness;
}

const ACTIVITY_VERB: Record<string, string> = {
  allow: "allowed",
  warn: "allowed",
  review: "paused",
  block: "blocked",
};

// Mirrors buildRecentProtectionCopy: names that look like paths stay off Home.
export function expectedActivityLine(receipt: LiveReceipt): string | null {
  const verb = ACTIVITY_VERB[receipt.policy_decision];
  if (!verb || receipt.user_override || !(receipt.harness in APP_NAMES)) return null;
  const raw = receipt.artifact_name?.trim() ?? "";
  const label = raw && !/[\\/~:]/.test(raw) && raw.length <= 48 ? raw : "a local action";
  const suffix = receipt.policy_decision === "warn" ? " with a warning" : receipt.policy_decision === "review" ? " for review" : "";
  return `${APP_NAMES[receipt.harness]} ${verb} ${label}${suffix}`;
}

export type ExpectedPackageProtection = {
  status: "protected" | "staged" | "partial" | "unprotected" | "unknown";
  label: string;
  managers: string[];
  protectedManagers: string[];
  tag: string | null;
  shimDir: string | null;
};

// Mirrors resolveHomeProtectionStatus and the module's copy.
export function expectedPackageProtection(runtime: LiveRuntime): ExpectedPackageProtection {
  const protection = runtime.supply_chain?.package_manager_protection;
  if (!protection) {
    return { status: "unknown", label: "Supply chain status unknown", managers: [], protectedManagers: [], tag: null, shimDir: null };
  }
  const managers = Array.from(new Set([...protection.protected_managers, ...protection.unprotected_managers])).sort();
  let status: ExpectedPackageProtection["status"] = "unprotected";
  if (protection.path_status === "restart_required" && protection.installed_managers.length > 0) status = "staged";
  else if (protection.unprotected_managers.length === 0 && protection.protected_managers.length > 0) status = "protected";
  else if (protection.protected_managers.length > 0) status = "partial";
  const label = {
    protected: "Package managers protected",
    staged: "Protection staged, finish activation",
    partial: "Some package managers unprotected",
    unprotected: "Package managers unprotected",
    unknown: "Supply chain status unknown",
  }[status];
  const tag =
    managers.length === 0
      ? null
      : status === "staged"
        ? `${protection.installed_managers.length} ready after restart`
        : `${protection.protected_managers.length} of ${managers.length} protected`;
  return {
    status,
    label,
    managers,
    protectedManagers: protection.protected_managers,
    tag,
    shimDir: protection.shim_dir ?? null,
  };
}

export function heroRegion(page: Page): Locator {
  return page.getByRole("region", { name: "Protection status" });
}

export function packageRegion(page: Page): Locator {
  return page.getByRole("region", { name: "Package manager protection" });
}

export function appsList(page: Page): Locator {
  return page.getByRole("list", { name: "Apps at a glance" });
}

// One of the "Pending / Apps / Recorded" tiles: a label above its value.
export function statTile(page: Page, label: string, value: string): Locator {
  return page.getByText(`${label}${value}`, { exact: true });
}
