import type { ReactNode } from "react";
import { HiMiniChevronRight } from "react-icons/hi2";

import { SectionLabel } from "./approval-center-primitives";
import { formatNumber, formatRelativeTime, harnessDisplayName } from "./approval-center-utils";
import type { GuardApprovalRequest, GuardReceipt, GuardReceiptAnalytics } from "./guard-types";
import { HeroParticleLogo } from "./home-hero-particle-logo";
import type { HeroParticleMood } from "./home-hero-particles";

export type HomeHeroStatus = "clear" | "needs_review" | "setup_gap" | "partial" | "degraded" | "checking";

export type HomeHeroQueueItem = {
  requestId: string;
  app: string;
  what: string;
  when: string;
};

/** Keeps names off the Home screen when they look like paths or are too long to be a plain name. */
export function redactQueueArtifactName(value: string | null | undefined): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 48) return null;
  if (/[\\/~:]/.test(trimmed)) return null;
  return trimmed;
}

/** Plain-language description of what a paused request wants to do, for people who do not read logs. */
export function describeQueueItem(item: GuardApprovalRequest): string {
  const actionType = item.action_envelope_json?.action_type;
  const name = redactQueueArtifactName(item.artifact_name);
  const suffix = name ? ` · ${name}` : "";
  switch (actionType) {
    case "shell_command":
      return "wants to run a command";
    case "prompt":
      return "sent a prompt that needs a look";
    case "file_read":
      return "wants to read a file";
    case "file_write":
      return "wants to change a file";
    case "mcp_tool":
      return `wants to use a tool${suffix}`;
    case "package_script":
      return `wants to run a package script${suffix}`;
    case "network_request":
      return "wants to reach the internet";
    case "config_change":
      return "wants to change a setting";
    case "browser_action":
      return "wants to act in the browser";
    case "harness_start":
      return "is starting up";
    default:
      break;
  }
  switch (item.artifact_type) {
    case "file_read_request":
      return "wants to read a file";
    case "prompt_request":
      return "sent a prompt that needs a look";
    case "tool_action_request":
      return `wants to use a tool${suffix}`;
    case "mcp_server":
      return `wants to start a new tool${suffix}`;
    case "extension":
      return `wants to load an extension${suffix}`;
    case "hook":
      return `wants to run a hook${suffix}`;
    default:
      return `wants to run something new${suffix}`;
  }
}

export function buildHeroQueuePreview(items: GuardApprovalRequest[], limit = 3): HomeHeroQueueItem[] {
  return items.slice(0, limit).map((item) => ({
    requestId: item.request_id,
    app: harnessDisplayName(item.harness),
    what: describeQueueItem(item),
    when: formatRelativeTime(item.created_at),
  }));
}

function localDateKey(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function countReceiptsToday(receipts: GuardReceipt[]): number {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return receipts.filter((receipt) => new Date(receipt.timestamp) >= today).length;
}

export function buildHeroFacts(input: {
  status: HomeHeroStatus;
  watchedAppsCount: number;
  queuedCount: number;
  latestReceipts: GuardReceipt[];
  analytics: GuardReceiptAnalytics | null;
  oldestQueuedAt: string | null;
}): string[] {
  if (input.status === "setup_gap") {
    return ["Runs on this computer only", "Nothing leaves your machine unless you turn on sync", "Free and open source"];
  }
  if (input.status === "checking") {
    return [];
  }
  const facts: string[] = [];
  const appsLabel = `${formatNumber(input.watchedAppsCount)} app${input.watchedAppsCount === 1 ? "" : "s"}`;
  const fullyProtected = input.status === "clear" || input.status === "needs_review";
  facts.push(fullyProtected ? `${appsLabel} protected` : `${appsLabel} connected`);
  if (input.status === "needs_review") {
    if (input.oldestQueuedAt) facts.push(`Paused ${formatRelativeTime(input.oldestQueuedAt)}`);
    facts.push("Your apps keep working while you decide");
    return facts;
  }
  const todayKey = localDateKey(new Date());
  const todayFromAnalytics = input.analytics?.daily_activity.find((day) => day.date_key === todayKey)?.total;
  const checkedToday = todayFromAnalytics ?? countReceiptsToday(input.latestReceipts);
  if (checkedToday > 0) facts.push(`${formatNumber(checkedToday)} action${checkedToday === 1 ? "" : "s"} checked today`);
  const latest = input.latestReceipts[0];
  if (latest) facts.push(`Last decision ${formatRelativeTime(latest.timestamp)}`);
  return facts;
}

export function buildHeroLiveLabel(status: HomeHeroStatus, watchedAppsCount: number, queuedCount: number): string {
  if (status === "needs_review") return queuedCount === 1 ? "1 paused" : `${queuedCount} paused`;
  if (status === "setup_gap") return "Ready";
  if (status === "checking") return "Checking";
  if (status === "degraded") return "Needs repair";
  if (status === "partial") return "Partly protected";
  return `Watching ${watchedAppsCount} app${watchedAppsCount === 1 ? "" : "s"}`;
}

export type HomeHeroModel = {
  facts: string[];
  liveLabel: string;
  queue: HomeHeroQueueItem[];
};

function oldestCreatedAt(items: GuardApprovalRequest[]): string | null {
  let oldest: string | null = null;
  let oldestMs = Number.POSITIVE_INFINITY;
  for (const item of items) {
    const ms = Date.parse(item.created_at);
    if (Number.isFinite(ms) && ms < oldestMs) {
      oldestMs = ms;
      oldest = item.created_at;
    }
  }
  return oldest;
}

/** Everything the hero shows that comes from runtime data, in one call so HomeWorkspace stays small. */
export function buildHomeHeroModel(input: {
  status: HomeHeroStatus;
  watchedAppsCount: number;
  queuedCount: number;
  queuedItems: GuardApprovalRequest[];
  latestReceipts: GuardReceipt[];
  analytics: GuardReceiptAnalytics | null;
}): HomeHeroModel {
  // Only name the oldest pause when every paused action is loaded; a partial page could miss it.
  const oldest = input.queuedItems.length >= input.queuedCount ? oldestCreatedAt(input.queuedItems) : null;
  return {
    facts: buildHeroFacts({
      status: input.status,
      watchedAppsCount: input.watchedAppsCount,
      queuedCount: input.queuedCount,
      latestReceipts: input.latestReceipts,
      analytics: input.analytics,
      oldestQueuedAt: oldest,
    }),
    liveLabel: buildHeroLiveLabel(input.status, input.watchedAppsCount, input.queuedCount),
    queue: buildHeroQueuePreview(input.queuedItems),
  };
}

export const HERO_BADGE_LABELS: Record<HomeHeroStatus, string> = {
  clear: "Protected",
  needs_review: "Needs your choice",
  setup_gap: "Setup needed",
  partial: "Partially protected",
  degraded: "Degraded",
  checking: "Checking",
};

/** Visual tone for a status: the hero accent, chip tint and particle mood all follow it. */
export function heroToneForStatus(status: HomeHeroStatus): "clear" | "review" | "setup" {
  if (status === "needs_review" || status === "degraded") return "review";
  if (status === "clear") return "clear";
  return "setup";
}

function HeroStatusBadge(props: { status: HomeHeroStatus }) {
  const tone = heroToneForStatus(props.status);
  return (
    <span className={`guard-hero-badge guard-hero-badge--${tone}`}>
      <i aria-hidden="true" />
      {HERO_BADGE_LABELS[props.status]}
    </span>
  );
}

export function heroMoodForStatus(status: HomeHeroStatus): HeroParticleMood {
  return heroToneForStatus(status);
}

export function HomeHero(props: {
  status: HomeHeroStatus;
  headline: string;
  subheadline: string;
  facts: string[];
  liveLabel: string;
  queue: HomeHeroQueueItem[];
  cta: ReactNode;
  secondaryCta?: ReactNode;
  onOpenRequest?: (requestId: string) => void;
}) {
  const dataStatus = heroToneForStatus(props.status);

  return (
    <section
      className="guard-hero guard-surface-in relative overflow-hidden rounded-2xl border border-white/10 p-5 text-white sm:p-6 lg:p-8"
      data-status={dataStatus}
      role="region"
      aria-label="Protection status"
    >
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_380px] lg:items-center">
        <div className="relative min-w-0 space-y-5">
          <div className="guard-hero-label flex flex-wrap items-center gap-2">
            <SectionLabel>Protection status</SectionLabel>
            <HeroStatusBadge status={props.status} />
          </div>
          <div className="max-w-2xl">
            <h1 className="guard-hero-title text-3xl font-semibold tracking-tight text-white sm:text-4xl">{props.headline}</h1>
            <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-white/75">{props.subheadline}</p>
          </div>
          {props.queue.length > 0 ? (
            <ul className="rounded-xl border border-white/15 bg-white/[0.08] p-1" aria-label="Actions waiting for review">
              {props.queue.map((item) => {
                const content = (
                  <>
                    <span className="inline-flex h-2 w-2 shrink-0 rounded-full bg-[#ffd58a]" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-sm text-white">
                      <strong className="font-semibold">{item.app}</strong> {item.what}
                    </span>
                    <span className="shrink-0 text-xs text-white/65">{item.when}</span>
                  </>
                );
                const onOpenRequest = props.onOpenRequest;
                return (
                  <li key={item.requestId}>
                    {onOpenRequest ? (
                      <button
                        type="button"
                        onClick={() => onOpenRequest(item.requestId)}
                        className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left transition-colors hover:bg-white/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60"
                      >
                        {content}
                        <HiMiniChevronRight className="h-4 w-4 shrink-0 text-white/50" aria-hidden="true" />
                      </button>
                    ) : (
                      <div className="flex w-full items-center gap-3 rounded-lg px-3 py-2">{content}</div>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : null}
          <div className="guard-hero-ctas flex flex-wrap gap-3">
            {props.cta}
            {props.secondaryCta}
          </div>
          {props.facts.length > 0 ? (
            <ul className="flex flex-wrap gap-x-6 gap-y-2 pt-1 text-sm text-white/75">
              {props.facts.map((fact) => (
                <li key={fact} className="guard-hero-fact">
                  {fact}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <div className="relative mx-auto w-full max-w-[380px] lg:max-w-none">
          <HeroParticleLogo mood={heroMoodForStatus(props.status)} finish="white" />
          <p className="guard-hero-live" aria-hidden="true">
            <i />
            <span>{props.liveLabel}</span>
          </p>
        </div>
      </div>
    </section>
  );
}
