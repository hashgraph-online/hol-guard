import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import { guardActionActivityCopy, guardActionDisposition } from "./guard-action";
import { isConnectableAppHarness } from "./apps/harness-setup-target";
import type {
  GuardRuntimeSnapshot,
  GuardReceipt,
  GuardManagedInstall,
  GuardProtectionState,
} from "./guard-types";

export const safeLocalStorage = {
  getItem(key: string): string | null {
    try {
      return typeof window !== "undefined" ? window.localStorage.getItem(key) : null;
    } catch {
      return null;
    }
  },
  setItem(key: string, value: string): void {
    try {
      if (typeof window !== "undefined") {
        window.localStorage.setItem(key, value);
      }
    } catch {
      return;
    }
  },
};

export const STREAK_MILESTONE_MESSAGES: Record<number, string> = {
  7: "One week of Guard activity on this machine.",
  14: "Two weeks of consistent Guard coverage.",
  30: "A full month of daily Guard coverage.",
};

export function resolveCloudUpsellVisible(
  pendingCount: number,
  cloudState: GuardRuntimeSnapshot["cloud_state"]
): boolean {
  if (pendingCount > 0) return false;
  return cloudState === "local_only";
}

export function buildEmptyStateCopy(): { title: string; body: string; installHint: string } {
  return {
    title: "No apps connected",
    body: "Connect an AI app so Guard can start protecting it. Guard works with Codex, Claude Code, Cursor, Grok, Hermes, Kimi, and more.",
    installHint: "hol-guard apps connect <app>",
  };
}

export function redactHomeArtifactLabel(value: string | null | undefined): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    return "a local action";
  }
  const trimmed = value.trim();
  if (
    trimmed.includes("/") ||
    trimmed.includes("\\") ||
    trimmed.includes("~") ||
    trimmed.includes(":") ||
    trimmed.length > 48
  ) {
    return "a local action";
  }
  return trimmed;
}

export function buildRecentProtectionCopy(receipt: GuardReceipt): string {
  return guardActionActivityCopy(
    receipt.policy_decision,
    harnessDisplayName(receipt.harness),
    redactHomeArtifactLabel(receipt.artifact_name),
  );
}

export function resolveHomeQueuedCount(input: {
  pendingCount: number | null;
  requestCount: number | null;
}): number {
  return Math.max(input.pendingCount ?? 0, input.requestCount ?? 0);
}

export function deriveHomeState(input: {
  hasActiveInstalls: boolean;
  hasObservedHarnesses: boolean;
  queuedCount: number;
  watchedAppsCount: number;
  protectionState: GuardProtectionState | "checking";
}): {
  heroStatus: "clear" | "needs_review" | "setup_gap" | "partial" | "degraded" | "checking";
  headline: string;
  subheadline: string;
  ctaLabel: string;
  ctaTarget: "inbox" | "protect" | "evidence";
} {
  const { hasActiveInstalls, hasObservedHarnesses, protectionState, queuedCount, watchedAppsCount } = input;

  if (queuedCount > 0) {
    return {
      heroStatus: "needs_review",
      headline: queuedCount === 1 ? "1 action needs review" : `${queuedCount} actions need review`,
      subheadline: "Guard paused an action for your decision. Review it, then choose whether to allow or block it.",
      ctaLabel: "Review now",
      ctaTarget: "inbox",
    };
  }

  if (!hasActiveInstalls && !hasObservedHarnesses) {
    return {
      heroStatus: "setup_gap",
      headline: "Guard is ready",
      subheadline: "Connect your first AI app so Guard can start protecting it.",
      ctaLabel: "Open Protect",
      ctaTarget: "protect",
    };
  }

  if (!hasActiveInstalls && hasObservedHarnesses) {
    return {
      heroStatus: "setup_gap",
      headline: "Finish setup",
      subheadline: "Guard detected apps but they need setup to be fully protected.",
      ctaLabel: "Open Protect",
      ctaTarget: "protect",
    };
  }

  if (protectionState === "checking") {
    return {
      heroStatus: "checking",
      headline: "Checking protection",
      subheadline: "Guard is confirming local protection. This takes a moment.",
      ctaLabel: "Open Protect",
      ctaTarget: "protect",
    };
  }

  if (protectionState === "degraded") {
    return {
      heroStatus: "degraded",
      headline: "Protection is degraded",
      subheadline: "Guard is running, but one or more required protection checks failed or remain unproven.",
      ctaLabel: "Review protection",
      ctaTarget: "protect",
    };
  }

  if (protectionState === "partial") {
    return {
      heroStatus: "partial",
      headline: "Protection is partial",
      subheadline: "Core protection passes, but complete decision-stream evidence is not available.",
      ctaLabel: "Review protection",
      ctaTarget: "protect",
    };
  }

  return {
    heroStatus: "clear",
    headline: "All clear",
    subheadline: `Guard is watching your AI work. ${watchedAppsCount} app${watchedAppsCount !== 1 ? "s" : ""} protected. Nothing needs you right now.`,
    ctaLabel: "View history",
    ctaTarget: "evidence",
  };
}

export function buildDailyStory(
  receipts: GuardReceipt[],
  queuedCount: number
): { title: string; body: string; stats?: { label: string; value: number }[] } | null {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayReceipts = receipts.filter((r) => new Date(r.timestamp) >= today);
  const allowedToday = todayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length;
  const blockedToday = todayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length;
  const reviewedToday = todayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed").length;

  if (queuedCount > 0) {
    const actionText = queuedCount === 1 ? "1 action is" : `${queuedCount} actions are`;
    const pronoun = queuedCount === 1 ? "it" : "them";
    return {
      title: "Needs your attention",
      body: `${actionText} waiting for review. Guard paused ${pronoun} to keep you safe.`,
      stats: [{ label: "pending review", value: queuedCount }],
    };
  }

  if (allowedToday + blockedToday + reviewedToday > 0) {
    const clauses: string[] = [];
    if (allowedToday > 0) clauses.push(`allowed ${allowedToday} action${allowedToday !== 1 ? "s" : ""}`);
    if (blockedToday > 0) clauses.push(`blocked ${blockedToday}`);
    if (reviewedToday > 0) clauses.push(`sent ${reviewedToday} for review`);
    const story = clauses.length > 1
      ? `${clauses.slice(0, -1).join(", ")} and ${clauses[clauses.length - 1]}`
      : clauses[0];
    return {
      title: "Today so far",
      body: `Guard ${story}.`,
      stats: [
        ...(allowedToday > 0 ? [{ label: "allowed", value: allowedToday }] : []),
        ...(blockedToday > 0 ? [{ label: "blocked", value: blockedToday }] : []),
        ...(reviewedToday > 0 ? [{ label: "review", value: reviewedToday }] : []),
      ],
    };
  }

  if (receipts.length > 0) {
    const last = receipts[0];
    return {
      title: "All quiet",
      body: `No new activity today. Last decision was ${formatRelativeTime(last.timestamp)}.`,
    };
  }

  return null;
}

export function computeStreak(receipts: GuardReceipt[]): number {
  if (receipts.length === 0) return 0;
  const sortedByTime = [...receipts].sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));
  const mostRecent = new Date(sortedByTime[0].timestamp);
  const now = new Date();
  const diffHours = (now.getTime() - mostRecent.getTime()) / (1000 * 60 * 60);
  if (diffHours > 48) return 0;

  const dates = new Set(receipts.map((r) => new Date(r.timestamp).toDateString()));
  const sortedDates = Array.from(dates).sort((a, b) => +new Date(b) - +new Date(a));
  let streak = 0;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  let checkDate = new Date(today);
  for (const dateStr of sortedDates) {
    const d = new Date(dateStr);
    d.setHours(0, 0, 0, 0);
    if (d.getTime() === checkDate.getTime()) {
      streak++;
      checkDate.setDate(checkDate.getDate() - 1);
    } else if (d.getTime() < checkDate.getTime()) {
      break;
    }
  }
  return streak;
}

export function resolveNewAppDiscoveries(
  managedInstalls: GuardManagedInstall[],
  observedHarnesses: string[]
): string[] {
  const activeHarnesses = new Set(managedInstalls.filter((i) => isConnectableAppHarness(i.harness)).map((i) => i.harness));
  return observedHarnesses.filter((h) => isConnectableAppHarness(h) && !activeHarnesses.has(h));
}
