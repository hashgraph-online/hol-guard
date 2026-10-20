import type { GuardPolicyDecision } from "./guard-types";
import { isCloudManagedPolicy, resolvePolicyMatcherFamily } from "./policy-workspace-helpers";
import { countPolicyRules, type PolicyRuleCounts } from "./policy-rules-overview-model";

export type RulesHeroTone = "clear" | "review" | "setup";

export interface RulesHeroModel {
  tone: RulesHeroTone;
  badge: string;
  headline: string;
  subheadline: string;
  facts: string[];
  liveLabel: string;
}

const RISKY_FAMILIES = new Set(["tool-action", "package-request", "mcp", "prompt-env-read"]);

export function policyRiskScore(policy: GuardPolicyDecision): number {
  let score = 0;
  if (policy.action === "allow") score += 2;
  if (policy.scope === "global") score += 4;
  else if (policy.scope === "harness") score += 3;
  else if (policy.scope === "publisher") score += 2;
  const family = resolvePolicyMatcherFamily(policy);
  if (family && RISKY_FAMILIES.has(family)) score += 2;
  if (!isCloudManagedPolicy(policy.source)) score += 1;
  return score;
}

export function isBroadAllow(policy: GuardPolicyDecision): boolean {
  return policy.action === "allow" && (policy.scope === "global" || policy.scope === "harness");
}

const STALE_DAYS = 90;

export function isStaleRule(policy: GuardPolicyDecision, now: Date): boolean {
  if (!policy.updated_at) return false;
  const updated = new Date(policy.updated_at).getTime();
  if (Number.isNaN(updated)) return false;
  return now.getTime() - updated > STALE_DAYS * 24 * 60 * 60 * 1000;
}

export interface RuleAttention {
  broadAllows: GuardPolicyDecision[];
  staleLocals: GuardPolicyDecision[];
}

export function buildRuleAttention(
  policies: readonly GuardPolicyDecision[],
  now: Date,
): RuleAttention {
  const remembered = policies.filter((p) => p.action === "allow" || p.action === "block");
  return {
    broadAllows: remembered.filter(isBroadAllow),
    staleLocals: remembered.filter((p) => !isCloudManagedPolicy(p.source) && isStaleRule(p, now)),
  };
}

/**
 * Spotlight picks: broad allows always lead (the hero calls them out by
 * name, so they must appear here), then highest risk score, then newest.
 */
export function buildRulesSpotlight(
  policies: readonly GuardPolicyDecision[],
): GuardPolicyDecision[] {
  const remembered = policies.filter((p) => p.action === "allow" || p.action === "block");
  const sorted = [...remembered].sort((a, b) => {
    const broadDelta = Number(isBroadAllow(b)) - Number(isBroadAllow(a));
    if (broadDelta !== 0) return broadDelta;
    const byRisk = policyRiskScore(b) - policyRiskScore(a);
    if (byRisk !== 0) return byRisk;
    return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
  });
  return sorted.slice(0, 3);
}

export function buildRulesHeroModel(input: {
  counts: PolicyRuleCounts;
  attention: RuleAttention;
  protectionLabel: string;
  cloudConnected: boolean;
  pendingCount: number;
}): RulesHeroModel {
  const { counts, attention } = input;
  const facts: string[] = [];
  facts.push(`${counts.local} on this device`);
  facts.push(input.cloudConnected ? `${counts.cloud} from Guard Cloud` : "Guard Cloud not connected");
  facts.push(`Protection: ${input.protectionLabel}`);
  if (input.pendingCount > 0) {
    facts.push(`${input.pendingCount} waiting in Inbox`);
  }

  if (counts.total === 0) {
    return {
      tone: "setup",
      badge: "Nothing remembered yet",
      headline: "Guard asks before it repeats anything",
      subheadline:
        "No decision is remembered on this device yet. The first time an app asks to do something new, Guard checks with you — approve it once and choose how broadly to remember it, and it lands here.",
      facts,
      liveLabel: "Asking every time",
    };
  }
  if (attention.broadAllows.length > 0) {
    const n = attention.broadAllows.length;
    return {
      tone: "review",
      badge: "Worth a second look",
      headline: n === 1 ? "1 broad allow deserves a second look" : `${n} broad allows deserve a second look`,
      subheadline:
        "These rules let an action through everywhere it matches — every project, or every time an app runs it. If one is wider than you meant, narrow or remove it below and Guard will ask again.",
      facts,
      liveLabel: `${counts.total} rules in force`,
    };
  }
  const provenance =
    counts.cloud === 0
      ? "Every rule below is a choice you made once, stated in plain language with where it came from and how to undo it."
      : counts.local === 0
        ? "Every rule below synced from Guard Cloud, stated in plain language. They are read-only here — change them in Guard Cloud or their governing Extension."
        : "Rules below mix choices you made on this device with rules synced from Guard Cloud. Each one says where it came from and how it can be changed.";
  return {
    tone: "clear",
    badge: "Memory is tidy",
    headline:
      counts.total === 1
        ? "1 decision Guard will repeat for you"
        : `${counts.total} decisions Guard will repeat for you`,
    subheadline: `${provenance} Nothing here widens itself — Guard only repeats what was approved.`,
    facts,
    liveLabel: `${counts.total} rules in force`,
  };
}

export function heroCountsFrom(policies: readonly GuardPolicyDecision[]): PolicyRuleCounts {
  return countPolicyRules(policies.filter((p) => p.action === "allow" || p.action === "block"));
}
