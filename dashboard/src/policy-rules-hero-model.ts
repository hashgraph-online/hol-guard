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

/**
 * The widest broad allow, for the one line the attention strip shows: a
 * global rule outranks a harness-scoped one whatever their risk scores are,
 * and the score only separates rules of the same reach.
 */
export function widestBroadAllow(policies: GuardPolicyDecision[]): GuardPolicyDecision | undefined {
  const breadth = (policy: GuardPolicyDecision) => (policy.scope === "global" ? 2 : policy.scope === "harness" ? 1 : 0);
  return [...policies].sort((a, b) => breadth(b) - breadth(a) || policyRiskScore(b) - policyRiskScore(a))[0];
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
      subheadline: "approve in Inbox and it lands here.",
      facts,
    };
  }
  if (attention.broadAllows.length > 0) {
    const n = attention.broadAllows.length;
    return {
      tone: "review",
      badge: "Worth a second look",
      headline: n === 1 ? "1 broad allow deserves a second look" : `${n} broad allows deserve a second look`,
      subheadline: "remove one and Guard asks again.",
      facts,
    };
  }
  const provenance =
    counts.local === 0 && counts.cloud > 0
      ? "read-only here — change them in Guard Cloud or their governing Extension."
      : "";
  return {
    tone: "clear",
    badge: "Memory is tidy",
    headline:
      counts.total === 1
        ? "1 decision Guard will repeat for you"
        : `${counts.total} decisions Guard will repeat for you`,
    subheadline: provenance,
    facts,
  };
}

export function heroCountsFrom(policies: readonly GuardPolicyDecision[]): PolicyRuleCounts {
  return countPolicyRules(policies.filter((p) => p.action === "allow" || p.action === "block"));
}
