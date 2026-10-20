import assert from "node:assert/strict";
import type { GuardPolicyDecision } from "./guard-types";
import {
  buildRuleAttention,
  buildRulesHeroModel,
  buildRulesSpotlight,
  isBroadAllow,
  isStaleRule,
  policyRiskScore,
} from "./policy-rules-hero-model";
import { countPolicyRules } from "./policy-rules-overview-model";

function policy(overrides: Partial<GuardPolicyDecision>): GuardPolicyDecision {
  return {
    harness: "claude-code",
    scope: "workspace",
    action: "allow",
    source: "local",
    artifact_id: null,
    publisher: null,
    workspace: null,
    reason: null,
    updated_at: "2026-10-19T00:00:00Z",
    ...overrides,
  };
}

const now = new Date("2026-10-20T00:00:00Z");

assert.equal(isBroadAllow(policy({ scope: "global" })), true);
assert.equal(isBroadAllow(policy({ scope: "harness" })), true);
assert.equal(isBroadAllow(policy({ scope: "workspace" })), false);
assert.equal(isBroadAllow(policy({ scope: "global", action: "block" })), false);

assert.equal(isStaleRule(policy({ updated_at: "2026-01-01T00:00:00Z" }), now), true);
assert.equal(isStaleRule(policy({ updated_at: "2026-10-19T00:00:00Z" }), now), false);

const broad = policy({ scope: "global", artifact_id: "family:tool-action", reason: "broad" });
const narrow = policy({ scope: "artifact", artifact_id: "family:tool-action", reason: "narrow" });
assert.ok(policyRiskScore(broad) > policyRiskScore(narrow));

const attention = buildRuleAttention([broad, narrow, policy({ updated_at: "2026-01-01T00:00:00Z", reason: "old" })], now);
assert.equal(attention.broadAllows.length, 1);
assert.equal(attention.staleLocals.length, 1);

const spotlight = buildRulesSpotlight([narrow, broad]);
assert.equal(spotlight[0].reason, "broad");
assert.ok(spotlight.length <= 3);

// A broad allow must lead the shelf even when narrower rules outscore it.
const cloudBroad = policy({ scope: "global", source: "cloud-sync", artifact_id: "family:prompt", reason: "cloud-broad", updated_at: "2026-10-10T00:00:00Z" });
const loudLocal = (n: number) => policy({ scope: "publisher", artifact_id: "family:tool-action", reason: `loud-${n}`, updated_at: `2026-10-1${n}T00:00:00Z` });
const crowded = buildRulesSpotlight([loudLocal(1), loudLocal(2), loudLocal(3), cloudBroad]);
assert.equal(crowded[0].reason, "cloud-broad");

const empty = buildRulesHeroModel({
  counts: countPolicyRules([]),
  attention: { broadAllows: [], staleLocals: [] },
  protectionLabel: "Protected",
  cloudConnected: false,
  pendingCount: 0,
});
assert.equal(empty.tone, "setup");
assert.match(empty.headline, /asks before it repeats/);

const review = buildRulesHeroModel({
  counts: countPolicyRules([broad]),
  attention: { broadAllows: [broad], staleLocals: [] },
  protectionLabel: "Protected",
  cloudConnected: true,
  pendingCount: 2,
});
assert.equal(review.tone, "review");
assert.match(review.headline, /second look/);
assert.ok(review.facts.some((f) => f.includes("waiting in Inbox")));

const clear = buildRulesHeroModel({
  counts: countPolicyRules([narrow]),
  attention: { broadAllows: [], staleLocals: [] },
  protectionLabel: "Protected",
  cloudConnected: true,
  pendingCount: 0,
});
assert.equal(clear.tone, "clear");
assert.match(clear.headline, /repeat for you/);
assert.match(clear.subheadline, /choice you made once/);

const cloudOnly = buildRulesHeroModel({
  counts: countPolicyRules([policy({ source: "cloud-sync", scope: "workspace" })]),
  attention: { broadAllows: [], staleLocals: [] },
  protectionLabel: "Protected",
  cloudConnected: true,
  pendingCount: 0,
});
assert.match(cloudOnly.subheadline, /read-only here/);
assert.ok(!cloudOnly.subheadline.includes("choice you made once"));

console.log("policy-rules-hero-model.test.ts: all assertions passed");
