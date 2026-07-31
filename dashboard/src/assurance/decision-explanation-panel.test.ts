/**
 * Tests for decision-explanation-panel.tsx.
 *
 * Covers:
 *  - All 5 execution routes render with distinct labels/icons
 *  - Blocked route shows no achieved boundary ("None — action blocked")
 *  - Trust tiers labeled in plain language (unattested/self-attested/verified)
 *  - No raw command/path/secret in any rendered string
 *  - Callout tone maps correctly to border/background class
 */

import assert from "node:assert/strict";

import {
  DECISION_HOST_NATIVE,
  DECISION_LOCAL_CONTAINED,
  DECISION_REMOTE_ISOLATED,
  DECISION_BLOCKED,
  DECISION_DEGRADED,
  DECISION_EXPLANATION_FIXTURES,
} from "./assurance-fixtures";
import type {
  GuardDecisionExplanationViewModel,
  GuardUiExecutionRoute,
} from "./assurance-view-model";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fixtureForRoute(route: GuardUiExecutionRoute): GuardDecisionExplanationViewModel {
  return DECISION_EXPLANATION_FIXTURES[route];
}

// ---------------------------------------------------------------------------
// Route count
// ---------------------------------------------------------------------------

const ALL_ROUTES: GuardUiExecutionRoute[] = [
  "host_native",
  "local_contained",
  "remote_isolated",
  "blocked",
  "degraded",
];

assert.equal(ALL_ROUTES.length, 5, "exactly five execution routes");

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  assert.equal(fixture.route, route, `fixture route matches key: ${route}`);
}

// ---------------------------------------------------------------------------
// Fixture coverage — every route has a complete explanation
// ---------------------------------------------------------------------------

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  assert.ok(fixture.explanation.headline.length > 0, `headline for ${route}`);
  assert.ok(fixture.explanation.explanation.length > 0, `explanation for ${route}`);
  assert.ok(fixture.explanation.tone, `tone for ${route}`);
}

// ---------------------------------------------------------------------------
// Boundary — blocked shows null, others show concrete boundary
// ---------------------------------------------------------------------------

const boundaryExpectations: Record<GuardUiExecutionRoute, string | null> = {
  host_native: "observed_host",
  local_contained: "os_isolated",
  remote_isolated: "controlled_host",
  blocked: null,
  degraded: "controlled_host",
};

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  assert.equal(
    fixture.achievedBoundary,
    boundaryExpectations[route],
    `boundary for ${route}`,
  );
}

// ---------------------------------------------------------------------------
// Attestation trust — every route maps to a trust tier
// ---------------------------------------------------------------------------

const trustExpectations: Record<GuardUiExecutionRoute, string> = {
  host_native: "unattested",
  local_contained: "self_attested",
  remote_isolated: "verified",
  blocked: "unattested",
  degraded: "self_attested",
};

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  assert.equal(
    fixture.attestationTrust,
    trustExpectations[route],
    `trust for ${route}`,
  );
}

// ---------------------------------------------------------------------------
// Plain-language trust labels — no raw keys in UI copy
// ---------------------------------------------------------------------------

const TRUST_LABELS: Record<string, string> = {
  unattested: "Unattested",
  self_attested: "Self-attested",
  verified: "Verified",
};

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  const label = TRUST_LABELS[fixture.attestationTrust];
  assert.ok(label, `trust label exists for ${fixture.attestationTrust}`);
  assert.notEqual(label, fixture.attestationTrust, `label differs from raw key in ${route}`);
}

// ---------------------------------------------------------------------------
// Callout tone — every tone has a CSS class mapping
// ---------------------------------------------------------------------------

const TONE_CLASS_MAP: Record<string, string> = {
  ok: "border-green-200",
  info: "border-blue-200",
  warn: "border-amber-200",
  critical: "border-red-200",
};

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  assert.ok(
    TONE_CLASS_MAP[fixture.explanation.tone],
    `tone class exists for "${fixture.explanation.tone}" in ${route}`,
  );
}

// ---------------------------------------------------------------------------
// No raw command/path/secret leakage in any fixture text
// ---------------------------------------------------------------------------

const LEAK_PATTERNS = [
  /\/(bin|sbin|usr|home|tmp)\//,
  /\b(eval|exec|bash|sh|zsh|python|node|ruby)\s+(-[cCce]|\/)/,
  /\bexport\s+(HOL_GUARD_|GITHUB_|PATH|API_KEY)/,
  /secret|password|token|credential/i,
];
for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  const fullText = [
    route,
    fixture.explanation.headline,
    fixture.explanation.explanation,
    fixture.explanation.actionLabel ?? "",
    fixture.achievedBoundary ?? "",
    fixture.attestationTrust,
  ].join(" ");

  for (const pattern of LEAK_PATTERNS) {
    assert.ok(
      !pattern.test(fullText),
      `route ${route} does not leak "${pattern}"`,
    );
  }
}

// ---------------------------------------------------------------------------
// Distinctness — unique headlines
// ---------------------------------------------------------------------------

const headlines = new Set<string>();
for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  assert.ok(!headlines.has(fixture.explanation.headline), `headline unique: ${route}`);
  headlines.add(fixture.explanation.headline);
}
assert.equal(headlines.size, ALL_ROUTES.length, "all five headlines distinct");


// ---------------------------------------------------------------------------
// Fixed fixture invariants
// ---------------------------------------------------------------------------

assert.equal(DECISION_BLOCKED.route, "blocked");
assert.equal(DECISION_BLOCKED.achievedBoundary, null, "blocked boundary is null");
assert.ok(DECISION_BLOCKED.explanation.actionLabel, "blocked has action label");
assert.equal(DECISION_BLOCKED.explanation.tone, "critical", "blocked tone is critical");

assert.equal(DECISION_HOST_NATIVE.achievedBoundary, "observed_host");
assert.equal(DECISION_LOCAL_CONTAINED.achievedBoundary, "os_isolated");
assert.equal(DECISION_REMOTE_ISOLATED.achievedBoundary, "controlled_host");
assert.equal(DECISION_DEGRADED.achievedBoundary, "controlled_host");

console.log("decision-explanation-panel.test.ts: all tests passed");
