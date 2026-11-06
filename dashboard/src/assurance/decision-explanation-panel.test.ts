/**
 * Tests for decision-explanation-panel.tsx.
 *
 * Exercises the component's actual mapping functions and data against
 * the five execution routes, ensuring label/URL/class outputs match
 * expectations — not just a parallel copy of the same data.
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
  GuardUiAttestationTrust,
  GuardUiBoundary,
  GuardUiExecutionRoute,
} from "./assurance-view-model";
import {
  BOUNDARY_LABELS,
  TRUST_LABELS,
  calloutBodyClass,
  routeIconClass,
  routeLabel,
  trustToneClass,
} from "./decision-explanation-panel";

const ALL_ROUTES: GuardUiExecutionRoute[] = [
  "host_native",
  "local_contained",
  "remote_isolated",
  "blocked",
  "degraded",
];

function fixtureForRoute(
  route: GuardUiExecutionRoute,
): GuardDecisionExplanationViewModel {
  return DECISION_EXPLANATION_FIXTURES[route];
}

// ---------------------------------------------------------------------------
// routeLabel — exercises the component's actual switch
// ---------------------------------------------------------------------------

const ROUTE_LABELS: Record<GuardUiExecutionRoute, string> = {
  host_native: "Host",
  local_contained: "Local Contained",
  remote_isolated: "Remote Isolated",
  blocked: "Blocked",
  degraded: "Degraded",
};

for (const route of Object.keys(ROUTE_LABELS) as GuardUiExecutionRoute[]) {
  assert.equal(
    routeLabel(route),
    ROUTE_LABELS[route],
    `routeLabel("${route}")`,
  );
}

const labelValues = Object.values(ROUTE_LABELS);
assert.equal(new Set(labelValues).size, 5, "all five route labels are distinct");

// ---------------------------------------------------------------------------
// routeIconClass — exercises the component's actual if-chain
// ---------------------------------------------------------------------------

assert.equal(
  routeIconClass("blocked"),
  "text-red-500",
  "blocked → red icon",
);
assert.equal(
  routeIconClass("degraded"),
  "text-amber-500",
  "degraded → amber icon",
);
assert.equal(
  routeIconClass("host_native"),
  "text-slate-500",
  "host_native → slate icon",
);
assert.equal(
  routeIconClass("local_contained"),
  "text-green-600",
  "local_contained → green icon",
);
assert.equal(
  routeIconClass("remote_isolated"),
  "text-green-600",
  "remote_isolated → green icon",
);

// ---------------------------------------------------------------------------
// BOUNDARY_LABELS — exercises the component's actual mapping
// ---------------------------------------------------------------------------

const EXPECTED_BOUNDARIES: Record<GuardUiBoundary, string> = {
  observed_host: "Observed on host",
  controlled_host: "Controlled host",
  os_isolated: "OS-isolated",
  hardware_isolated: "Hardware-isolated",
};

for (const [boundary, expected] of Object.entries(EXPECTED_BOUNDARIES) as [
  GuardUiBoundary,
  string,
][]) {
  assert.equal(
    BOUNDARY_LABELS[boundary],
    expected,
    `BOUNDARY_LABELS["${boundary}"]`,
  );
}

// ---------------------------------------------------------------------------
// Trust — fixture data maps to TRUST_LABELS (no raw key leakage)
// ---------------------------------------------------------------------------

const TRUST_FIXTURES: Record<GuardUiExecutionRoute, GuardUiAttestationTrust> = {
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
    TRUST_FIXTURES[route],
    `fixture trust for ${route}`,
  );

  const entry = TRUST_LABELS[fixture.attestationTrust];
  assert.ok(entry, `TRUST_LABELS has entry for ${fixture.attestationTrust}`);
  assert.ok(entry.label.length > 0, `trust label is non-empty for ${fixture.attestationTrust}`);
  assert.notEqual(
    entry.label,
    fixture.attestationTrust,
    `trust label differs from raw key in ${route}`,
  );
}

// ---------------------------------------------------------------------------
// trustToneClass — exercises the component's actual mapping
// ---------------------------------------------------------------------------

assert.equal(
  trustToneClass("green"),
  "bg-green-100 text-green-700 border-green-200",
  "green → green badge",
);
assert.equal(
  trustToneClass("blue"),
  "bg-blue-100 text-blue-700 border-blue-200",
  "blue → blue badge",
);
assert.equal(
  trustToneClass("amber"),
  "bg-amber-100 text-amber-700 border-amber-200",
  "amber → amber badge",
);

// ---------------------------------------------------------------------------
// calloutBodyClass — exercises the component's actual mapping
// ---------------------------------------------------------------------------

assert.equal(
  calloutBodyClass("ok"),
  "border-green-200 bg-green-50/80",
  "ok → green callout",
);
assert.equal(
  calloutBodyClass("info"),
  "border-blue-200 bg-blue-50/80",
  "info → blue callout",
);
assert.equal(
  calloutBodyClass("warn"),
  "border-amber-200 bg-amber-50/80",
  "warn → amber callout",
);
assert.equal(
  calloutBodyClass("critical"),
  "border-red-200 bg-red-50/80",
  "critical → red callout",
);

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  const cls = calloutBodyClass(fixture.explanation.tone);
  assert.ok(cls.startsWith("border-"), `calloutBodyClass valid for "${fixture.explanation.tone}" in ${route}`);
}

// ---------------------------------------------------------------------------
// Boundary — blocked shows null, others show concrete boundary
// ---------------------------------------------------------------------------

const BOUNDARY_FIXTURES: Record<GuardUiExecutionRoute, GuardUiBoundary | null> = {
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
    BOUNDARY_FIXTURES[route],
    `boundary for ${route}`,
  );
}

assert.equal(
  DECISION_BLOCKED.achievedBoundary,
  null,
  "blocked boundary is null",
);

for (const route of ALL_ROUTES) {
  const fixture = fixtureForRoute(route);
  if (fixture.achievedBoundary !== null) {
    const label = BOUNDARY_LABELS[fixture.achievedBoundary];
    assert.ok(label.length > 0, `boundary label for ${fixture.achievedBoundary} in ${route}`);
  }
}

// ---------------------------------------------------------------------------
// No raw command/path/secret leakage
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
assert.ok(DECISION_BLOCKED.explanation.actionLabel, "blocked has action label");
assert.equal(DECISION_BLOCKED.explanation.tone, "critical", "blocked tone is critical");

assert.equal(DECISION_HOST_NATIVE.achievedBoundary, "observed_host");
assert.equal(DECISION_LOCAL_CONTAINED.achievedBoundary, "os_isolated");
assert.equal(DECISION_REMOTE_ISOLATED.achievedBoundary, "controlled_host");
assert.equal(DECISION_DEGRADED.achievedBoundary, "controlled_host");

console.log("decision-explanation-panel.test.ts: all tests passed");
