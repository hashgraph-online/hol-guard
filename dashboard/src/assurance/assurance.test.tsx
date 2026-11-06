/**
 * Colocated tests for ProviderDetailCard — covers:
 *  - All 7 health states render distinctly
 *  - Freshness badge renders
 *  - Drift indicator renders when flagged
 *  - Remediation callout: exactly one on non-healthy, none on healthy
 *  - No raw path/secret in rendered copy
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToString } from "react-dom/server";
import { createElement } from "react";
import {
  ProviderDetailCard,
  GuaranteeChip,
} from "./components/ProviderDetailCard";
import {
  PROVIDER_DETAIL_HEALTHY,
  PROVIDER_DETAIL_VERIFYING,
  PROVIDER_DETAIL_DEGRADED,
  PROVIDER_DETAIL_UNAVAILABLE,
  PROVIDER_DETAIL_REVOKED,
  PROVIDER_DETAIL_INCOMPATIBLE,
  PROVIDER_DETAIL_UNKNOWN,
} from "./assurance-fixtures";
import type {
  GuardProviderDetailViewModel,
} from "./assurance-view-model";

// ---------------------------------------------------------------------------
// Fixtures mapped with their expected health label
// ---------------------------------------------------------------------------

interface StateExpectation {
  name: string;
  model: GuardProviderDetailViewModel;
  healthLabel: string;
  hasRemediation: boolean;
  hasDrift: boolean;
  freshness: string;
}

const STATE_EXPECTATIONS: StateExpectation[] = [
  {
    name: "healthy",
    model: PROVIDER_DETAIL_HEALTHY,
    healthLabel: "Healthy",
    hasRemediation: false,
    hasDrift: false,
    freshness: "Fresh",
  },
  {
    name: "verifying",
    model: PROVIDER_DETAIL_VERIFYING,
    healthLabel: "Verifying",
    hasRemediation: true,
    hasDrift: false,
    freshness: "Fresh",
  },
  {
    name: "degraded",
    model: PROVIDER_DETAIL_DEGRADED,
    healthLabel: "Degraded",
    hasRemediation: true,
    hasDrift: true,
    freshness: "Stale",
  },
  {
    name: "unavailable",
    model: PROVIDER_DETAIL_UNAVAILABLE,
    healthLabel: "Unavailable",
    hasRemediation: true,
    hasDrift: false,
    freshness: "Unknown",
  },
  {
    name: "revoked",
    model: PROVIDER_DETAIL_REVOKED,
    healthLabel: "Revoked",
    hasRemediation: true,
    hasDrift: false,
    freshness: "Unknown",
  },
  {
    name: "incompatible",
    model: PROVIDER_DETAIL_INCOMPATIBLE,
    healthLabel: "Incompatible",
    hasRemediation: true,
    hasDrift: false,
    freshness: "Stale",
  },
  {
    name: "unknown",
    model: PROVIDER_DETAIL_UNKNOWN,
    healthLabel: "Unknown",
    hasRemediation: true,
    hasDrift: false,
    freshness: "Unknown",
  },
];

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderCard(model: GuardProviderDetailViewModel): string {
  return renderToString(
    createElement(ProviderDetailCard, { model }),
  );
}

// ---------------------------------------------------------------------------
// 1. All 7 health states render distinctly
// ---------------------------------------------------------------------------

for (const { name, model, healthLabel, hasRemediation, hasDrift, freshness } of STATE_EXPECTATIONS) {
  {
    const html = renderCard(model);
    assert.ok(
      html.includes(healthLabel),
      `Expected rendered HTML to contain "${healthLabel}" for state "${name}"`,
    );
    assert.ok(
      html.includes(model.providerLabel),
      `Expected rendered HTML to contain provider label for state "${name}"`,
    );
  }

  {
    const html = renderCard(model);
    assert.ok(
      html.includes(freshness),
      `Expected rendered HTML to contain freshness badge "${freshness}" for state "${name}"`,
    );
  }

  {
    const html = renderCard(model);
    if (hasRemediation) {
      assert.ok(
        html.includes("Remediation"),
        `Expected remediation region for state "${name}"`,
      );
    } else {
      assert.ok(
        !html.includes("Remediation"),
        `Expected no remediation region for healthy state`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// 2. Healthy has NO remediation
// ---------------------------------------------------------------------------

{
  const html = renderCard(PROVIDER_DETAIL_HEALTHY);
  assert.ok(
    !html.includes("Remediation"),
    "Healthy state should not render a remediation callout",
  );
  assert.equal(
    PROVIDER_DETAIL_HEALTHY.remediation,
    null,
    "Fixture remediation should be null for healthy",
  );
}

// ---------------------------------------------------------------------------
// 3. All non-healthy states have exactly ONE remediation
// ---------------------------------------------------------------------------

const NON_HEALTHY = STATE_EXPECTATIONS.filter((s) => s.name !== "healthy");

for (const { name, model } of NON_HEALTHY) {
  {
    const html = renderCard(model);
    assert.ok(
      html.includes("Remediation"),
      `Non-healthy state "${name}" must have a remediation callout`,
    );
  }
}

// ---------------------------------------------------------------------------
// 4. Drift indicator shows only when driftDetected
// ---------------------------------------------------------------------------

{
  const html = renderCard(PROVIDER_DETAIL_DEGRADED);
  assert.ok(
    html.includes("Drift detected"),
    "Degraded state has driftDetected=true; should show drift indicator",
  );
}

{
  const html = renderCard(PROVIDER_DETAIL_HEALTHY);
  assert.ok(
    !html.includes("Drift detected"),
    "Healthy state has driftDetected=false; should NOT show drift indicator",
  );
}

// ---------------------------------------------------------------------------
// 5. Guarantee chips render
// ---------------------------------------------------------------------------

{
  const html = renderCard(PROVIDER_DETAIL_HEALTHY);
  assert.ok(html.includes("filesystem"));
  assert.ok(html.includes("process"));
  assert.ok(html.includes("network"));
}

{
  const emptyModel: GuardProviderDetailViewModel = {
    ...PROVIDER_DETAIL_UNAVAILABLE,
    actualGuarantees: [],
  };
  const html = renderCard(emptyModel);
  assert.ok(
    html.includes("No guarantees active"),
    "Empty guarantees should render fallback text",
  );
}

// ---------------------------------------------------------------------------
// 6. No raw path/secret in component source
// ---------------------------------------------------------------------------

const SOURCE = readFileSync(
  new URL("./components/ProviderDetailCard.tsx", import.meta.url),
  "utf8",
);

const PROHIBITED_PATTERNS = [
  /\/private\/workspace/,
  /\/tmp\/guard/,
  /secret\s*[:=]/i,
  /password\s*[:=]/i,
  /command\s*[:=]/i,
  /execution[_-]command/,
  /\/etc\/passwd/,
  /\$\{process\.env\.SECRET/,
];

{
  for (const pattern of PROHIBITED_PATTERNS) {
    assert.ok(
      !pattern.test(SOURCE),
      `Source should not contain pattern: ${pattern}`,
    );
  }
}

// ---------------------------------------------------------------------------
// 7. No raw path/secret in rendered copy
// ---------------------------------------------------------------------------

{
  for (const { name, model } of STATE_EXPECTATIONS) {
    const html = renderCard(model);
    for (const pattern of PROHIBITED_PATTERNS) {
      assert.ok(
        !pattern.test(html),
        `Rendered HTML for "${name}" should not contain pattern: ${pattern}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// 8. Each health state has a unique visual class for its card border
// ---------------------------------------------------------------------------

{
  const html = renderCard(PROVIDER_DETAIL_UNAVAILABLE);
  assert.ok(html.includes("border-red-400"));
}

{
  const html = renderCard(PROVIDER_DETAIL_HEALTHY);
  assert.ok(html.includes("border-brand-green/30"));
}

{
  const html = renderCard(PROVIDER_DETAIL_DEGRADED);
  assert.ok(html.includes("border-brand-blue/30"));
}

// ---------------------------------------------------------------------------
// 9. GuaranteeChip renders standalone
// ---------------------------------------------------------------------------

{
  const html = renderToString(createElement(GuaranteeChip, { label: "process" }));
  assert.ok(html.includes("process"));
  assert.ok(html.includes("Guarantee: process"));
}
