import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";
import { PROTECTION_CHECK_IDS } from "../src/protection-health";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
type ProtectionState = "protected" | "partial" | "degraded";

const degradedChecks = PROTECTION_CHECK_IDS.map((checkId) => ({
  check_id: checkId,
  status: checkId === "daemon" ? "pass" : "unknown",
  reason_code: checkId === "daemon" ? "daemon_healthy" : "proof_unavailable",
}));

const degradedApp = {
  harness: "codex",
  state: "protected",
  label: "Untrusted protected label",
  detail: "Untrusted detail",
  evidence_gap: false,
  reason_codes: ["untrusted"],
  checks: degradedChecks,
};

const degradedSnapshot = {
  ...freeStateSnapshot,
  headline_state: "degraded",
  headline_label: "Degraded",
  headline_detail: "One or more required protection checks failed or remain unproven.",
  managed_installs: [{
    harness: "codex",
    active: true,
    workspace: null,
    manifest: {},
    updated_at: "2026-07-19T12:00:00+00:00",
  }],
  protection_health: {
    schema_version: "guard.protection-health.v1",
    state: "protected",
    label: "Untrusted protected label",
    detail: "Untrusted detail",
    evidence_gap: false,
    reason_codes: ["untrusted"],
    checks: degradedChecks,
    apps: [degradedApp],
  },
};

function snapshotForState(state: ProtectionState) {
  if (state === "degraded") return degradedSnapshot;
  const checks = PROTECTION_CHECK_IDS.map((checkId) => ({
    check_id: checkId,
    status: state === "partial" && checkId === "decision_stream" ? "unknown" : "pass",
    reason_code: `${checkId}_${state}`,
  }));
  const app = {
    ...degradedApp,
    state: "degraded",
    label: "Untrusted degraded label",
    checks,
    reason_codes: checks.map((check) => check.reason_code),
  };
  return {
    ...degradedSnapshot,
    protection_health: {
      ...degradedSnapshot.protection_health,
      state: "degraded",
      label: "Untrusted degraded label",
      checks,
      reason_codes: checks.map((check) => check.reason_code),
      apps: [app],
    },
  };
}

async function mountProtectionFixture(
  page: Page,
  snapshot: ReturnType<typeof snapshotForState> = degradedSnapshot,
): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.includes("/initialize")) body = { auth_token: "e2e-protection-token" };
    else if (path.endsWith("/runtime")) body = snapshot;
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/command-activity/events")) {
      await route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
      return;
    } else if (path.endsWith("/command-activity/analytics")) {
      body = {
        schema_version: "guard.command-activity-api.v1",
        window: { from: "2026-07-19", through: "2026-07-19", days: 1 },
        scope: { dimension: null, dimension_value: null },
        commands_checked: 0,
        trend: [],
        dimensions: {},
        dimension_breakdowns_scope: "global",
        feedback: [],
        health: { status: "healthy", dropped_events: 0, persistence_errors: 0, last_error_class: null, last_error_at: null },
      };
    } else if (path.endsWith("/command-extensions")) {
      body = { schema_version: 2, source: "built-in", items: [], next_cursor: null };
    } else if (path.endsWith("/command-activity")) {
      body = { schema_version: "guard.command-activity-api.v1", items: [], next_cursor: null };
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

test("unproven checks clamp server and install claims across protection views", async ({ page }, testInfo) => {
  await mountProtectionFixture(page);
  await page.goto(`/?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Protection is degraded" })).toBeVisible();
  await expect(page.getByText("Untrusted protected label")).toHaveCount(0);

  await page.goto(`/protect?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "App protection is degraded" })).toBeVisible();
  await expect(page.getByLabel("Protection status").getByText("Degraded", { exact: true })).toBeVisible();
  await expect(page.getByText("Your apps are covered")).toHaveCount(0);

  await page.goto(`/apps/codex?tab=settings&${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Codex protection is degraded" })).toBeVisible();
  await expect(page.getByText("Installed", { exact: true })).toBeVisible();
  await expect(page.getByText("Codex is protected")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("protection-health-desktop.png"), fullPage: true });
});

test("degraded protection copy remains visible on mobile", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mountProtectionFixture(page);
  await page.goto(`/protect?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "App protection is degraded" })).toBeVisible();
  await expect(page.getByLabel("Protection status").getByText("Degraded", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("protection-health-mobile.png"), fullPage: true });
});

for (const expected of [
  { state: "protected", heading: "All clear", badge: "Protected" },
  { state: "partial", heading: "Protection is partial", badge: "Partially protected" },
] as const) {
  test(`Home derives ${expected.state} from checks instead of server copy`, async ({ page }, testInfo) => {
    await mountProtectionFixture(page, snapshotForState(expected.state));
    await page.goto(`/?${DAEMON}`);
    await expect(page.getByRole("heading", { name: expected.heading })).toBeVisible();
    await expect(page.getByText(expected.badge, { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Untrusted degraded label")).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath(`protection-health-${expected.state}.png`), fullPage: true });
  });
}
