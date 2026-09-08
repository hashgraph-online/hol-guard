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

const provingChecks = PROTECTION_CHECK_IDS.map((checkId) => ({
  check_id: checkId,
  status: checkId === "daemon" ? "pass" : "unknown",
  reason_code: checkId === "daemon" ? "daemon_healthy" : "proof_unavailable",
}));

const failedChecks = PROTECTION_CHECK_IDS.map((checkId) => ({
  check_id: checkId,
  status: checkId === "harness_hooks" ? "fail" : "pass",
  reason_code: checkId === "harness_hooks" ? "hooks_verification_failed" : `${checkId}_verified`,
}));

const untrustedApp = {
  harness: "codex",
  state: "protected",
  label: "Untrusted protected label",
  detail: "Untrusted detail",
  evidence_gap: false,
  reason_codes: ["untrusted"],
  checks: provingChecks,
};

const provingSnapshot = {
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
    checks: provingChecks,
    apps: [untrustedApp],
  },
};

function snapshotForState(state: ProtectionState) {
  if (state === "degraded") {
    const app = {
      ...untrustedApp,
      state: "degraded",
      label: "Untrusted degraded label",
      checks: failedChecks,
      reason_codes: failedChecks.map((check) => check.reason_code),
    };
    return {
      ...provingSnapshot,
      protection_health: {
        ...provingSnapshot.protection_health,
        state: "degraded",
        label: "Untrusted degraded label",
        checks: failedChecks,
        reason_codes: failedChecks.map((check) => check.reason_code),
        apps: [app],
      },
    };
  }
  const checks = PROTECTION_CHECK_IDS.map((checkId) => ({
    check_id: checkId,
    status: state === "partial" && checkId === "decision_stream" ? "unknown" : "pass",
    reason_code: `${checkId}_${state}`,
  }));
  const app = {
    ...untrustedApp,
    state: "degraded",
    label: "Untrusted degraded label",
    checks,
    reason_codes: checks.map((check) => check.reason_code),
  };
  return {
    ...provingSnapshot,
    protection_health: {
      ...provingSnapshot.protection_health,
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
  snapshot: ReturnType<typeof snapshotForState> | typeof provingSnapshot = provingSnapshot,
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
    else if (path.endsWith("/daemon/repair")) {
      body = { repaired: true, cleared: ["locator", "daemon_state"] };
    } else if (/\/harnesses\/[^/]+\/repair$/.test(path)) {
      body = {
        harness: "codex",
        action: "repair",
        dry_run: false,
        steps: [],
        managed_install: provingSnapshot.managed_installs[0],
      };
    } else if (path.endsWith("/protection/repair")) {
      body = {
        repaired: true,
        repair_scope: "local_integrity",
        check_ids: ["policy_engine", "rule_packs", "tamper_checks"],
        message: "Integrity protection restored.",
      };
    }
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

test("startup proving snapshot shows checking instead of degraded", async ({ page }, testInfo) => {
  await mountProtectionFixture(page, provingSnapshot);
  await page.goto(`/?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Checking protection" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Protection is degraded" })).toHaveCount(0);
  await expect(page.getByText("Untrusted protected label")).toHaveCount(0);

  await page.goto(`/protect?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Checking app protection" })).toBeVisible();
  await expect(page.getByLabel("Protection status").getByText("Checking", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Protection status").getByText("Degraded", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Your apps are covered")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Repair protection" })).toHaveCount(0);

  await page.goto(`/apps/codex?tab=settings&${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Checking Codex protection" })).toBeVisible();
  await expect(page.getByText("Codex protection is degraded")).toHaveCount(0);
  await expect(page.getByText("Codex is protected")).toHaveCount(0);

  await page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("button", { name: "Apps" }).click();
  await page.waitForURL(/\/protect/);
  await expect(page.getByRole("heading", { name: "Checking app protection" })).toBeVisible();

  await page.screenshot({ path: testInfo.outputPath("protection-health-checking.png"), fullPage: true });
});

test("failed protection checks still render as degraded", async ({ page }, testInfo) => {
  await mountProtectionFixture(page, snapshotForState("degraded"));
  await page.goto(`/?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Protection is degraded" })).toBeVisible();

  await page.goto(`/protect?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "App protection is degraded" })).toBeVisible();
  await expect(page.getByLabel("Protection status").getByText("Degraded", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Repair protection" })).toHaveCount(1);

  await page.goto(`/apps/codex?tab=settings&${DAEMON}`);
  await expect(page.getByRole("heading", { name: "Codex protection is degraded" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("protection-health-desktop.png"), fullPage: true });
});

test("degraded protection copy remains visible on mobile", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mountProtectionFixture(page, snapshotForState("degraded"));
  await page.goto(`/protect?${DAEMON}`);
  await expect(page.getByRole("heading", { name: "App protection is degraded" })).toBeVisible();
  await expect(page.getByLabel("Protection status").getByText("Degraded", { exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("protection-health-mobile.png"), fullPage: true });
});

test("one inline action repairs failed protection checks without leaving Protect", async ({ page }) => {
  const snapshot = snapshotForState("partial");
  snapshot.protection_health.checks = snapshot.protection_health.checks.map((check) =>
    check.check_id === "rule_packs" ? { ...check, status: "fail" as const } : check
  );
  await mountProtectionFixture(page, snapshot);
  await page.goto(`/protect?${DAEMON}`);

  await page.getByRole("button", { name: "Repair protection" }).click();

  await expect(page).toHaveURL(/\/protect/);
  await expect(page.getByRole("heading", { name: "App protection is degraded" })).toBeVisible();
  await expect(page.getByText("Command evidence still needs repair.")).toBeVisible();
  await expect(page.getByText("Guard attempts evidence-store recovery during repair.")).toBeVisible();
  await expect(page.getByRole("link", { name: "Open diagnostics" })).toHaveCount(0);
  await expect(page.locator("#protection-recovery").getByRole("link", { name: /settings/i })).toHaveCount(0);
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
