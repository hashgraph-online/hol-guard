import { expect, test } from "@playwright/test";
import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  freeStateSnapshot,
} from "./fixture-states";

test("Apps lists harnesses without discarding package-tool evidence", async ({ page }) => {
  const items = ["codex", "bun", "npm", "guard-cli"].map((harness) => ({
    receipt_id: `receipt-${harness}`,
    harness,
    artifact_id: `artifact-${harness}`,
    artifact_hash: `hash-${harness}`,
    artifact_name: `Recorded ${harness} command`,
    policy_decision: "allow",
    capabilities_summary: "Local command",
    changed_capabilities: [],
    provenance_summary: `${harness} --version`,
    user_override: null,
    source_scope: null,
    timestamp: new Date().toISOString(),
  }));
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.includes("/initialize")) body = { auth_token: "e2e-app-origin-token" };
    else if (path.endsWith("/runtime")) body = freeStateSnapshot;
    else if (path.endsWith("/receipts")) body = { items };
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto("/evidence?view=apps&guardDaemon=http://127.0.0.1:4175");
  await expect(page.getByRole("heading", { name: "Apps", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /Codex.*1 actions/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Bun.*actions/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Npm.*actions/i })).toHaveCount(0);
  await page.screenshot({ path: "test-results/evidence-app-origins.png", fullPage: true });
  await page.goto("/evidence?view=actions&guardDaemon=http://127.0.0.1:4175");
  await expect(page.getByText("Recorded bun command", { exact: true }).first()).toBeVisible();
});
