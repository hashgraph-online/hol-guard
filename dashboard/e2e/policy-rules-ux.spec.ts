import { test, expect, type Page } from "@playwright/test";
import {
  freeStateSnapshot,
  emptyReceiptsPayload,
  emptyInventoryPayload,
  defaultSettingsPayload,
} from "./fixture-states";

const DAEMON_PARAM = "?guardDaemon=http://127.0.0.1:4175";

const policiesPayload = {
  items: [
    {
      decision_id: 1,
      harness: "claude-code",
      scope: "workspace",
      artifact_id: "family:tool-action",
      workspace: "/work/shop-app",
      workspace_label: "shop-app",
      publisher: null,
      action: "allow",
      reason: "git push origin main",
      source: "local",
      updated_at: "2026-10-19T10:00:00Z",
      remembered_command: "git push origin main",
      source_receipt_id: "receipt-aaa111",
    },
    {
      decision_id: 2,
      harness: "codex",
      scope: "artifact",
      artifact_id: "family:tool-action",
      workspace: "/work/shop-app",
      workspace_label: "shop-app",
      publisher: null,
      action: "block",
      reason: "rm -rf build",
      source: "local",
      updated_at: "2026-10-18T10:00:00Z",
      remembered_command: "rm -rf build",
      source_receipt_id: "receipt-bbb222",
    },
    {
      decision_id: 4,
      harness: "codex",
      scope: "global",
      artifact_id: "family:tool-action",
      workspace: null,
      workspace_label: null,
      publisher: null,
      action: "allow",
      reason: "shell commands",
      source: "local",
      updated_at: "2026-10-19T09:00:00Z",
      remembered_command: "any shell command",
      source_receipt_id: "receipt-ddd444",
    },
    {
      decision_id: 5,
      harness: "omp",
      scope: "artifact",
      artifact_id: "omp:native-pretool:bash",
      artifact_hash: "guard-approval-context:v1:token",
      workspace: null,
      workspace_label: null,
      publisher: null,
      action: "allow",
      reason: "approved in review",
      source: "approval-gate",
      updated_at: "2026-10-19T08:00:00Z",
      remembered_command: "cd /work/shop-app && git status && rm -rf /tmp/build",
      source_receipt_id: "receipt-eee555",
    },
    {
      decision_id: 3,
      harness: "claude-code",
      scope: "workspace",
      artifact_id: "family:package-request",
      workspace: "/work/shop-app",
      workspace_label: "shop-app",
      publisher: null,
      action: "allow",
      reason: "npm install",
      source: "cloud-sync",
      updated_at: "2026-10-17T10:00:00Z",
      remembered_command: "npm install left-pad",
      source_receipt_id: "receipt-ccc333",
    },
  ],
  cloud_exceptions: [],
};

async function mount(page: Page) {
  await page.route("**/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.includes("/initialize")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ auth_token: "e2e-token-rules" }) });
      return;
    }
    if (path.includes("/runtime")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(freeStateSnapshot) });
      return;
    }
    if (path.endsWith("/policy") || path.includes("/policy/cloud")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(policiesPayload) });
      return;
    }
    if (path.includes("/receipts")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(emptyReceiptsPayload) });
      return;
    }
    if (path.includes("/settings")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(defaultSettingsPayload) });
      return;
    }
    if (path.includes("/inventory")) {
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(emptyInventoryPayload) });
      return;
    }
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({}) });
  });
}

test.describe("Rules & exceptions UX", () => {
  test("header, attention strip, list switch, inspector and bulk selection", async ({ page }) => {
    await mount(page);
    await page.goto(`/policy${DAEMON_PARAM}`);
    await expect(page.getByText("1 broad allow deserves a second look")).toBeVisible();
    await expect(page.getByText("Worth a second look").first()).toBeVisible();
    await expect(page.getByText(/Broad allow:/)).toBeVisible();
    await expect(page.getByText(/Guard will allow "git push origin main"/).first()).toBeVisible();
    await expect(page.getByText("Broad allow", { exact: true }).first()).toBeVisible();

    await expect(page.getByText(/cd \/work\/shop-app && git status && rm -rf \/tmp\/build/).first()).toBeVisible();
    await expect(page.getByText(/Guard will allow "cd \/work\/shop-app && git status && rm -rf \/tmp\/build" the next time Oh My Pi retries this exact action/)).toBeVisible();

    await page.getByRole("button", { name: /^Block/ }).click();
    await expect(page.getByText(/Showing 1 of 5 remembered rules/)).toBeVisible();
    await expect(page.getByText(/Guard will block "rm -rf build"/).first()).toBeVisible();

    await page.getByRole("button", { name: /^All actions/ }).click();
    await page.getByLabel(/Select rule git push origin main/).check();
    await page.getByLabel(/Select rule rm -rf build/).check();
    await expect(page.getByText("2 rules selected")).toBeVisible();
    await expect(page.getByRole("button", { name: "Remove selected" })).toBeVisible();

    await page.getByRole("button", { name: /Inspect rule cd \/work\/shop-app/ }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByRole("dialog").getByText("Exact action approved")).toBeVisible();
    await expect(page.getByRole("dialog").locator("pre")).toContainText("cd /work/shop-app && git status && rm -rf /tmp/build");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);

    await page.getByRole("button", { name: "Inspect rule git push origin main" }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByRole("dialog").getByText(/Guard will allow "git push origin main"/)).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await page.screenshot({ path: "e2e/policy-rules-ux-desktop.png", fullPage: true });
  });

  test("deep link opens cloud exceptions and empty search recovers", async ({ page }) => {
    await mount(page);
    await page.goto(`/policy${DAEMON_PARAM}#policy-view=cloud-exceptions`);
    await expect(page.getByText("Guard Cloud is not connected")).toBeVisible();
    await expect(page.getByText("Connect Guard Cloud to request an exception.")).toBeVisible();

    await page.getByRole("tab", { name: /Remembered rules/ }).click();
    await page.getByLabel("Search remembered rules").fill("no-such-rule-zzz");
    await expect(page.getByRole("heading", { name: "No rules match" })).toBeVisible();
    await page.getByRole("button", { name: "Clear search and filters" }).click();
    await expect(page.getByText(/Guard will allow "git push origin main"/).first()).toBeVisible();
  });

  test("mobile layout keeps header and rules reachable", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await mount(page);
    await page.goto(`/policy${DAEMON_PARAM}`);
    await expect(page.getByText("1 broad allow deserves a second look")).toBeVisible();
    await expect(page.getByText(/Guard will block "rm -rf build"/).first()).toBeVisible();
    await page.screenshot({ path: "e2e/policy-rules-ux-mobile.png", fullPage: true });
  });
});
