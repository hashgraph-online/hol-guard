import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  paidStateSnapshot,
} from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const NOW = Date.parse("2026-10-24T12:00:00Z");

const worktrees = [
  { codebase_key: "a".repeat(64), worktree_key: "b".repeat(64), root: "/Users/dev/projects/storefront", stale: false, paused: false, last_scan_at_ms: NOW - 120_000 },
  { codebase_key: "c".repeat(64), worktree_key: "d".repeat(64), root: "/Users/dev/projects/billing-api", stale: false, paused: false, last_scan_at_ms: NOW - 3_600_000 },
  { codebase_key: "e".repeat(64), worktree_key: "f".repeat(64), root: "/Users/dev/projects/docs-site", stale: false, paused: true, last_scan_at_ms: null },
];

const runs = [
  { codebase_key: "a".repeat(64), worktree_key: "b".repeat(64), run_id: "run-1", state: "partial", trigger_kind: "file_change", error_code: null, finished_at_ms: NOW - 120_000 },
  { codebase_key: "c".repeat(64), worktree_key: "d".repeat(64), run_id: "run-2", state: "failed", trigger_kind: "feed_change", error_code: "feed_context_unavailable", finished_at_ms: NOW - 3_600_000 },
];

const assessments = [
  {
    codebase_key: "a".repeat(64),
    worktree_key: "b".repeat(64),
    run_id: "run-1",
    state: "partial",
    finished_at_ms: NOW - 120_000,
    coverage: {
      status: "partial",
      reasons: ["supply_chain_incomplete", "detector_not_run:secrets"],
      detectors: { supply_chain: "incomplete", secrets: "not_run" },
    },
    findings: [
      { finding_id: "f-1", severity: "critical", decision: "block", ecosystem: "npm", package_name: "minimist", package_version: "1.2.5", fix_version: "1.2.8", advisory_ids: ["GHSA-xvch-5gv4-984h", "CVE-2021-44906"] },
      { finding_id: "f-2", severity: "moderate", decision: "ask", ecosystem: "pypi", package_name: "requests", package_version: "2.25.0", fix_version: null, advisory_ids: [] },
    ],
  },
];

async function mountWorkspaceFindings(page: Page, actions: unknown[]): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/supply-chain/workspace-assessments/run")) {
      actions.push(request.postDataJSON());
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ run_id: "run-3" }) });
      return;
    }
    let body: unknown = {};
    if (path.endsWith("/supply-chain/workspace-assessments")) body = { worktrees, runs };
    else if (path.endsWith("/supply-chain/workspace-findings")) body = { worktrees, assessments };
    else if (path.endsWith("/initialize")) body = { auth_token: "e2e-workspace-findings-token" };
    else if (path.endsWith("/runtime")) body = paidStateSnapshot;
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/command-activity/events")) {
      await route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

for (const width of [390, 1280]) {
  test(`workspaces tab shows per-worktree status, coverage and findings at ${width}px`, async ({ page }, testInfo) => {
    const pageErrors: string[] = [];
    const actions: unknown[] = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    await mountWorkspaceFindings(page, actions);

    await page.goto(`/workspaces?${DAEMON}`);
    const storefront = page.getByRole("listitem", { name: "storefront" });
    await expect(storefront).toContainText("Partial coverage");
    await expect(storefront).toContainText("Some dependencies need registry data Guard does not have offline.");
    await expect(storefront).toContainText("Secret scanning is not part of this check yet.");
    await expect(storefront).toContainText("minimist");
    await expect(storefront).toContainText("1.2.8");
    await expect(storefront).toContainText("Blocked");
    await expect(storefront).toContainText("No fix yet");

    const billing = page.getByRole("listitem", { name: "billing-api" });
    await expect(billing).toContainText("Assessment failed");
    await expect(billing).toContainText("Guard could not read its cached advisories.");

    const docs = page.getByRole("listitem", { name: "docs-site" });
    await expect(docs).toContainText("Paused");
    await expect(docs.getByRole("button", { name: "Assess now" })).toBeDisabled();
    await expect(docs.getByRole("button", { name: "Resume" })).toBeVisible();

    await storefront.getByRole("button", { name: "Assess now" }).click();
    await expect.poll(() => actions.length).toBe(1);
    expect(actions[0]).toEqual({ codebase_key: "a".repeat(64), worktree_key: "b".repeat(64) });

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    await page.screenshot({ path: testInfo.outputPath(`workspace-findings-${width}.png`), fullPage: true });
    expect(pageErrors).toEqual([]);
  });
}
