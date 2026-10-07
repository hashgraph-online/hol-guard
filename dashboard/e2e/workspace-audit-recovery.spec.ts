import { expect, test, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  paidStateSnapshot,
} from "./fixture-states";

const DAEMON = "guardDaemon=http://127.0.0.1:4175";
const projectFolder = "/workspace/project";

const packageShimStatus = {
  operation: "status",
  status: "completed",
  supported_managers: [],
  package_shims: {},
  entitlement: {
    allowed: true,
    reason: "allowed",
    tier: "premium",
    upgrade_cta: null,
    upgrade_url: null,
  },
  actions: { audit: "available" },
  cli_fallback: { connect: "hol-guard connect" },
  connect_flow: null,
  audit_workspace_dir: null,
};

async function mountWorkspaceAuditFixture(page: Page, auditRequests: unknown[]): Promise<void> {
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith("/supply-chain/audit")) {
      const payload = request.postDataJSON();
      auditRequests.push(payload);
      const workspaceDir =
        typeof payload === "object" && payload !== null
          ? (payload as { workspace_dir?: string }).workspace_dir
          : undefined;
      if (workspaceDir !== projectFolder) {
        const invalidWorkspace = typeof workspaceDir === "string" && workspaceDir.length > 0;
        await route.fulfill({
          status: 400,
          contentType: "application/json",
          body: JSON.stringify({
            error: invalidWorkspace ? "workspace_dir_invalid" : "workspace_dir_required",
            message: invalidWorkspace
              ? "Guard could not use the selected project folder. Choose an existing local folder and try again."
              : "Guard needs a project folder with package manifests before it can run the workspace audit.",
            operation: "audit",
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          operation: "audit",
          status: "completed",
          entitlement: packageShimStatus.entitlement,
          result: {
            generated_at: "2026-09-20T12:00:00.000Z",
            audit_status: "completed",
            evaluation: { decision: "monitor", packages: [] },
            inventory: { total_packages: 0, direct_package_count: 0, transitive_package_count: 0, sbom_package_count: 0 },
            manifest_paths: ["package.json"],
            lockfile_paths: ["package-lock.json"],
          },
        }),
      });
      return;
    }

    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "e2e-workspace-audit-token" };
    else if (path.endsWith("/runtime")) body = paidStateSnapshot;
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/supply-chain/package-shims")) body = packageShimStatus;
    else if (path.endsWith("/command-activity/events")) {
      await route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
}

for (const width of [390, 1440]) {
  test(`workspace audit recovers by accepting a project folder at ${width}px`, async ({ page }, testInfo) => {
    const pageErrors: string[] = [];
    const auditRequests: unknown[] = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    await mountWorkspaceAuditFixture(page, auditRequests);

    await page.goto(`/audit?${DAEMON}`);
    const runAudit = page.getByTestId("workspace-audit-run");
    await expect(runAudit).toBeVisible();
    await runAudit.click();

    await expect(page.getByTestId("workbench-audit-error")).toContainText("Workspace audit could not start");
    const workspaceInput = page.getByTestId("workspace-audit-folder-input");
    await expect(workspaceInput).toBeVisible();
    await expect(runAudit).toBeDisabled();

    await workspaceInput.fill("/workspace/missing");
    await expect(runAudit).toBeEnabled();
    await runAudit.click();
    await expect(page.getByTestId("workbench-audit-error")).toContainText("could not use that project folder");

    await workspaceInput.fill(projectFolder);
    await expect(runAudit).toBeEnabled();
    await runAudit.click();

    await expect.poll(() => auditRequests.length).toBe(3);
    expect(auditRequests[0]).toEqual({});
    expect(auditRequests[1]).toEqual({ workspace_dir: "/workspace/missing" });
    expect(auditRequests[2]).toEqual({ workspace_dir: projectFolder });
    await expect(page.getByTestId("workbench-audit-error")).toHaveCount(0);
    await expect(page.locator("body")).not.toHaveCSS("overflow-x", "scroll");
    await page.screenshot({ path: testInfo.outputPath(`workspace-audit-recovery-${width}.png`), fullPage: true });
    expect(pageErrors).toEqual([]);
  });
}
