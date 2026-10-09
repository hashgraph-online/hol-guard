import { expect, test } from "@playwright/test";
import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  paidStateSnapshot,
} from "./fixture-states";

const packageStatus = {
  operation: "status",
  status: "ready",
  supported_managers: ["npm"],
  entitlement: { allowed: true, reason: "paid_entitlement_active", tier: "premium" },
  actions: { install: "available", repair: "available", test: "available", remove: "available" },
  connect_flow: null,
  package_shims: {
    detected_managers: ["npm"],
    installed_managers: ["npm"],
    active_managers: [],
    missing_managers: [],
    path_broken_managers: ["npm"],
    path_status: "missing_from_path",
    manager_details: [{ manager: "npm", integrity: "ok", path_active: false }],
  },
};

test("completed PATH repair releases other controls without repeating stale repair", async ({ page }) => {
  let repairRequests = 0;
  let holdStatusRefresh = false;
  let releaseStatusRefresh: () => void = () => undefined;
  const statusRefresh = new Promise<void>((resolve) => {
    releaseStatusRefresh = resolve;
  });

  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let payload: unknown = {};
    if (path === "/v1/supply-chain/package-shims") {
      if (holdStatusRefresh) await statusRefresh;
      payload = packageStatus;
    } else if (path === "/v1/supply-chain/package-shims/repair") {
      repairRequests += 1;
      holdStatusRefresh = true;
      await new Promise((resolve) => setTimeout(resolve, 200));
      payload = {
        entitlement: { allowed: true },
        operation: "repair",
        receipt: null,
        result: { repaired_count: 1 },
        status: "completed",
      };
    } else if (path === "/v1/runtime") {
      if (holdStatusRefresh) {
        await route.fulfill({ status: 500, contentType: "application/json", body: "{}" });
        return;
      }
      payload = paidStateSnapshot;
    } else if (path === "/v1/receipts") {
      payload = emptyReceiptsPayload;
    } else if (path === "/v1/policy") {
      payload = emptyPoliciesPayload;
    } else if (path === "/v1/settings") {
      payload = defaultSettingsPayload;
    } else if (path === "/v1/inventory") {
      payload = emptyInventoryPayload;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(payload) });
  });

  try {
    await page.goto("/supply-chain?guard-token=e2e-token&guardDaemon=http://127.0.0.1:4175");
    const fixPath = page.getByTestId("package-firewall-panel").getByRole("button", { name: "Fix PATH" });
    await expect(fixPath).toBeVisible();
    await fixPath.click();
    await expect(fixPath).toBeDisabled();
    await expect.poll(() => repairRequests).toBe(1);
    await expect(page.getByTestId("package-firewall-panel").getByRole("button", { name: "Remove" })).toBeEnabled({ timeout: 5_000 });
    await expect(fixPath).toBeDisabled();
    await page.getByRole("button", { name: "Open npm manager details" }).click();
    await expect(page.getByRole("dialog", { name: "npm manager details" }).getByRole("button", { name: "Fix PATH" })).toBeDisabled();
    await expect(page.getByText("Guard could not refresh the rest of the dashboard.", { exact: false })).toBeVisible();
    expect(repairRequests).toBe(1);
  } finally {
    releaseStatusRefresh();
  }
});

for (const viewport of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
  test(`Cloud access is checked before proof and paid first activation succeeds at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    let allowed = false;
    let repairs = 0;
    let proofs = 0;
    const gate = {
      enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false,
      cooldown_expires_at: null, locked_until: null, fail_closed: true,
      strict_all_decisions: true, totp_enabled: false,
    };
    await page.route("**/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      let payload: unknown = {};
      if (path === "/v1/supply-chain/package-shims") {
        payload = {
          ...packageStatus,
          entitlement: { allowed, reason: allowed ? "paid_entitlement_active" : "paid_guard_cloud_required", tier: allowed ? "premium" : "free" },
          package_shims: { ...packageStatus.package_shims, installed_managers: [], path_broken_managers: [], manager_details: [] },
        };
      } else if (path === "/v1/supply-chain/repair") {
        repairs += 1;
        const body = route.request().postDataJSON();
        if (!body.approval_password) {
          await route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: "approval_gate_required" }) });
          return;
        }
        proofs += 1;
        payload = { status: "completed", operation: "repair_all", result: {
          repaired: true, completed_steps: ["package_shims", "runtime_activation", "intelligence_sync"], failed_steps: [], remaining_steps: [], message: "Supply-chain protection restored and refreshed.",
        } };
      } else if (path === "/v1/runtime") payload = {
        ...paidStateSnapshot,
        supply_chain: { package_manager_protection: {
          path_status: "missing_from_path", path_contains_shim_dir: false,
          restart_shell_required: false, shell_profile_configured: false,
          shell_profile_path: null, shim_dir: null, supported_managers: ["npm"],
          detected_managers: ["npm"], installed_managers: [], active_managers: [],
          missing_shims: ["npm"], protected_managers: [], unprotected_managers: ["npm"],
        } },
      };
      else if (path === "/v1/receipts") payload = emptyReceiptsPayload;
      else if (path === "/v1/policy") payload = emptyPoliciesPayload;
      else if (path === "/v1/settings") payload = { ...defaultSettingsPayload, settings: { ...defaultSettingsPayload.settings, approval_gate: gate } };
      else if (path === "/v1/settings/approval-gate") payload = { approval_gate: gate };
      else if (path === "/v1/inventory") payload = emptyInventoryPayload;
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(payload) });
    });

    await page.goto("/supply-chain?guard-token=e2e-token&guardDaemon=http://127.0.0.1:4175");
    const recovery = page.getByTestId("supply-chain-recovery");
    await recovery.getByRole("button", { name: "Restore protection", exact: true }).click();
    await expect(recovery.getByRole("button", { name: "Check Cloud access", exact: true })).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Restore package protection" })).toHaveCount(0);
    expect(repairs).toBe(0);
    await recovery.getByRole("button", { name: "Check Cloud access", exact: true }).click();
    await expect(recovery.getByRole("button", { name: "Check Cloud access", exact: true })).toBeEnabled();
    expect(repairs).toBe(0);
    expect(proofs).toBe(0);
    await page.screenshot({ path: test.info().outputPath("cloud-access-recovery.png") });

    allowed = true;
    await recovery.getByRole("button", { name: "Check Cloud access", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Restore package protection" });
    await expect(dialog).toBeVisible();
    await dialog.getByLabel("Approval password", { exact: true }).fill("synthetic-test-password");
    await dialog.getByRole("button", { name: "Restore protection", exact: true }).click();
    await expect(recovery.getByText("Supply-chain protection restored and refreshed.", { exact: true })).toBeVisible();
    expect(repairs).toBe(2);
    expect(proofs).toBe(1);
    await expect(dialog).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath("paid-first-activation.png") });
  });
}
