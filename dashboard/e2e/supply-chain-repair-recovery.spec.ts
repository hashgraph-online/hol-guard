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
