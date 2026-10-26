import type { Locator, Page } from "@playwright/test";

import { daemonApi, type IntegrationState } from "./fixtures";

export type SupplyChainSeed = {
  project: string;
  projectName: string;
  app: string;
  shimmedManagers: string[];
  packages: string[];
};

export function supplySeed(state: IntegrationState): SupplyChainSeed {
  return state.seeded.supply_chain as unknown as SupplyChainSeed;
}

type ShimDetail = { manager: string; integrity?: string; path_active?: boolean };

export type PackageShimsResponse = {
  actions: Record<string, string>;
  supported_managers: string[];
  package_shims: {
    detected_managers: string[];
    installed_managers: string[];
    tested_managers: string[];
    path_broken_managers: string[];
    bypasses: Array<{ manager: string }>;
    manager_details: ShimDetail[];
    path_status: string;
    shim_dir: string;
  };
};

export function loadPackageShims(state: IntegrationState): Promise<PackageShimsResponse> {
  return daemonApi<PackageShimsResponse>(state, "/v1/supply-chain/package-shims");
}

export type ExpectedRow = {
  manager: string;
  status: string;
  tone: "green" | "blue" | "attention" | "slate";
  // Row buttons beside the manager name, in page order.
  actions: string[];
  detected: boolean;
};

// Mirrors normalizePackageShimEntries, resolveShimStatus and ManagerRow for
// the managers the page lists. The host decides which managers it detects, so
// specs compare the page with the daemon rather than with a fixed list.
export function expectedRows(shims: PackageShimsResponse): ExpectedRow[] {
  const status = shims.package_shims;
  const detected = new Set(status.detected_managers);
  const installed = new Set(status.installed_managers);
  const tested = new Set(status.tested_managers);
  const broken = new Set([...status.path_broken_managers, ...status.bypasses.map((bypass) => bypass.manager)]);
  const details = new Map(status.manager_details.map((detail) => [detail.manager, detail]));
  const restartRequired = status.path_status === "restart_required";
  const managers = [...new Set([...detected, ...installed, ...tested])].sort();
  return managers.map((manager) => {
    const isInstalled = installed.has(manager);
    const detail = details.get(manager);
    const pathBroken = !restartRequired && broken.has(manager);
    let label: string;
    let tone: ExpectedRow["tone"];
    const actions: string[] = [];
    if (!isInstalled) {
      label = detected.has(manager) ? "Detected, not protected" : "Unprotected";
      tone = detected.has(manager) ? "slate" : "attention";
      actions.push("Protect");
    } else if (detail?.integrity !== "tampered" && detail?.path_active) {
      label = "Protected";
      tone = "green";
      actions.push("Test", "Remove");
    } else {
      if (detail?.integrity !== "tampered" && restartRequired) {
        label = "Restart required";
        tone = "blue";
      } else {
        label = pathBroken ? "PATH broken" : "Needs PATH repair";
        tone = "attention";
        actions.push("Fix PATH");
      }
      actions.push("Remove");
    }
    return { manager, status: label, tone, actions, detected: detected.has(manager) };
  });
}

export function managerList(page: Page): Locator {
  return page.getByRole("list", { name: "Package manager controls" });
}

// The card for one manager: the list item that holds its details button.
export function managerCard(page: Page, manager: string): Locator {
  return managerList(page)
    .getByRole("listitem")
    .filter({ has: page.getByRole("button", { name: `Open ${manager} manager details`, exact: true }) });
}
