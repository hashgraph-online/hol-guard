import type { GuardReceipt, GuardRuntimeSnapshot, PackageManagerProtection } from "./guard-types";
import { isPackageBlockReceipt } from "./supply-chain-evidence-rail";

export type ManagerCoverageStatus = "protected" | "restart_required" | "path_repair" | "unprotected";

export function resolveManagerCoverageManagers(
  protection: PackageManagerProtection | undefined,
): string[] {
  if (protection === undefined) {
    return [];
  }
  // Local health is detection-scoped; supported_managers is capability metadata only.
  return protection.detected_managers ?? [];
}

export function resolveManagerCoverageStatus(
  protection: PackageManagerProtection | undefined,
  manager: string,
): ManagerCoverageStatus {
  if (protection === undefined) {
    return "unprotected";
  }
  if (protection.protected_managers.includes(manager)) {
    return "protected";
  }
  if (protection.installed_managers.includes(manager)) {
    if (protection.path_status === "restart_required") {
      return "restart_required";
    }
    return "path_repair";
  }
  return "unprotected";
}

/**
 * Package blocks from the snapshot plus the longer receipt page, once loaded.
 * The snapshot carries only the newest receipts, so an older block would
 * otherwise drop out while the activity rail still shows it.
 */
export function collectPackageBlockReceipts(
  snapshot: GuardRuntimeSnapshot,
  loadedReceipts?: readonly GuardReceipt[] | null,
): GuardReceipt[] {
  const blocks = new Map<string, GuardReceipt>();
  for (const receipt of [...(snapshot.latest_receipts ?? []), ...(loadedReceipts ?? [])]) {
    if (isPackageBlockReceipt(receipt)) {
      blocks.set(receipt.receipt_id, receipt);
    }
  }
  return [...blocks.values()];
}

export function buildSupplyChainStats(
  snapshot: GuardRuntimeSnapshot,
  loadedReceipts?: readonly GuardReceipt[] | null,
): {
  totalApps: number;
  activeApps: number;
  preventedInstalls: number;
  protectedManagers: number;
  stagedManagers: number;
  repairRequiredManagers: number;
  unprotectedManagers: number;
} {
  const managedInstalls = snapshot.managed_installs ?? [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const coverageManagers = resolveManagerCoverageManagers(protection);
  const protectedManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "protected",
  ).length;
  const stagedManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "restart_required",
  ).length;
  const repairRequiredManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "path_repair",
  ).length;
  const unprotectedManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected",
  ).length;
  return {
    totalApps: managedInstalls.length,
    activeApps: managedInstalls.filter((install) => install.active).length,
    // Managed installs are connected apps; an inactive one is not a blocked
    // package. Count the package blocks among the receipts Guard has loaded.
    preventedInstalls: collectPackageBlockReceipts(snapshot, loadedReceipts).length,
    protectedManagers,
    stagedManagers,
    repairRequiredManagers,
    unprotectedManagers,
  };
}
