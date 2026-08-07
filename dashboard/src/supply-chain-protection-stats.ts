import type { GuardRuntimeSnapshot, PackageManagerProtection } from "./guard-types";

export type ManagerCoverageStatus = "protected" | "restart_required" | "path_repair" | "unprotected";

export function resolveManagerCoverageManagers(
  protection: PackageManagerProtection | undefined,
): string[] {
  if (protection === undefined) {
    return [];
  }
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

export function buildSupplyChainStats(
  snapshot: GuardRuntimeSnapshot,
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
    preventedInstalls: managedInstalls.filter((install) => !install.active).length,
    protectedManagers,
    stagedManagers,
    repairRequiredManagers,
    unprotectedManagers,
  };
}
