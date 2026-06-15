function resolveManagerCoverageStatus(protection, manager) {
  if (protection === void 0) {
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
function buildSupplyChainStats(snapshot) {
  const managedInstalls = snapshot.managed_installs ?? [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const supportedManagers = protection?.supported_managers ?? [];
  const protectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "protected"
  ).length;
  const stagedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "restart_required"
  ).length;
  const repairRequiredManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "path_repair"
  ).length;
  const unprotectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected"
  ).length;
  return {
    totalApps: managedInstalls.length,
    activeApps: managedInstalls.filter((install) => install.active).length,
    preventedInstalls: managedInstalls.filter((install) => !install.active).length,
    protectedManagers,
    stagedManagers,
    repairRequiredManagers,
    unprotectedManagers
  };
}
export {
  buildSupplyChainStats as b,
  resolveManagerCoverageStatus as r
};
