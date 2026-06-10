import { resolveFeedStaleness } from "./feed-health-workspace";
import { resolveHomeProtectionStatus } from "./home-protection-module";
import { buildSupplyChainStats } from "./supply-chain-protection-stats";
import type { GuardRuntimeSnapshot } from "./guard-types";

export type SupplyChainPostureAlertKind =
  | "partial_protection"
  | "path_repair"
  | "stale_intel";

export type SupplyChainPostureAlert = {
  kind: SupplyChainPostureAlertKind;
  title: string;
  detail: string;
  tone: "attention" | "blue" | "slate";
};

export function resolveSupplyChainPostureAlerts(
  snapshot: GuardRuntimeSnapshot,
): SupplyChainPostureAlert[] {
  const alerts: SupplyChainPostureAlert[] = [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const stats = buildSupplyChainStats(snapshot);
  const protectionStatus = resolveHomeProtectionStatus(snapshot);

  if (protection?.path_status === "missing_from_path") {
    alerts.push({
      kind: "path_repair",
      title: "Guard shims are missing from PATH",
      detail:
        "Package manager shims are not active in your shell PATH yet. Install or repair shims in the firewall panel, then open a new shell.",
      tone: "attention",
    });
  } else if (stats.repairRequiredManagers > 0) {
    const managers =
      protection !== undefined
        ? protection.installed_managers.filter(
            (manager) => !protection.protected_managers.includes(manager),
          )
        : [];
    const managerLabel = managers.length > 0 ? managers.join(", ") : "installed managers";
    alerts.push({
      kind: "path_repair",
      title: "PATH repair required before intercepts work",
      detail: `Guard installed shims for ${managerLabel}, but PATH order still needs repair. Use Fix PATH in the firewall panel, then restart your shell.`,
      tone: "attention",
    });
  } else if (protection?.path_status === "restart_required" || stats.stagedManagers > 0) {
    alerts.push({
      kind: "path_repair",
      title: "Restart shell to activate PATH protection",
      detail:
        "Guard updated your shell profile. Open a new terminal or restart AI apps before testing intercept proof.",
      tone: "blue",
    });
  }

  if (
    protectionStatus === "partial" &&
    protection !== undefined &&
    protection.protected_managers.length > 0 &&
    protection.unprotected_managers.length > 0
  ) {
    alerts.push({
      kind: "partial_protection",
      title: "Some package managers are still unprotected",
      detail: `${protection.protected_managers.length} protected, ${protection.unprotected_managers.length} still open: ${protection.unprotected_managers.join(", ")}. Install shims for the remaining managers to close the gap.`,
      tone: "attention",
    });
  }

  if (snapshot.cloud_state !== "local_only") {
    const feedStaleness = resolveFeedStaleness(snapshot);
    if (feedStaleness.stale) {
      alerts.push({
        kind: "stale_intel",
        title: "Supply-chain intel looks stale on this device",
        detail: `${feedStaleness.ageLabel}. Sync policy or run a workspace audit so Guard evaluates packages against current advisories.`,
        tone: "attention",
      });
    }
  }

  return alerts;
}
