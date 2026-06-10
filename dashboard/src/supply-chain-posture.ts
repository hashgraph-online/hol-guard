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
      title: "Package installs are not being checked yet",
      detail:
        "Guard has not hooked into your shell path yet. Turn on protection in the firewall panel below, then open a new terminal.",
      tone: "attention",
    });
  } else if (stats.repairRequiredManagers > 0) {
    const managers =
      protection !== undefined
        ? protection.installed_managers.filter(
            (manager) => !protection.protected_managers.includes(manager),
          )
        : [];
    const managerLabel = managers.length > 0 ? managers.join(", ") : "installed tools";
    alerts.push({
      kind: "path_repair",
      title: "Fix your shell path before installs can be blocked",
      detail: `Guard set up protection for ${managerLabel}, but your shell path still needs a quick repair. Tap Fix PATH in the firewall panel, then open a new terminal.`,
      tone: "attention",
    });
  } else if (protection?.path_status === "restart_required" || stats.stagedManagers > 0) {
    alerts.push({
      kind: "path_repair",
      title: "Open a new terminal to finish setup",
      detail:
        "Guard updated your shell profile. Open a new terminal or restart your AI apps before running a protection test.",
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
      title: "Some package tools are still open",
      detail: `${protection.protected_managers.length} protected, ${protection.unprotected_managers.length} still open: ${protection.unprotected_managers.join(", ")}. Turn on protection for the remaining tools to close the gap.`,
      tone: "attention",
    });
  }

  if (snapshot.cloud_state !== "local_only") {
    const feedStaleness = resolveFeedStaleness(snapshot);
    if (feedStaleness.stale) {
      alerts.push({
        kind: "stale_intel",
        title: "Safety check data looks old on this device",
        detail: `${feedStaleness.ageLabel}. Sync policy or run a workspace audit so Guard evaluates packages against current warnings.`,
        tone: "attention",
      });
    }
  }

  return alerts;
}
