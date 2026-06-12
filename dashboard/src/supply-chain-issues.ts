import { resolveFeedStaleness } from "./feed-health-workspace";
import { resolveHomeProtectionStatus } from "./home-protection-module";
import { buildSupplyChainStats } from "./supply-chain-protection-stats";
import { resolveSupplyChainCloudDegradedState } from "./supply-chain-evidence-rail";
import type { GuardRuntimeSnapshot } from "./guard-types";

export type SupplyChainIssueAction =
  | { kind: "connect" }
  | { kind: "firewall_unprotected" }
  | { kind: "firewall_repair" }
  | { kind: "firewall_audit" }
  | { kind: "open_shell" }
  | { kind: "sync" };

export type SupplyChainIssue = {
  id: string;
  title: string;
  detail: string;
  tone: "attention" | "blue" | "slate";
  actionLabel: string;
  action: SupplyChainIssueAction;
};

export function resolveSupplyChainIssues(snapshot: GuardRuntimeSnapshot): SupplyChainIssue[] {
  const issues: SupplyChainIssue[] = [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const stats = buildSupplyChainStats(snapshot);
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
  const cloudDegraded = resolveSupplyChainCloudDegradedState(snapshot);

  if (cloudDegraded.active) {
    issues.push({
      id: "cloud_connect",
      title: cloudDegraded.title,
      detail:
        cloudDegraded.detail.trim().length > 0
          ? cloudDegraded.detail
          : "Connect Guard Cloud for live package warnings, synced policy, and cross-device evidence.",
      tone: "attention",
      actionLabel: "Connect Guard Cloud",
      action: { kind: "connect" },
    });
  }

  if (protection?.path_status === "missing_from_path") {
    issues.push({
      id: "path_missing",
      title: "Package installs are not being checked yet",
      detail:
        "Guard has not hooked into your shell path yet. Turn on protection for your package tools, then open a new terminal.",
      tone: "attention",
      actionLabel: "Protect package tools",
      action: { kind: "firewall_unprotected" },
    });
  } else if (stats.repairRequiredManagers > 0) {
    const managers =
      protection !== undefined
        ? protection.installed_managers.filter(
            (manager) => !protection.protected_managers.includes(manager),
          )
        : [];
    const managerLabel = managers.length > 0 ? managers.join(", ") : "installed tools";
    issues.push({
      id: "path_repair",
      title: "Fix your shell path before installs can be blocked",
      detail: `Guard set up protection for ${managerLabel}, but your shell path still needs a quick repair.`,
      tone: "attention",
      actionLabel: "Repair PATH in firewall",
      action: { kind: "firewall_repair" },
    });
  } else if (protection?.path_status === "restart_required" || stats.stagedManagers > 0) {
    issues.push({
      id: "path_restart",
      title: "Open a new terminal to finish setup",
      detail:
        "Guard updated your shell profile. Open a new terminal or restart your AI apps before running a protection test.",
      tone: "blue",
      actionLabel: "Open new shell",
      action: { kind: "open_shell" },
    });
  }

  if (
    protectionStatus === "partial" &&
    protection !== undefined &&
    protection.protected_managers.length > 0 &&
    protection.unprotected_managers.length > 0
  ) {
    issues.push({
      id: "partial_protection",
      title: "Some package tools are still open",
      detail: `${protection.protected_managers.length} protected, ${protection.unprotected_managers.length} still open: ${protection.unprotected_managers.join(", ")}.`,
      tone: "attention",
      actionLabel: "Review open tools",
      action: { kind: "firewall_unprotected" },
    });
  } else if (
    protectionStatus === "unprotected" &&
    protection !== undefined &&
    protection.unprotected_managers.length > 0
  ) {
    issues.push({
      id: "unprotected_tools",
      title: "Package installs are not protected yet",
      detail: `Turn on protection for ${protection.unprotected_managers.join(", ")} to block risky installs before they run.`,
      tone: "attention",
      actionLabel: "Protect package tools",
      action: { kind: "firewall_unprotected" },
    });
  }

  if (snapshot.cloud_state !== "local_only") {
    const feedStaleness = resolveFeedStaleness(snapshot);
    if (feedStaleness.stale) {
      issues.push({
        id: "stale_intel",
        title: "Safety check data looks old on this device",
        detail: `${feedStaleness.ageLabel}. Sync policy or run a workspace audit so Guard evaluates packages against current warnings.`,
        tone: "attention",
        actionLabel: "Run workspace audit",
        action: { kind: "firewall_audit" },
      });
    }
  }

  return issues;
}
