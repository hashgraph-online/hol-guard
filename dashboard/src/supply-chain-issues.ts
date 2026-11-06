import { resolveFeedStaleness } from "./feed-health-workspace";
import { resolveHomeProtectionStatus } from "./home-protection-module";
import {
  buildSupplyChainStats,
  resolveManagerCoverageManagers,
  resolveManagerCoverageStatus,
} from "./supply-chain-protection-stats";
import { resolveSupplyChainCloudDegradedState } from "./supply-chain-evidence-rail";
import type { GuardRuntimeSnapshot } from "./guard-types";

export type SupplyChainIssueAction =
  | { kind: "connect" }
  | { kind: "firewall_unprotected" }
  | { kind: "firewall_repair" }
  | { kind: "firewall_audit" };

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
  const unprotectedManagers = resolveManagerCoverageManagers(protection).filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected",
  );
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
        "Guard has not activated package protection yet. Turn on protection for your package tools, then finish activation here.",
      tone: "attention",
      actionLabel: "Protect package tools",
      action: { kind: "firewall_unprotected" },
    });
  } else if (stats.repairRequiredManagers > 0) {
    const coverageManagers = new Set(resolveManagerCoverageManagers(protection));
    const managers =
      protection !== undefined
        ? protection.installed_managers.filter(
            (manager) =>
              coverageManagers.has(manager) && !protection.protected_managers.includes(manager),
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
  }

  if (
    protectionStatus === "partial" &&
    stats.protectedManagers > 0 &&
    unprotectedManagers.length > 0
  ) {
    issues.push({
      id: "partial_protection",
      title: "Some package tools are still open",
      detail: `${stats.protectedManagers} protected, ${unprotectedManagers.length} still open: ${unprotectedManagers.join(", ")}.`,
      tone: "attention",
      actionLabel: "Review open tools",
      action: { kind: "firewall_unprotected" },
    });
  } else if (protectionStatus === "unprotected" && unprotectedManagers.length > 0) {
    issues.push({
      id: "unprotected_tools",
      title: "Package installs are not protected yet",
      detail: `Turn on protection for ${unprotectedManagers.join(", ")} to block risky installs before they run.`,
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
