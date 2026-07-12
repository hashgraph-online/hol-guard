import { resolveHomeProtectionStatus, type HomeProtectionStatus } from "./home-protection-module";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { buildSupplyChainStats } from "./supply-chain-protection-stats";

export type SupplyChainWorkspaceHeroState = {
  cloudMode: GuardRuntimeSnapshot["cloud_state"];
  cloudLabel: string;
  protectionStatus: HomeProtectionStatus;
  title: string;
  detail: string;
  tone: "green" | "blue" | "attention" | "slate";
  statLine: string;
};

function protectionTitle(status: HomeProtectionStatus): string {
  if (status === "protected") {
    return "Package installs are protected on this device";
  }
  if (status === "partial") {
    return "Protection is only partly set up";
  }
  if (status === "staged") {
    return "Finish setup in a new terminal";
  }
  if (status === "unprotected") {
    return "Package installs are not protected yet";
  }
  return "Checking package protection on this device";
}

function protectionDetail(
  snapshot: GuardRuntimeSnapshot,
  status: HomeProtectionStatus,
): string {
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (status === "protected" && protection) {
    return `${protection.protected_managers.length} package tool${
      protection.protected_managers.length === 1 ? "" : "s"
    } active. Guard can block risky installs before they run.`;
  }
  if (status === "partial" && protection) {
    return `${protection.unprotected_managers.length} tool${
      protection.unprotected_managers.length === 1 ? "" : "s"
    } still open: ${protection.unprotected_managers.join(", ")}.`;
  }
  if (status === "staged") {
    return "Guard saved your shell setup. Finish activation here, then run a protection check.";
  }
  if (status === "unprotected") {
    return "Turn on protection for npm, pip, and other tools in the firewall panel below.";
  }
  return "Refresh status after installing package tools on this machine.";
}

function protectionTone(status: HomeProtectionStatus): SupplyChainWorkspaceHeroState["tone"] {
  if (status === "protected") {
    return "green";
  }
  if (status === "staged") {
    return "blue";
  }
  if (status === "partial" || status === "unprotected") {
    return "attention";
  }
  return "slate";
}

function cloudLabel(snapshot: GuardRuntimeSnapshot): string {
  const label = snapshot.cloud_state_label ?? "";
  if (snapshot.cloud_state === "paired_active") {
    return label.trim().length > 0 ? label : "Guard Cloud connected";
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return label.trim().length > 0 ? label : "Pairing in progress";
  }
  return label.trim().length > 0 ? label : "On this device only";
}

export function resolveSupplyChainWorkspaceHero(
  snapshot: GuardRuntimeSnapshot,
  options?: { openIssueCount?: number },
): SupplyChainWorkspaceHeroState {
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
  const stats = buildSupplyChainStats(snapshot);
  const preventedLabel =
    stats.preventedInstalls > 0
      ? `${stats.preventedInstalls} blocked install${stats.preventedInstalls === 1 ? "" : "s"}`
      : "No blocked installs yet";

  const openIssueCount = options?.openIssueCount ?? 0;
  if (openIssueCount > 0) {
    return {
      cloudMode: snapshot.cloud_state,
      cloudLabel: cloudLabel(snapshot),
      protectionStatus,
      title: "Work through the steps below",
      detail: `${openIssueCount} setup step${openIssueCount === 1 ? "" : "s"} need attention on this device.`,
      tone: protectionTone(protectionStatus),
      statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`,
    };
  }

  return {
    cloudMode: snapshot.cloud_state,
    cloudLabel: cloudLabel(snapshot),
    protectionStatus,
    title: protectionTitle(protectionStatus),
    detail: protectionDetail(snapshot, protectionStatus),
    tone: protectionTone(protectionStatus),
    statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`,
  };
}

export function supplyChainCloudTagTone(
  mode: SupplyChainWorkspaceHeroState["cloudMode"],
): "green" | "blue" | "attention" {
  if (mode === "paired_active") {
    return "green";
  }
  if (mode === "paired_waiting") {
    return "blue";
  }
  return "attention";
}
