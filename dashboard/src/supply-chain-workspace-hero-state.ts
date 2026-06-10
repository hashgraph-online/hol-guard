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
  if (status === "protected" && protection !== undefined) {
    return `${protection.protected_managers.length} package tool${
      protection.protected_managers.length === 1 ? "" : "s"
    } active. Guard can block risky installs before they run.`;
  }
  if (status === "partial" && protection !== undefined) {
    return `${protection.unprotected_managers.length} tool${
      protection.unprotected_managers.length === 1 ? "" : "s"
    } still open: ${protection.unprotected_managers.join(", ")}.`;
  }
  if (status === "staged") {
    return "Guard updated your shell profile. Open a new terminal, then run a protection test.";
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
  if (snapshot.cloud_state === "paired_active") {
    return snapshot.cloud_state_label.trim().length > 0
      ? snapshot.cloud_state_label
      : "Guard Cloud connected";
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return snapshot.cloud_state_label.trim().length > 0
      ? snapshot.cloud_state_label
      : "Pairing in progress";
  }
  return snapshot.cloud_state_label.trim().length > 0
    ? snapshot.cloud_state_label
    : "On this device only";
}

export function resolveSupplyChainWorkspaceHero(
  snapshot: GuardRuntimeSnapshot,
): SupplyChainWorkspaceHeroState {
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
  const stats = buildSupplyChainStats(snapshot);
  const preventedLabel =
    stats.preventedInstalls > 0
      ? `${stats.preventedInstalls} blocked install${stats.preventedInstalls === 1 ? "" : "s"}`
      : "No blocked installs yet";

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
