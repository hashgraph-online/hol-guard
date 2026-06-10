import type { GuardRuntimeSnapshot } from "./guard-types";

export type SupplyChainCapabilityItem = {
  label: string;
  available: boolean;
};

export type SupplyChainCloudCapabilitiesState = {
  mode: GuardRuntimeSnapshot["cloud_state"];
  title: string;
  detail: string;
  tone: "blue" | "green" | "slate";
  localHeading: string;
  cloudHeading: string;
  localCapabilities: SupplyChainCapabilityItem[];
  cloudCapabilities: SupplyChainCapabilityItem[];
};

const LOCAL_FREE_CAPABILITIES: SupplyChainCapabilityItem[] = [
  { label: "Block risky package installs on this device", available: true },
  { label: "Install and repair package tool protection", available: true },
  { label: "Run workspace audits with on-device rules", available: true },
  { label: "Review recent blocks and audits on this machine", available: true },
];

const CLOUD_CAPABILITIES: SupplyChainCapabilityItem[] = [
  { label: "Live package warnings from Guard Cloud", available: false },
  { label: "Sync policy and evidence across devices", available: false },
  { label: "Fleet visibility for connected machines", available: false },
  { label: "Cloud-backed audit and sync actions", available: false },
];

const CLOUD_ACTIVE_CAPABILITIES: SupplyChainCapabilityItem[] = CLOUD_CAPABILITIES.map(
  (item) => ({ ...item, available: true }),
);

export function resolveSupplyChainCloudCapabilities(
  snapshot: GuardRuntimeSnapshot,
): SupplyChainCloudCapabilitiesState {
  if (snapshot.cloud_state === "paired_active") {
    return {
      mode: "paired_active",
      title: "Guard Cloud connected",
      detail:
        snapshot.cloud_state_detail.trim().length > 0
          ? `${snapshot.cloud_state_detail} Local protection still runs on this device.`
          : "Live package warnings and synced policy are active. Local protection still runs on this device.",
      tone: "green",
      localHeading: "Still on this device",
      cloudHeading: "Now from Guard Cloud",
      localCapabilities: LOCAL_FREE_CAPABILITIES,
      cloudCapabilities: CLOUD_ACTIVE_CAPABILITIES,
    };
  }

  if (snapshot.cloud_state === "paired_waiting") {
    return {
      mode: "paired_waiting",
      title: "Guard Cloud pairing in progress",
      detail:
        snapshot.cloud_state_detail.trim().length > 0
          ? snapshot.cloud_state_detail
          : "Finish connecting this machine to Guard Cloud. Local package protection stays available while pairing completes.",
      tone: "blue",
      localHeading: "Available now on this device",
      cloudHeading: "Unlocks after pairing",
      localCapabilities: LOCAL_FREE_CAPABILITIES,
      cloudCapabilities: CLOUD_CAPABILITIES,
    };
  }

  return {
    mode: "local_only",
    title: "Local protection works on this device",
    detail:
      snapshot.cloud_state_detail.trim().length > 0
        ? snapshot.cloud_state_detail
        : "You can block installs and run audits locally for free. Connect Guard Cloud for live warnings, synced policy, and cross-device evidence.",
    tone: "slate",
    localHeading: "Free on this device",
    cloudHeading: "Adds with Guard Cloud",
    localCapabilities: LOCAL_FREE_CAPABILITIES,
    cloudCapabilities: CLOUD_CAPABILITIES,
  };
}
