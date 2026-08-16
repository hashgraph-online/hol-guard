import type { EffectiveExtensionControls } from "../../extension-controls-api";

export type ProtectionStatusTone = "safe" | "attention" | "danger" | "neutral";
export type ProtectionPrimaryAction =
  | "none"
  | "finish-setup"
  | "repair"
  | "retry-repair"
  | "review-lockdown"
  | "refresh";

export type ProtectionStatusView = {
  status: "protected" | "finish-setup" | "needs-repair" | "limited" | "lockdown" | "unavailable";
  title: string;
  summary: string;
  tone: ProtectionStatusTone;
  primaryAction: ProtectionPrimaryAction;
  primaryActionLabel: string | null;
};

export function deriveProtectionStatus(effective: EffectiveExtensionControls): ProtectionStatusView {
  if (effective.global_lockdown) {
    return {
      status: "lockdown",
      title: "Emergency Lockdown active",
      summary: "Guard is blocking matching optional actions until you review and end lockdown.",
      tone: "danger",
      primaryAction: "review-lockdown",
      primaryActionLabel: "Review lockdown",
    };
  }

  switch (effective.health) {
    case "protected":
      return {
        status: "protected",
        title: "Protected",
        summary: "Guard is actively applying the trusted protection settings on this device.",
        tone: "safe",
        primaryAction: "none",
        primaryActionLabel: null,
      };
    case "unenrolled":
      return {
        status: "finish-setup",
        title: "Finish setup",
        summary: "Complete local setup so Guard can protect and verify settings on this device.",
        tone: "attention",
        primaryAction: "finish-setup",
        primaryActionLabel: "Show setup steps",
      };
    case "tampered":
    case "recovery-required":
      return {
        status: "needs-repair",
        title: "Needs repair",
        summary: "Guard detected a problem with trusted protection settings and is staying fail-safe until they are repaired.",
        tone: "danger",
        primaryAction: "repair",
        primaryActionLabel: "Repair protection",
      };
    case "degraded-unacknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is staying fail-safe because it cannot fully verify protection settings. Repair is recommended.",
        tone: "attention",
        primaryAction: "repair",
        primaryActionLabel: "Restore protection",
      };
    case "degraded-acknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is still staying fail-safe. The earlier acknowledgement did not restore trusted protection.",
        tone: "attention",
        primaryAction: "retry-repair",
        primaryActionLabel: "Try repair again",
      };
    default:
      return {
        status: "unavailable",
        title: "Protection status unavailable",
        summary: "Guard could not verify the current protection state. Refresh before making any protection changes.",
        tone: "neutral",
        primaryAction: "refresh",
        primaryActionLabel: "Check again",
      };
  }
}

export function localProtectionLabel(effective: EffectiveExtensionControls): string {
  return deriveProtectionStatus(effective).title;
}
