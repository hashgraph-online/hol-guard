export const PROTECTION_TERMS = {
  navigation: "Extensions",
  pageTitle: "Extensions",
  module: "Extension",
  modules: "Extensions",
  setting: "Protection setting",
  detection: "Detection",
  lockdown: "Emergency Lockdown",
  inheritedSetting: "Recommended",
  changeReview: "What will change",
} as const;

export const SIMPLE_MODE_PROHIBITED_TERMS = [
  "catalog digest",
  "canonical id",
  "matcher kind",
  "baseline floor",
  "local-admin",
  "signed-cloud",
  "semantic blast radius",
  "permission id",
  "rule id",
  "degraded-unacknowledged",
] as const;

export type ProtectionBehavior = "allowed" | "ask-first" | "blocked" | "required" | "managed";

export function protectionBehaviorLabel(behavior: ProtectionBehavior): string {
  switch (behavior) {
    case "allowed": return "Allowed";
    case "ask-first": return "Ask once";
    case "blocked": return "Blocked";
    case "required": return "Required";
    case "managed": return "Managed by your organization";
  }
}

export function localSettingChoiceLabel(choice: "inherit" | "allow" | "block"): string {
  if (choice === "inherit") return "Recommended";
  if (choice === "allow") return "Permit when Guard considers it safe";
  return "Always block matching actions";
}

export function localSettingChoiceDescription(choice: "inherit" | "allow" | "block"): string {
  if (choice === "inherit") return "Follow Guard's built-in defaults plus any organization policy.";
  if (choice === "allow") return "Permit matching actions only when Guard's built-in safety rules and organization policy allow them.";
  return "Add a stricter local block for matching actions on this device.";
}

export function simpleCopyViolations(text: string): string[] {
  const lower = text.toLowerCase();
  return SIMPLE_MODE_PROHIBITED_TERMS.filter((term) => lower.includes(term));
}

export function assertSimpleCopySafe(text: string): void {
  const violations = simpleCopyViolations(text);
  if (violations.length) throw new Error(`Simple protection copy leaked internal terms: ${violations.join(", ")}`);
}

export const CLOUD_LOCAL_BOUNDARY_COPY = {
  localProtected: "Local protection is active on this device.",
  cloudDisconnected: "Cloud continuity is not connected. Local protection continues.",
  cloudUnavailable: "Cloud sync is temporarily unavailable. Local protection continues.",
} as const;

function looksLikeUnauthorizedSession(message: string): boolean {
  const lower = message.trim().toLowerCase();
  if (!lower || lower === "unauthorized" || lower.includes("unauthorized") || lower.includes("session")) return true;
  return /(^|[^0-9])401([^0-9]|$)/.test(lower);
}

export function protectionCenterLoadError(message: string): { title: string; detail: string } {
  if (looksLikeUnauthorizedSession(message)) {
    return {
      title: "This view needs a signed local session",
      detail: "Local protection is still running on this device. Open Extensions from the local Guard dashboard and try again after Guard signs this session.",
    };
  }
  return {
    title: "Extensions unavailable",
    detail: message.trim() || "Guard could not load protection settings. Local protection continues. Try again.",
  };
}
