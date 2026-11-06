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

export type ProtectionCenterLoadError = {
  title: string;
  detail: string;
  /** The daemon's own reason code, kept for support and never used as the message. */
  reference?: string;
};

// The daemon answers failures with a reason code. A code is an accurate record
// and a useless sentence, so each one the page can actually receive gets copy
// that names what failed and the step that recovers it.
const LOAD_ERROR_COPY: Record<string, { title: string; detail: string }> = {
  catalog_read_model_unavailable: {
    title: "Guard cannot open your extension list",
    detail: "Guard is running on this device but could not open the extension list it keeps locally. Quit HOL Guard and open it again. If the page still cannot load, install the latest version.",
  },
  catalog_read_transport_failed: {
    title: "Guard stopped answering while the list loaded",
    detail: "The connection to Guard on this device ended before the extension list finished loading.",
  },
  catalog_snapshot_expired: {
    title: "The extension list changed while it loaded",
    detail: "Guard rebuilt the extension list while this page was reading it, so this page never finished loading. Load it again to read the rebuilt list.",
  },
  catalog_read_preparation_failed: {
    title: "Guard cannot rebuild your extension list",
    detail: "Guard on this device has failed to rebuild its extension list on every recent attempt, so waiting or loading the page again will not clear it. Install the latest version of HOL Guard. Guard writes the reason to its log file at ~/.hol-guard/logs/daemon.log.",
  },
  catalog_snapshot_mismatch: {
    title: "Guard's parts are on different versions",
    detail: "The background service and the protection runtime on this device come from different versions of Guard, so neither can answer for the other's extension list. Install the latest version of HOL Guard to put them back in step.",
  },
};

// Reason codes arrive as lower snake_case. Anything with a space is a sentence
// someone wrote for an operator, so it reaches the card unchanged.
function looksLikeReasonCode(message: string): boolean {
  return /^[a-z0-9]+(?:_[a-z0-9]+)+$/.test(message);
}

export function protectionCenterLoadError(message: string): ProtectionCenterLoadError {
  const trimmed = message.trim();
  if (looksLikeUnauthorizedSession(trimmed)) {
    return {
      title: "This view needs a signed local session",
      detail: "Open Extensions from the local Guard dashboard and try again after Guard signs this session.",
    };
  }
  const known = LOAD_ERROR_COPY[trimmed];
  if (known) return { ...known, reference: trimmed };
  if (looksLikeReasonCode(trimmed)) {
    return {
      title: "Extensions unavailable",
      detail: "Guard could not load your extension settings on this device. If trying again does not help, quit HOL Guard and open it again.",
      reference: trimmed,
    };
  }
  return {
    title: "Extensions unavailable",
    detail: trimmed || "Guard could not load your extension settings on this device.",
  };
}
