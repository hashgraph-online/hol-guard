/**
 * Frozen UI data contracts for Guard local protection status.
 *
 * Five separate channels — interception, policy, assurance, self-protection,
 * cloud-sync — each with its own state. No single global protection badge.
 *
 * Derived from the portal contracts in
 * `execution-assurance-view-models.ts` and `execution-assurance-fixtures.ts`.
 */

// ---------------------------------------------------------------------------
// Shared primitives (mirror of portal types)
// ---------------------------------------------------------------------------

export type GuardUiProtectionChannelState =
  | "active"
  | "inactive"
  | "degraded"
  | "unknown";

export interface GuardUiStateCallout {
  readonly headline: string;
  readonly explanation: string;
  readonly actionLabel: string | null;
  readonly tone: "ok" | "info" | "warn" | "critical";
}

// ---------------------------------------------------------------------------
// Local protection status
// ---------------------------------------------------------------------------

export interface GuardLocalProtectionStatusViewModel {
  readonly interception: GuardUiProtectionChannelState;
  readonly policy: GuardUiProtectionChannelState;
  readonly assurance: GuardUiProtectionChannelState;
  readonly selfProtection: GuardUiProtectionChannelState;
  readonly cloudSync: GuardUiProtectionChannelState;
  readonly summary: GuardUiStateCallout;
}

// ---------------------------------------------------------------------------
// Synthetic fixtures (mirror of portal fixtures)
// ---------------------------------------------------------------------------

export const PROTECTION_STATUS_ALL_ACTIVE: GuardLocalProtectionStatusViewModel =
  {
    interception: "active",
    policy: "active",
    assurance: "active",
    selfProtection: "active",
    cloudSync: "active",
    summary: {
      headline: "Fully protected",
      explanation:
        "Interception, policy, assurance, self-protection, and Cloud sync are all active on this machine.",
      actionLabel: null,
      tone: "ok",
    },
  };

export const PROTECTION_STATUS_ASSURANCE_DEGRADED: GuardLocalProtectionStatusViewModel =
  {
    interception: "active",
    policy: "active",
    assurance: "degraded",
    selfProtection: "active",
    cloudSync: "active",
    summary: {
      headline: "Assurance degraded",
      explanation:
        "Commands are still intercepted and policy is enforced, but the isolation provider is degraded. Execution assurance is weaker than configured.",
      actionLabel: "Review provider",
      tone: "warn",
    },
  };

export const PROTECTION_STATUS_CLOUD_SYNC_INACTIVE: GuardLocalProtectionStatusViewModel =
  {
    interception: "active",
    policy: "active",
    assurance: "active",
    selfProtection: "active",
    cloudSync: "inactive",
    summary: {
      headline: "Cloud sync paused",
      explanation:
        "Local protection is fully active, but receipts and evidence are not syncing to Cloud. Local enforcement continues.",
      actionLabel: "Reconnect",
      tone: "info",
    },
  };

export const PROTECTION_STATUS_INTERCEPTION_INACTIVE: GuardLocalProtectionStatusViewModel =
  {
    interception: "inactive",
    policy: "active",
    assurance: "active",
    selfProtection: "active",
    cloudSync: "active",
    summary: {
      headline: "Interception inactive",
      explanation:
        "Command interception is not active. Commands may execute without Guard oversight.",
      actionLabel: "Enable interception",
      tone: "critical",
    },
  };

export const PROTECTION_STATUS_POLICY_INACTIVE: GuardLocalProtectionStatusViewModel =
  {
    interception: "active",
    policy: "inactive",
    assurance: "active",
    selfProtection: "active",
    cloudSync: "active",
    summary: {
      headline: "Policy enforcement inactive",
      explanation:
        "Policy engine is not active. Commands are intercepted but not evaluated against your policy.",
      actionLabel: "Enable policy",
      tone: "critical",
    },
  };
