/**
 * Frozen UI data contracts for Guard execution assurance.
 * Copied from hol-portal-eai-w3-followup/src/lib/guard/ui/execution-assurance-view-models.ts
 * to avoid cross-repo imports in the dashboard.
 */

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

export type GuardUiBoundary =
  | "observed_host"
  | "controlled_host"
  | "os_isolated"
  | "hardware_isolated";

export type GuardUiProviderHealth =
  | "unknown"
  | "verifying"
  | "healthy"
  | "degraded"
  | "unavailable"
  | "revoked"
  | "incompatible";

/** Plain-language state explanation with one clear action. */
export interface GuardUiStateCallout {
  readonly headline: string;
  readonly explanation: string;
  readonly actionLabel: string | null;
  readonly tone: "ok" | "info" | "warn" | "critical";
}

// ---------------------------------------------------------------------------
// Provider detail
// ---------------------------------------------------------------------------

export interface GuardProviderDetailViewModel {
  readonly providerLabel: string;
  readonly computedLevel: GuardUiBoundary;
  readonly actualGuarantees: readonly string[];
  readonly health: GuardUiProviderHealth;
  readonly healthFreshness: "fresh" | "stale" | "unknown";
  readonly driftDetected: boolean;
  readonly remediation: GuardUiStateCallout | null;
}

// ---------------------------------------------------------------------------
// Local protection status
// ---------------------------------------------------------------------------

export type GuardUiProtectionChannelState =
  | "active"
  | "inactive"
  | "degraded"
  | "unknown";

export interface GuardLocalProtectionStatusViewModel {
  readonly interception: GuardUiProtectionChannelState;
  readonly policy: GuardUiProtectionChannelState;
  readonly assurance: GuardUiProtectionChannelState;
  readonly selfProtection: GuardUiProtectionChannelState;
  readonly cloudSync: GuardUiProtectionChannelState;
  readonly summary: GuardUiStateCallout;
}

// ---------------------------------------------------------------------------
// Decision explanation (no command/content leak)
// ---------------------------------------------------------------------------

export type GuardUiAttestationTrust =
  | "unattested"
  | "self_attested"
  | "verified";

export type GuardUiExecutionRoute =
  | "host_native"
  | "local_contained"
  | "remote_isolated"
  | "blocked"
  | "degraded";

export interface GuardDecisionExplanationViewModel {
  readonly route: GuardUiExecutionRoute;
  readonly explanation: GuardUiStateCallout;
  readonly achievedBoundary: GuardUiBoundary | null;
  readonly attestationTrust: GuardUiAttestationTrust;
}
