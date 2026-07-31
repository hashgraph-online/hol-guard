/**
 * Synthetic fixtures for Guard decision explanation view-model.
 *
 * Covers all five execution routes: host_native, local_contained,
 * remote_isolated, blocked, and degraded.
 */

import type {
  GuardDecisionExplanationViewModel,
  GuardUiBoundary,
  GuardUiExecutionRoute,
  GuardUiStateCallout,
} from "./assurance-view-model";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function callout(
  headline: string,
  explanation: string,
  actionLabel: string | null,
  tone: GuardUiStateCallout["tone"],
): GuardUiStateCallout {
  return { headline, explanation, actionLabel, tone };
}

// ---------------------------------------------------------------------------
// Fixtures — one per execution route
// ---------------------------------------------------------------------------

export const DECISION_HOST_NATIVE: GuardDecisionExplanationViewModel = {
  route: "host_native",
  explanation: callout(
    "Ran on host",
    "Your policy allowed this command to run directly on the host without an isolation requirement.",
    null,
    "info",
  ),
  achievedBoundary: "observed_host",
  attestationTrust: "unattested",
};

export const DECISION_LOCAL_CONTAINED: GuardDecisionExplanationViewModel = {
  route: "local_contained",
  explanation: callout(
    "Ran locally, contained",
    "Guard ran this command on your machine inside a local isolation boundary, as your policy required.",
    null,
    "ok",
  ),
  achievedBoundary: "os_isolated",
  attestationTrust: "self_attested",
};

export const DECISION_REMOTE_ISOLATED: GuardDecisionExplanationViewModel = {
  route: "remote_isolated",
  explanation: callout(
    "Ran in remote sandbox",
    "Guard executed this command inside a remote sandbox to meet the policy guarantee.",
    null,
    "ok",
  ),
  achievedBoundary: "controlled_host",
  attestationTrust: "verified",
};

export const DECISION_BLOCKED: GuardDecisionExplanationViewModel = {
  route: "blocked",
  explanation: callout(
    "Blocked",
    "Guard blocked this action because the required isolation guarantee could not be met. Nothing was executed.",
    "Review policy",
    "critical",
  ),
  achievedBoundary: null,
  attestationTrust: "unattested",
};

export const DECISION_DEGRADED: GuardDecisionExplanationViewModel = {
  route: "degraded",
  explanation: callout(
    "Ran with reduced assurance",
    "Guard allowed this action, but the achieved isolation was below the configured level because the provider was degraded.",
    "Review provider",
    "warn",
  ),
  achievedBoundary: "controlled_host",
  attestationTrust: "self_attested",
};

// ---------------------------------------------------------------------------
// Collection — keyed by route for easy lookup
// ---------------------------------------------------------------------------

export const DECISION_EXPLANATION_FIXTURES: Record<
  GuardUiExecutionRoute,
  GuardDecisionExplanationViewModel
> = {
  host_native: DECISION_HOST_NATIVE,
  local_contained: DECISION_LOCAL_CONTAINED,
  remote_isolated: DECISION_REMOTE_ISOLATED,
  blocked: DECISION_BLOCKED,
  degraded: DECISION_DEGRADED,
};

// ---------------------------------------------------------------------------
// Fixtures — Provider detail (one per health state)
// ---------------------------------------------------------------------------

import type { GuardProviderDetailViewModel } from "./assurance-view-model";

export const PROVIDER_DETAIL_HEALTHY: GuardProviderDetailViewModel = {
  providerLabel: "Local OS containment",
  computedLevel: "os_isolated",
  actualGuarantees: ["filesystem", "process", "network"],
  health: "healthy",
  healthFreshness: "fresh",
  driftDetected: false,
  remediation: null,
};

export const PROVIDER_DETAIL_VERIFYING: GuardProviderDetailViewModel = {
  providerLabel: "Cloud isolation service",
  computedLevel: "os_isolated",
  actualGuarantees: ["filesystem", "process"],
  health: "verifying",
  healthFreshness: "fresh",
  driftDetected: false,
  remediation: {
    headline: "Verification in progress",
    explanation:
      "The provider is being verified. Isolation guarantees are pending attestation.",
    actionLabel: "Wait for verification",
    tone: "info",
  },
};

export const PROVIDER_DETAIL_DEGRADED: GuardProviderDetailViewModel = {
  providerLabel: "Local OS containment",
  computedLevel: "controlled_host",
  actualGuarantees: ["filesystem", "process"],
  health: "degraded",
  healthFreshness: "stale",
  driftDetected: true,
  remediation: {
    headline: "Provider degraded",
    explanation:
      "This provider reports degraded health and its last verification is stale. Guarantees may be weaker than shown.",
    actionLabel: "Restart provider",
    tone: "warn",
  },
};

export const PROVIDER_DETAIL_UNAVAILABLE: GuardProviderDetailViewModel = {
  providerLabel: "Local OS containment",
  computedLevel: "observed_host",
  actualGuarantees: [],
  health: "unavailable",
  healthFreshness: "unknown",
  driftDetected: false,
  remediation: {
    headline: "Provider unavailable",
    explanation:
      "The isolation provider is not running. Executions fall back to host observation only, which provides no isolation guarantee.",
    actionLabel: "Restore provider",
    tone: "critical",
  },
};

export const PROVIDER_DETAIL_REVOKED: GuardProviderDetailViewModel = {
  providerLabel: "Local OS containment",
  computedLevel: "observed_host",
  actualGuarantees: [],
  health: "revoked",
  healthFreshness: "unknown",
  driftDetected: false,
  remediation: {
    headline: "Provider revoked",
    explanation:
      "This provider identity was revoked and is no longer trusted. Install a current provider to restore isolation.",
    actionLabel: "View replacement",
    tone: "critical",
  },
};

export const PROVIDER_DETAIL_INCOMPATIBLE: GuardProviderDetailViewModel = {
  providerLabel: "Legacy sandbox driver",
  computedLevel: "observed_host",
  actualGuarantees: [],
  health: "incompatible",
  healthFreshness: "stale",
  driftDetected: false,
  remediation: {
    headline: "Provider incompatible",
    explanation:
      "This provider version is not compatible with the current Guard release. Upgrade the provider to restore isolation guarantees.",
    actionLabel: "Upgrade provider",
    tone: "warn",
  },
};

export const PROVIDER_DETAIL_UNKNOWN: GuardProviderDetailViewModel = {
  providerLabel: "Hardware isolation engine",
  computedLevel: "hardware_isolated",
  actualGuarantees: ["filesystem", "process", "network", "power"],
  health: "unknown",
  healthFreshness: "unknown",
  driftDetected: false,
  remediation: {
    headline: "Provider status unknown",
    explanation:
      "We cannot confirm the health of this provider. Last telemetry is missing — isolation may be weaker than expected.",
    actionLabel: "Check provider",
    tone: "info",
  },
};
