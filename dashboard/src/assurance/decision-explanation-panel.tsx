/**
 * Decision explanation panel — renders GuardDecisionExplanationViewModel.
 *
 * Displays the selected execution route, plain-language explanation
 * callout, achieved boundary (or none for blocked), and attestation-
 * trust tier with plain-language labels.  Never leaks command,
 * content, path, or secret.
 */

import { HiMiniCheckCircle, HiMiniShieldExclamation, HiMiniExclamationTriangle, HiMiniShieldCheck, HiMiniXCircle } from "react-icons/hi2";
import type {
  GuardDecisionExplanationViewModel,
  GuardUiBoundary,
  GuardUiExecutionRoute,
} from "./assurance-view-model";

// ---------------------------------------------------------------------------
// Route display
// ---------------------------------------------------------------------------

export function routeLabel(route: GuardUiExecutionRoute): string {
  switch (route) {
    case "host_native":
      return "Host";
    case "local_contained":
      return "Local Contained";
    case "remote_isolated":
      return "Remote Isolated";
    case "blocked":
      return "Blocked";
    case "degraded":
      return "Degraded";
  }
}

export function routeIconClass(route: GuardUiExecutionRoute): string {
  if (route === "blocked") return "text-red-500";
  if (route === "degraded") return "text-amber-500";
  if (route === "host_native") return "text-slate-500";
  return "text-green-600";
}

function routeIcon(route: GuardUiExecutionRoute) {
  if (route === "host_native") return HiMiniShieldExclamation;
  if (route === "blocked") return HiMiniXCircle;
  if (route === "degraded") return HiMiniExclamationTriangle;
  return HiMiniShieldCheck;
}

// ---------------------------------------------------------------------------
// Boundary display
// ---------------------------------------------------------------------------

export const BOUNDARY_LABELS: Record<GuardUiBoundary, string> = {
  observed_host: "Observed on host",
  controlled_host: "Controlled host",
  os_isolated: "OS-isolated",
  hardware_isolated: "Hardware-isolated",
};

// ---------------------------------------------------------------------------
// Attestation trust display
// ---------------------------------------------------------------------------

export const TRUST_LABELS: Record<
  GuardDecisionExplanationViewModel["attestationTrust"],
  { label: string; tone: "blue" | "green" | "amber" }
> = {
  unattested: { label: "Unattested", tone: "amber" },
  self_attested: { label: "Self-attested", tone: "blue" },
  verified: { label: "Verified", tone: "green" },
};

export function trustToneClass(tone: "blue" | "green" | "amber"): string {
  if (tone === "green") return "bg-green-100 text-green-700 border-green-200";
  if (tone === "blue") return "bg-blue-100 text-blue-700 border-blue-200";
  return "bg-amber-100 text-amber-700 border-amber-200";
}

// ---------------------------------------------------------------------------
// Callout styling — light-first, accent only for critical
// ---------------------------------------------------------------------------

export function calloutBodyClass(
  tone: GuardDecisionExplanationViewModel["explanation"]["tone"],
): string {
  if (tone === "ok") return "border-green-200 bg-green-50/80";
  if (tone === "info") return "border-blue-200 bg-blue-50/80";
  if (tone === "warn") return "border-amber-200 bg-amber-50/80";
  // critical — energetic accent
  return "border-red-200 bg-red-50/80";
}

// ---------------------------------------------------------------------------
// Public panel
// ---------------------------------------------------------------------------

export type DecisionExplanationPanelProps = {
  decision: GuardDecisionExplanationViewModel;
};

export function DecisionExplanationPanel({
  decision,
}: DecisionExplanationPanelProps) {
  const route = decision.route;
  const Icon = routeIcon(route);
  const trust = TRUST_LABELS[decision.attestationTrust];

  return (
    <div
      className="rounded-2xl border border-slate-200 bg-white p-5"
      data-testid="decision-explanation-panel"
    >
      {/* Route header */}
      <div className="mb-4 flex items-center gap-3">
        <Icon
          className={`h-5 w-5 shrink-0 ${routeIconClass(route)}`}
          aria-hidden="true"
        />
        <h3 className="text-lg font-semibold tracking-tight text-brand-dark">
          {routeLabel(route)}
        </h3>
      </div>

      {/* Explanation callout */}
      <div
        className={`mb-4 rounded-xl border px-4 py-3 ${calloutBodyClass(
          decision.explanation.tone,
        )}`}
        role="status"
      >
        <p className="text-sm font-semibold text-brand-dark">
          {decision.explanation.headline}
        </p>
        <p className="mt-1 text-xs leading-relaxed text-slate-600">
          {decision.explanation.explanation}
        </p>
        {decision.explanation.actionLabel && (
          <p className="mt-2 text-xs font-medium text-brand-blue">
            {decision.explanation.actionLabel}
          </p>
        )}
      </div>

      {/* Boundary + trust grid */}
      <div className="mt-2 grid grid-cols-2 gap-4">
        {/* Achieved boundary */}
        {decision.achievedBoundary !== null ? (
          <div>
            <dt className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Boundary
            </dt>
            <dd className="mt-1 text-sm text-slate-700">
              {BOUNDARY_LABELS[decision.achievedBoundary]}
            </dd>
          </div>
        ) : (
          <div>
            <dt className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Boundary
            </dt>
            <dd className="mt-1 text-sm text-slate-400">
              None — action blocked
            </dd>
          </div>
        )}

        {/* Attestation trust */}
        <div>
          <dt className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Trust
          </dt>
          <dd className="mt-1">
            <span
              className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${trustToneClass(
                trust.tone,
              )}`}
            >
              {trust.label}
            </span>
          </dd>
        </div>
      </div>
    </div>
  );
}
