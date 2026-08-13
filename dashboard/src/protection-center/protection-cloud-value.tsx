import { useEffect, useState } from "react";

import type { GuardRuntimeSnapshot } from "../guard-types";
import { emitProtectionTelemetry } from "./protection-telemetry";
import { EXTENSION_PANEL_COMPACT_CLASS } from "./protection-surface";

export type ProtectionCloudPlan = "free" | "solo" | "pro" | "team" | "enterprise";

const PLAN_IDS = new Set<string>(["free", "solo", "pro", "team", "enterprise"]);

function isProtectionCloudPlan(value: string): value is ProtectionCloudPlan {
  return PLAN_IDS.has(value);
}

export type ProtectionCloudValue = {
  state: "offline" | "optional" | "connecting" | "connected";
  plan: ProtectionCloudPlan | null;
  label: string;
  detail: string;
};

export function protectionCloudPlan(runtime: GuardRuntimeSnapshot | null): ProtectionCloudPlan | null {
  const raw = runtime?.cloud_pairing_state?.plan_id?.trim().toLowerCase();
  return raw && isProtectionCloudPlan(raw) ? raw : null;
}

function connectedPlanDetail(plan: ProtectionCloudPlan | null): string {
  switch (plan) {
    case "solo":
      return "Solo adds personal cross-device continuity and Cloud history. Protection and blocking still run locally on this device.";
    case "pro":
      return "Pro adds extended Cloud history plus richer evidence and export workflows. Protection and blocking still run locally on this device.";
    case "team":
      return "Team adds organization coordination, policy continuity, and centralized audit. This device keeps enforcing locally if Cloud is unavailable.";
    case "enterprise":
      return "Enterprise adds organization policy, centralized oversight, and delegated workflows. This device keeps enforcing locally if Cloud is unavailable.";
    case "free":
      return "Cloud is connected for account continuity. Plan choices affect Cloud features only; protection and blocking still run locally on this device.";
    default:
      return "Cloud continuity is connected. Protection and blocking still run locally on this device.";
  }
}

export function protectionCloudValue(runtime: GuardRuntimeSnapshot | null, loadFailed = false): ProtectionCloudValue {
  if (loadFailed) {
    return {
      state: "offline",
      plan: null,
      label: "Cloud status unavailable",
      detail: "Local protection is active independently. Cloud status could not be refreshed.",
    };
  }
  if (!runtime || !runtime.sync_configured || runtime.cloud_state === "local_only") {
    return {
      state: "optional",
      plan: protectionCloudPlan(runtime),
      label: "This device is already protected",
      detail: "Local protection is active on this device. Guard Cloud keeps the same protections with you: synced module settings, searchable history, and organization policy your laptop cannot weaken.",
    };
  }
  if (runtime.cloud_state === "paired_waiting") {
    return {
      state: "connecting",
      plan: protectionCloudPlan(runtime),
      label: "Cloud continuity is connecting",
      detail: "Local protection remains active while Cloud pairing or synchronization finishes.",
    };
  }
  const plan = protectionCloudPlan(runtime);
  return {
    state: "connected",
    plan,
    label: plan ? `${plan[0].toUpperCase()}${plan.slice(1)} Cloud continuity` : "Cloud continuity connected",
    detail: connectedPlanDetail(plan),
  };
}

function safeHttpsDestination(candidate: string | null | undefined): string | null {
  if (!candidate) return null;
  try {
    const parsed = new URL(candidate);
    return parsed.protocol === "https:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}

export function protectionCloudDestination(runtime: GuardRuntimeSnapshot | null): string | null {
  const candidate = runtime?.sync_configured
    ? runtime.cloud_pairing_state?.dashboard_url || runtime.dashboard_url
    : runtime?.cloud_pairing_state?.connect_url || runtime?.connect_url;
  return safeHttpsDestination(candidate);
}

function benefitForPlan(plan: ProtectionCloudPlan | null): string {
  switch (plan) {
    case "solo":
      return "Keep personal protection history available across your connected devices.";
    case "pro":
      return "Keep longer Cloud history and richer evidence workflows available when you need them.";
    case "team":
      return "Coordinate organization policy and audit context without moving local enforcement into the Cloud.";
    case "enterprise":
      return "Centralize oversight and delegated workflows while every device continues enforcing locally.";
    default:
      return "Keep module settings and decision history with you across devices without moving local blocking into the Cloud.";
  }
}

function eligiblePlanCopy(plan: ProtectionCloudPlan | null, eligiblePlan?: ProtectionCloudPlan): string {
  if (eligiblePlan) return `Available on ${eligiblePlan[0].toUpperCase()}${eligiblePlan.slice(1)} Cloud.`;
  if (plan) return `Current Cloud plan: ${plan[0].toUpperCase()}${plan.slice(1)}.`;
  return "Availability is determined by your connected Guard Cloud plan.";
}

function telemetryCloudState(value: ProtectionCloudValue): "local_only" | "paired_waiting" | "paired_active" | "unavailable" {
  if (value.state === "connected") return "paired_active";
  if (value.state === "connecting") return "paired_waiting";
  if (value.state === "offline") return "unavailable";
  return "local_only";
}

/**
 * Gates Cloud value copy only. Local Protection Center controls must never be
 * passed through this component or conditioned on its state.
 */
export function CloudValueGate(props: {
  runtime: GuardRuntimeSnapshot | null;
  loading?: boolean;
  loadFailed?: boolean;
  benefit?: string;
  eligiblePlan?: ProtectionCloudPlan;
  destination?: string | null;
  dismissible?: boolean;
}) {
  const [dismissed, setDismissed] = useState(false);
  const value = protectionCloudValue(props.runtime, props.loadFailed);
  const destination = props.destination === undefined
    ? protectionCloudDestination(props.runtime)
    : safeHttpsDestination(props.destination);

  useEffect(() => {
    if (props.loading || dismissed) return;
    emitProtectionTelemetry("protection_cloud_value_viewed", {
      plan_id: value.plan ?? "unknown",
      cloud_state: telemetryCloudState(value),
    });
  }, [props.loading, value.plan, value.state]);

  if (dismissed) return null;

  return <aside
    aria-label="Cloud continuity"
    data-local-protection-independent="true"
    data-cloud-value-state={props.loading ? "loading" : value.state}
    className={EXTENSION_PANEL_COMPACT_CLASS}
  >
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <strong className="text-sm text-brand-dark">{props.loading ? "Checking Cloud continuity…" : value.label}</strong>
          {value.plan ? <span className="rounded-full bg-[rgba(85,153,254,0.1)] px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-brand-blue">{value.plan}</span> : null}
        </div>
        <p className="mt-1 text-xs leading-5 text-brand-dark/75">{props.loading ? "Local protection continues while Cloud status is checked." : value.detail}</p>
        {!props.loading ? <p className="mt-2 text-xs font-medium leading-5 text-brand-dark/80">{props.benefit ?? benefitForPlan(value.plan)}</p> : null}
        {!props.loading ? <p className="mt-1 text-[11px] leading-5 text-brand-dark/65">{eligiblePlanCopy(value.plan, props.eligiblePlan)}</p> : null}
        {destination && !props.loading ? <a href={destination} target="_blank" rel="noreferrer" className="mt-2 inline-flex min-h-9 items-center rounded-lg border border-[rgba(63,65,116,0.12)] bg-white/70 px-3 text-xs font-semibold text-brand-blue hover:bg-[rgba(85,153,254,0.08)]">{value.state === "connected" ? "Open Guard Cloud" : "Connect Guard Cloud"}</a> : null}
      </div>
      {props.dismissible !== false ? <button type="button" onClick={() => setDismissed(true)} aria-label="Hide Cloud continuity" className="min-h-9 rounded-lg px-2 text-xs font-semibold text-brand-dark/55 hover:bg-white/70 hover:text-brand-dark">Hide</button> : null}
    </div>
  </aside>;
}
