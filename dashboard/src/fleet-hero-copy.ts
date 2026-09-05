import type { GuardProtectionState } from "./guard-types";
import { SUPPORTED_APPS_BRIEF } from "./apps/app-catalog";

const SUPPORTED_APPS_COPY = SUPPORTED_APPS_BRIEF;

type FleetHeroUrls = {
  fleet_url: string;
  dashboard_url: string;
  connect_url: string;
};

export type FleetHeroCopy = {
  status: "clear" | "setup_gap" | "partial" | "degraded" | "checking";
  headline: string;
  subheadline: string;
  primaryCtaLabel: string;
  primaryCtaHref: string;
  primaryCtaStartsCloudConnect: boolean;
  secondaryCtaLabel: string;
  secondaryCtaHref: string;
  secondaryCtaStartsCloudConnect: boolean;
};

export function resolveFleetHeroCopy(
  cloudState: "local_only" | "paired_waiting" | "paired_active",
  activeInstallCount: number,
  protectionState: GuardProtectionState | "checking",
  urls: FleetHeroUrls
): FleetHeroCopy {
  const hasApps = activeInstallCount > 0;
  if (hasApps && protectionState === "checking") {
    return {
      status: "checking",
      headline: "Checking app protection",
      subheadline: "Guard is confirming local protection. This takes a moment.",
      primaryCtaLabel: "Open Protect",
      primaryCtaHref: urls.fleet_url,
      primaryCtaStartsCloudConnect: false,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
      secondaryCtaStartsCloudConnect: false,
    };
  }
  if (hasApps && protectionState !== "protected") {
    return {
      status: protectionState,
      headline: protectionState === "partial" ? "Apps are partially protected" : "App protection is degraded",
      subheadline:
        protectionState === "partial"
          ? "Core protection passes. Finish the remaining proofs below to reach full protection."
          : "Some protection checks failed or remain unproven. Use the steps below to restore full protection.",
      primaryCtaLabel: "Restore full protection",
      primaryCtaHref: "#protection-recovery",
      primaryCtaStartsCloudConnect: false,
      secondaryCtaLabel: cloudState === "local_only" ? "Connect this machine" : "Open Cloud Devices",
      secondaryCtaHref: cloudState === "local_only" ? urls.connect_url : urls.fleet_url,
      secondaryCtaStartsCloudConnect: cloudState === "local_only",
    };
  }
  if (cloudState === "local_only") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Your apps are covered" : "Connect an app to start",
      subheadline: hasApps
        ? "Guard is protecting your local AI apps."
        : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Connect this machine",
      primaryCtaHref: urls.connect_url,
      primaryCtaStartsCloudConnect: true,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
      secondaryCtaStartsCloudConnect: false,
    };
  }
  if (cloudState === "paired_waiting") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Apps covered, first proof pending" : "Connect an app to start",
      subheadline: hasApps
        ? "Guard is running. First cloud proof is on its way."
        : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Open Cloud Devices",
      primaryCtaHref: urls.fleet_url,
      primaryCtaStartsCloudConnect: false,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
      secondaryCtaStartsCloudConnect: false,
    };
  }
  return {
    status: hasApps ? "clear" : "setup_gap",
    headline: hasApps ? "Your apps are covered" : "Connect an app to start",
    subheadline: hasApps
      ? "Confirm that Guard is running and protecting your local AI apps."
      : SUPPORTED_APPS_COPY,
    primaryCtaLabel: "Open Cloud Devices",
    primaryCtaHref: urls.fleet_url,
    primaryCtaStartsCloudConnect: false,
    secondaryCtaLabel: "Open Home",
    secondaryCtaHref: urls.dashboard_url,
    secondaryCtaStartsCloudConnect: false,
  };
}
