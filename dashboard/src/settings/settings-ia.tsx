import type { ReactNode } from "react";
import {
  HiMiniAdjustmentsHorizontal,
  HiMiniBellAlert,
  HiMiniCircleStack,
  HiMiniCloud,
  HiMiniLockClosed,
  HiMiniShieldCheck,
  HiMiniSquares2X2,
} from "react-icons/hi2";

export type LocalSettingsTabKey =
  | "protection"
  | "apps"
  | "approval"
  | "notifications"
  | "rules"
  | "maintenance"
  | "cloud-actions";

export type LocalSettingsNavGroupKey = "local" | "cloud";

export interface LocalSettingsNavGroup {
  key: LocalSettingsNavGroupKey;
  label: string;
  summary: string;
}

export interface LocalSettingsNavItem {
  key: LocalSettingsTabKey;
  label: string;
  summary: string;
  group: LocalSettingsNavGroupKey;
  icon: ReactNode;
  mobileLabel?: string;
}

export const localSettingsNavGroups: readonly LocalSettingsNavGroup[] = [
  {
    key: "local",
    label: "This machine",
    summary: "Protection, approval checks, alerts, tuning, and local upkeep.",
  },
  {
    key: "cloud",
    label: "Guard Cloud",
    summary: "Sign-ins to Guard Cloud. Protection on this machine does not depend on them.",
  },
] as const;

const ICON_PROTECTION = <HiMiniShieldCheck className="h-4 w-4" aria-hidden="true" />;
const ICON_APPS = <HiMiniSquares2X2 className="h-4 w-4" aria-hidden="true" />;
const ICON_APPROVAL = <HiMiniLockClosed className="h-4 w-4" aria-hidden="true" />;
const ICON_NOTIFICATIONS = <HiMiniBellAlert className="h-4 w-4" aria-hidden="true" />;
const ICON_RISK = <HiMiniAdjustmentsHorizontal className="h-4 w-4" aria-hidden="true" />;
const ICON_MAINTENANCE = <HiMiniCircleStack className="h-4 w-4" aria-hidden="true" />;
const ICON_CLOUD_ACTIONS = <HiMiniCloud className="h-4 w-4" aria-hidden="true" />;

export const localSettingsNavItems: readonly LocalSettingsNavItem[] = [
  {
    key: "protection",
    label: "Protection",
    mobileLabel: "Protect",
    summary: "Security level, mode, sync, and what Guard pauses.",
    group: "local",
    icon: ICON_PROTECTION,
  },
  {
    key: "apps",
    label: "Apps",
    mobileLabel: "Apps",
    summary: "Choose protection or Watch for each app on this machine.",
    group: "local",
    icon: ICON_APPS,
  },
  {
    key: "approval",
    label: "Approval gate",
    mobileLabel: "Gate",
    summary: "Password, app code, cooldown, and extra checks.",
    group: "local",
    icon: ICON_APPROVAL,
  },
  {
    key: "notifications",
    label: "Notifications",
    mobileLabel: "Alerts",
    summary: "Desktop alerts when Guard needs your attention.",
    group: "local",
    icon: ICON_NOTIFICATIONS,
  },
  {
    key: "rules",
    label: "Protection rules",
    mobileLabel: "Rules",
    summary: "Tune risky actions and advanced fallback behavior.",
    group: "local",
    icon: ICON_RISK,
  },
  {
    key: "maintenance",
    label: "Data & repair",
    mobileLabel: "Data",
    summary: "Export, reset, clear logs, and fix connection issues.",
    group: "local",
    icon: ICON_MAINTENANCE,
  },
  {
    key: "cloud-actions",
    label: "Cloud actions",
    mobileLabel: "Cloud",
    summary: "Which workspaces AI tools here are signed in to, and whether Guard Cloud still accepts them.",
    group: "cloud",
    icon: ICON_CLOUD_ACTIONS,
  },
] as const;


export const localSettingsMobileTabLabels: Record<LocalSettingsTabKey, string> = Object.fromEntries(
  localSettingsNavItems.map((item) => [item.key, item.mobileLabel ?? item.label]),
) as Record<LocalSettingsTabKey, string>;

export const localSettingsTabLabels: Record<LocalSettingsTabKey, string> = {
  protection: "Protection",
  apps: "Apps",
  approval: "Approval gate",
  notifications: "Notifications",
  rules: "Protection rules",
  maintenance: "Data & repair",
  "cloud-actions": "Cloud actions",
};

export function isLocalSettingsTabKey(value: string): value is LocalSettingsTabKey {
  return (
    value === "protection"
    || value === "apps"
    || value === "approval"
    || value === "notifications"
    || value === "rules"
    || value === "maintenance"
    || value === "cloud-actions"
  );
}
