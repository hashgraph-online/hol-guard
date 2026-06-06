import type { ReactNode } from "react";
import {
  HiMiniAdjustmentsHorizontal,
  HiMiniBellAlert,
  HiMiniLockClosed,
  HiMiniShieldCheck,
} from "react-icons/hi2";

export type LocalSettingsTabKey = "protection" | "approval" | "notifications" | "advanced";

export type LocalSettingsNavGroupKey = "local";

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
}

export const localSettingsNavGroups: readonly LocalSettingsNavGroup[] = [
  {
    key: "local",
    label: "This machine",
    summary: "Protection, approval gate, alerts, and fine-tuning for local Guard.",
  },
] as const;

const ICON_PROTECTION = <HiMiniShieldCheck className="h-4 w-4" aria-hidden="true" />;
const ICON_APPROVAL = <HiMiniLockClosed className="h-4 w-4" aria-hidden="true" />;
const ICON_NOTIFICATIONS = <HiMiniBellAlert className="h-4 w-4" aria-hidden="true" />;
const ICON_ADVANCED = <HiMiniAdjustmentsHorizontal className="h-4 w-4" aria-hidden="true" />;

export const localSettingsNavItems: readonly LocalSettingsNavItem[] = [
  {
    key: "protection",
    label: "Protection",
    summary: "Security level, mode, sync, and what Guard pauses.",
    group: "local",
    icon: ICON_PROTECTION,
  },
  {
    key: "approval",
    label: "Approval gate",
    summary: "Password, authenticator, cooldown, and strict decisions.",
    group: "local",
    icon: ICON_APPROVAL,
  },
  {
    key: "notifications",
    label: "Notifications",
    summary: "Desktop alerts when Guard needs your attention.",
    group: "local",
    icon: ICON_NOTIFICATIONS,
  },
  {
    key: "advanced",
    label: "Advanced",
    summary: "Risk controls, diagnostics, export, and maintenance.",
    group: "local",
    icon: ICON_ADVANCED,
  },
] as const;

export const localSettingsTabLabels: Record<LocalSettingsTabKey, string> = {
  protection: "Protection",
  approval: "Approval gate",
  notifications: "Notifications",
  advanced: "Advanced",
};

export function isLocalSettingsTabKey(value: string): value is LocalSettingsTabKey {
  return value === "protection" || value === "approval" || value === "notifications" || value === "advanced";
}
