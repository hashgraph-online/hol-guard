import type { IconType } from "react-icons";
import {
  HiMiniAdjustmentsHorizontal,
  HiMiniClipboardDocumentList,
  HiMiniDocumentText,
  HiMiniHome,
  HiMiniInbox,
  HiMiniInformationCircle,
  HiMiniPuzzlePiece,
  HiMiniShieldCheck,
  HiMiniSquares2X2,
} from "react-icons/hi2";

import type { AppView } from "./approval-center-primitives";
import type {
  GuardApprovalGatePublicConfig,
  GuardCloudUserProfile,
  GuardUpdatePhase,
  GuardUpdateStatus,
} from "./guard-types";

export type NavigationGroup = "primary" | "manage" | "support";
export type NavigationView = Exclude<AppView, "app-detail" | "audit" | "feed-health">;

export type ShellNavigationItem = {
  href: string;
  label: string;
  shortLabel: string;
  description: string;
  view: NavigationView;
  group: NavigationGroup;
  icon: IconType;
};

export type ShellNavigationProps = {
  queuedCount: number;
  view: AppView;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onNavigate: (pathname: string) => void;
  guardVersion?: string | null;
  updateStatus?: GuardUpdateStatus | null;
  onUpdateGuard?: () => void;
  onReinstallGuard?: () => void;
  updatePhase?: GuardUpdatePhase;
  updateError?: string | null;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  cloudUserProfile?: GuardCloudUserProfile | null;
  workspaceId?: string | null;
  planId?: string | null;
};

export const SHELL_NAV_ITEMS: readonly ShellNavigationItem[] = [
  {
    href: "/",
    label: "Home",
    shortLabel: "Home",
    description: "Protection overview and next actions",
    view: "home",
    group: "primary",
    icon: HiMiniHome,
  },
  {
    href: "/inbox",
    label: "Inbox",
    shortLabel: "Inbox",
    description: "Actions waiting for a Guard decision",
    view: "inbox",
    group: "primary",
    icon: HiMiniInbox,
  },
  {
    href: "/protect",
    label: "Protect",
    shortLabel: "Protect",
    description: "Apps, integrations, and protection health",
    view: "fleet",
    group: "primary",
    icon: HiMiniShieldCheck,
  },
  {
    href: "/evidence",
    label: "Evidence",
    shortLabel: "Evidence",
    description: "Receipts, commands, and security insights",
    view: "evidence",
    group: "primary",
    icon: HiMiniDocumentText,
  },
  {
    href: "/extensions",
    label: "Extensions",
    shortLabel: "Extensions",
    description: "Tools and capabilities protected on this device",
    view: "extensions",
    group: "manage",
    icon: HiMiniPuzzlePiece,
  },
  {
    href: "/policy",
    label: "Rules & exceptions",
    shortLabel: "Rules",
    description: "Remembered decisions, Guard Cloud rules, and exceptions",
    view: "policy",
    group: "manage",
    icon: HiMiniClipboardDocumentList,
  },
  {
    href: "/supply-chain",
    label: "Supply chain",
    shortLabel: "Supply",
    description: "Packages, audits, and feed health",
    view: "supply-chain",
    group: "manage",
    icon: HiMiniSquares2X2,
  },
  {
    href: "/settings",
    label: "Settings",
    shortLabel: "Settings",
    description: "Local Guard preferences and security",
    view: "settings",
    group: "manage",
    icon: HiMiniAdjustmentsHorizontal,
  },
  {
    href: "/about",
    label: "About",
    shortLabel: "About",
    description: "Version, support, and diagnostics",
    view: "about",
    group: "support",
    icon: HiMiniInformationCircle,
  },
] as const;

const MOBILE_PRIMARY_VIEWS = new Set<NavigationView>(["home", "inbox", "fleet", "evidence"]);

export const NAVIGATION_GROUPS: ReadonlyArray<{ id: NavigationGroup; label: string }> = [
  { id: "primary", label: "Guard" },
  { id: "manage", label: "Manage" },
  { id: "support", label: "Support" },
];

export function canonicalNavigationView(view: AppView): NavigationView {
  if (view === "app-detail") return "fleet";
  if (view === "audit" || view === "feed-health") return "supply-chain";
  return view;
}

export function navigationItemForView(view: AppView): ShellNavigationItem {
  const canonical = canonicalNavigationView(view);
  return SHELL_NAV_ITEMS.find((item) => item.view === canonical) ?? SHELL_NAV_ITEMS[0];
}

export function isNavigationItemActive(item: ShellNavigationItem, view: AppView): boolean {
  return item.view === canonicalNavigationView(view);
}

export function mobilePrimaryNavigationItems(): readonly ShellNavigationItem[] {
  return SHELL_NAV_ITEMS.filter((item) => MOBILE_PRIMARY_VIEWS.has(item.view));
}

export function isMobilePrimaryView(view: AppView): boolean {
  return MOBILE_PRIMARY_VIEWS.has(canonicalNavigationView(view));
}

export function queueCountDisplay(count: number): string {
  return count > 99 ? "99+" : String(count);
}

export function queueAriaLabel(count: number): string {
  if (count === 0) return "Inbox, no Guard actions waiting";
  return `Inbox, ${count} Guard ${count === 1 ? "action" : "actions"} waiting`;
}
