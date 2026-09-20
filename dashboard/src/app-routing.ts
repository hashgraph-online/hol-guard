import type { AppView } from "./approval-center-primitives";
import { normalizeHarnessSlug } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import { commitDashboardLocation } from "./dashboard-location";

export function navigate(pathname: string): void {
  commitDashboardLocation(guardAwareHref(pathname));
}

export function focusVisibleDashboardSearch(): boolean {
  const candidates = document.querySelectorAll<HTMLInputElement>(
    'input[type="search"], input[role="searchbox"]',
  );
  for (const input of candidates) {
    if (input.closest("[hidden], [inert]")) continue;
    input.focus();
    return true;
  }
  return false;
}

export function parseRequestId(pathname: string): string | null {
  if (pathname.startsWith("/requests/")) {
    return pathname.slice("/requests/".length);
  }
  if (pathname.startsWith("/approvals/")) {
    return pathname.slice("/approvals/".length);
  }
  return null;
}

export const PROTECT_ROUTE = "/protect";
export const TODAY_EVIDENCE_ROUTE = "/evidence?time=today";

export function viewTitle(view: AppView): string {
  if (view === "home") return "Home";
  if (view === "inbox") return "Inbox";
  if (view === "fleet") return "Protect";
  if (view === "evidence") return "Evidence";
  if (view === "settings") return "Settings";
  if (view === "supply-chain") return "Supply Chain";
  if (view === "audit") return "Audit";
  if (view === "policy") return "Rules & exceptions";
  if (view === "feed-health") return "Feed Health";
  if (view === "about") return "About";
  if (view === "extensions") return "Extensions";
  return "App detail";
}

export function parseAppDetail(pathname: string): string | null {
  if (!pathname.startsWith("/apps/")) {
    return null;
  }
  const rawSlug = pathname.slice("/apps/".length);
  try {
    return normalizeHarnessSlug(decodeURIComponent(rawSlug));
  } catch {
    return null;
  }
}

export function resolveView(pathname: string): AppView {
  if (parseAppDetail(pathname) !== null) {
    return "app-detail";
  }
  if (pathname.startsWith("/apps/")) {
    return "fleet";
  }
  if (pathname === "/extensions" || pathname.startsWith("/extensions/")) {
    return "extensions";
  }
  if (pathname === "/settings") {
    return "settings";
  }
  if (pathname === PROTECT_ROUTE) {
    return "fleet";
  }
  if (pathname === "/evidence") {
    return "evidence";
  }
  if (pathname === "/supply-chain") {
    return "supply-chain";
  }
  if (pathname === "/audit") {
    return "audit";
  }
  if (pathname === "/policy") {
    return "policy";
  }
  if (pathname === "/feed-health") {
    return "feed-health";
  }
  if (pathname === "/about") {
    return "about";
  }
  if (
    pathname === "/inbox" ||
    pathname === "/requests" ||
    pathname === "/approvals" ||
    pathname.startsWith("/requests/") ||
    pathname.startsWith("/approvals/")
  ) {
    return "inbox";
  }
  return "home";
}
