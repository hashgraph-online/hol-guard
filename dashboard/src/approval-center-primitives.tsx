import { forwardRef } from "react";
import type { ButtonHTMLAttributes, ChangeEvent, ReactNode, Ref } from "react";
import {
  HiMiniArrowTopRightOnSquare,
  HiMiniCloud,
  HiMiniCommandLine,
  HiMiniDocumentText,
  HiMiniHome,
  HiMiniInbox,
  HiMiniAdjustmentsHorizontal,
  HiMiniShieldCheck,
  HiMiniInformationCircle,
  HiMiniClipboardDocumentList,
  HiBars3,
  HiMiniXMark as HiMiniXMarkLayout,
  HiMiniCheckCircle,
  HiMiniArrowRight,
  HiMiniExclamationTriangle,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniChevronLeft,
  HiMiniChevronRight,
  HiMiniMagnifyingGlass,
  HiMiniLink,
  HiMiniBugAnt,
  HiMiniCog6Tooth,
  HiMiniSquares2X2,
} from "react-icons/hi2";

import { guardAwareHref } from "./guard-api";
import { EMPTY_QUEUE_TITLE } from "./approval-center-utils";
import { GuardUpdatePanel } from "./guard-update-panel";
import { GITHUB_ISSUE_BUTTON_LABEL, GITHUB_ISSUE_LINK } from "./github-issue-link";
import type { GuardUpdatePhase, GuardUpdateStatus } from "./guard-types";

const footerSections = [
  {
    title: "Guard",
    links: [
      { href: "https://hol.org/guard", label: "Cloud Dashboard" },
      { href: "https://hol.org/guard/pricing", label: "Pricing" },
      { href: "https://hol.org/guard/docs", label: "Docs" }
    ]
  },
  {
    title: "Docs",
    links: [
      { href: "https://hol.org/registry/docs", label: "API Reference" },
      { href: "https://hol.org/docs/libraries/standards-sdk", label: "Standards SDK" },
      { href: "https://hol.org/docs/standards/hcs-1", label: "Standards" }
    ]
  },
  {
    title: "Community",
    links: [
      { href: "https://x.com/HashgraphOnline", label: "X" },
      { href: "https://t.me/hashinals", label: "Telegram" }
    ]
  },
  {
    title: "More",
    links: [
      { href: "https://hol.org/blog", label: "Blog" },
      { href: "https://github.com/hashgraph-online", label: "GitHub" },
      { href: GITHUB_ISSUE_LINK, label: GITHUB_ISSUE_BUTTON_LABEL },
      { href: "https://hol.org/points/legal/privacy", label: "Privacy Policy" },
      { href: "https://hol.org/points/legal/terms", label: "Terms of Service" }
    ]
  }
] as const;

export type AppView =
  | "home"
  | "inbox"
  | "fleet"
  | "evidence"
  | "settings"
  | "app-detail"
  | "supply-chain"
  | "audit"
  | "policy"
  | "feed-health"
  | "about";

export function ShellHeader(props: {
  queuedCount: number;
  view: AppView;
  onNavigate: (pathname: string) => void;
  onOpenMobileQueue?: () => void;
  guardVersion?: string | null;
  updateStatus?: GuardUpdateStatus | null;
  onUpdateGuard?: () => void;
  onReinstallGuard?: () => void;
  updatePhase?: GuardUpdatePhase;
}) {
  function handleMobileNavigationChange(event: ChangeEvent<HTMLSelectElement>) {
    props.onNavigate(event.target.value);
  }

  const countDisplay = props.queuedCount > 99 ? "99+" : String(props.queuedCount);

  return (
    <header
      className="sticky top-0 z-30 flex min-h-16 items-center border-b border-brand-blue/20 bg-gradient-to-r from-brand-blue to-brand-dark px-4 text-white shadow-sm lg:hidden"
      style={{ contain: "layout style paint" }}
    >
      <div className="flex w-full items-center gap-3">
        <a
          href={guardAwareHref("/")}
          className="flex min-h-11 min-w-0 items-center gap-2.5 text-white no-underline transition-opacity duration-150 hover:opacity-85"
        >
          <img src="/brand/Logo_Icon_Dark.png" alt="HOL" className="h-9 w-9 shrink-0 rounded-none bg-transparent object-contain" />
          <span className="font-mono text-base font-semibold tracking-tight text-white hidden sm:inline">HOL Guard</span>
        </a>
        <div className="min-w-0 flex-1">
          <select
            id="guard-mobile-navigation"
            name="guard-mobile-navigation"
            aria-label="Navigate Guard sections"
            className="h-11 w-full rounded-full border border-white/25 bg-white/95 px-4 text-sm font-medium text-brand-dark shadow-none transition-colors duration-150 focus:border-white focus:outline-none focus:ring-2 focus:ring-white/40"
            onChange={handleMobileNavigationChange}
            value={sidebarLinks.find((item) => item.view === props.view)?.href ?? (hubViews.has(props.view) ? "/supply-chain" : "/")}
          >
            {sidebarLinks.map((item) => (
              <option key={item.href} value={item.href}>
                {item.label}
              </option>
            ))}
          </select>
        </div>
        {props.onOpenMobileQueue && props.view === "inbox" && props.queuedCount > 0 && (
          <button
            type="button"
            onClick={props.onOpenMobileQueue}
            aria-label={`Open queue list — ${props.queuedCount} decisions waiting`}
            className="inline-flex min-h-11 shrink-0 items-center gap-1.5 rounded-full border border-white/25 bg-white/10 px-3 py-2 text-sm font-semibold text-white no-underline transition-colors duration-150 hover:bg-white/15"
          >
            <HiBars3 className="h-4 w-4" aria-hidden="true" />
            <span className="hidden sm:inline">
              {props.queuedCount > 1
                ? `${countDisplay} decisions waiting`
                : countDisplay}
            </span>
            <span className="sm:hidden">{countDisplay}</span>
          </button>
        )}
        {(!props.onOpenMobileQueue || props.view !== "inbox" || props.queuedCount === 0) && (
          <a
            href={guardAwareHref("/inbox")}
            className="inline-flex min-h-11 shrink-0 items-center rounded-full border border-white/25 bg-white/10 px-3 py-2 text-sm font-semibold text-white no-underline transition-colors duration-150 hover:bg-white/15"
            aria-label={`${props.queuedCount} Guard actions queued`}
          >
            {props.queuedCount > 99 ? "99+" : props.queuedCount}
          </a>
        )}
        <a
          href={GITHUB_ISSUE_LINK}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={GITHUB_ISSUE_BUTTON_LABEL}
          className="inline-flex min-h-11 shrink-0 items-center rounded-full border border-white/25 bg-white/10 px-3 py-2 text-sm font-semibold text-white no-underline transition-colors duration-150 hover:bg-white/15"
        >
          <HiMiniBugAnt className="h-4 w-4" aria-hidden="true" />
        </a>
        {props.guardVersion ? (
          <span
            className="hidden min-h-11 shrink-0 items-center rounded-full border border-white/20 bg-white/10 px-2.5 font-mono text-[10px] text-white/85 sm:inline-flex"
            aria-label={`Guard version ${props.guardVersion}`}
            title={`Guard version ${props.guardVersion}`}
          >
            v{props.guardVersion}
          </span>
        ) : null}
        {props.updateStatus?.update_available && props.onUpdateGuard ? (
          <button
            type="button"
            onClick={props.onUpdateGuard}
            disabled={props.updatePhase === "updating" || props.updatePhase === "reconnecting"}
            className="inline-flex min-h-11 shrink-0 items-center rounded-full border border-white/25 bg-white px-3 py-2 text-xs font-semibold text-brand-blue transition-colors duration-150 hover:bg-white/90 focus:outline-none focus-visible:ring-2 focus-visible:ring-white/50 disabled:cursor-not-allowed disabled:opacity-70"
            aria-label="Update Guard to the latest version"
          >
            {props.updatePhase === "updating" || props.updatePhase === "reconnecting" ? "Updating…" : "Update"}
          </button>
        ) : null}
      </div>
    </header>
  );
}

const hubViews = new Set(["audit", "feed-health"]);

const sidebarLinks = [
  { href: "/", label: "Home", view: "home", icon: HiMiniHome },
  { href: "/inbox", label: "Inbox", view: "inbox", icon: HiMiniInbox },
  { href: "/protect", label: "Protect", view: "fleet", icon: HiMiniShieldCheck },
  { href: "/evidence", label: "Evidence", view: "evidence", icon: HiMiniDocumentText },
  { href: "/supply-chain", label: "Supply chain", view: "supply-chain", icon: HiMiniSquares2X2 },
  { href: "/policy", label: "Policy", view: "policy", icon: HiMiniClipboardDocumentList },
  { href: "/settings", label: "Settings", view: "settings", icon: HiMiniAdjustmentsHorizontal },
  { href: "/about", label: "About", view: "about", icon: HiMiniInformationCircle }
] as const;

export function ShellSidebar(props: {
  queuedCount: number;
  view: AppView;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  guardVersion?: string | null;
  updateStatus?: GuardUpdateStatus | null;
  onUpdateGuard?: () => void;
  onReinstallGuard?: () => void;
  updatePhase?: GuardUpdatePhase;
}) {
  const collapsed = props.collapsed ?? false;
  return (
    <aside className={`fixed inset-y-0 left-0 z-40 hidden flex-col border-r border-slate-200 bg-[#f8fafc] transition-all duration-200 lg:flex ${collapsed ? "w-20" : "w-64"}`}>
      <div className="flex min-h-[72px] shrink-0 items-center border-b border-brand-blue/20 bg-gradient-to-r from-brand-blue to-brand-dark px-6">
        <a href={guardAwareHref("/")} className="flex items-center gap-2.5 text-white no-underline transition-opacity hover:opacity-85" title="HOL Guard">
          <img src="/brand/Logo_Icon_Dark.png" alt="HOL" className="h-10 w-10 shrink-0 rounded-none bg-transparent object-contain" />
          {!collapsed && <span className="font-mono text-base font-semibold tracking-tight text-white">HOL Guard</span>}
        </a>
        {!collapsed && (
          <button
            onClick={props.onToggleCollapse}
            className="ml-auto rounded-md p-1 text-white/60 transition-colors hover:bg-white/10 hover:text-white"
            aria-label="Collapse sidebar"
            title="Collapse sidebar"
          >
            <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
          </button>
        )}
        {collapsed && (
          <button
            onClick={props.onToggleCollapse}
            className="absolute -right-3 top-6 rounded-full border border-slate-200 bg-white p-1 text-slate-400 shadow-sm transition-colors hover:text-brand-dark"
            aria-label="Expand sidebar"
            title="Expand sidebar"
          >
            <HiMiniChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        )}
      </div>
      <div className="flex flex-1 flex-col overflow-y-auto px-3 py-5">
        {!collapsed && (
          <p className="mb-2 px-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-400">
            Guard
          </p>
        )}
        <nav className="flex flex-col gap-0.5" aria-label="Guard dashboard">
          {sidebarLinks.map((item) => {
            const Icon = item.icon;
            return (
              <SidebarLink
                key={item.href}
                href={item.href}
                active={props.view === item.view || (props.view === "app-detail" && item.view === "fleet") || (item.view === "supply-chain" && hubViews.has(props.view))}
                icon={<Icon className="h-4 w-4" />}
                badgeCount={item.view === "inbox" ? props.queuedCount : 0}
                collapsed={collapsed}
              >
                {item.label}
              </SidebarLink>
            );
          })}
        </nav>

        {!collapsed && (
          <div className="mt-6 space-y-2">
            <p className="px-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-400">
              Quick Actions
            </p>
            <SidebarAction href="/" icon={<HiMiniCommandLine className="h-4 w-4" aria-hidden="true" />}>
              Local dashboard
            </SidebarAction>
            <SidebarAction href="https://hol.org/guard" external icon={<HiMiniCloud className="h-4 w-4" aria-hidden="true" />}>
              Open Guard Cloud
            </SidebarAction>
            <SidebarAction href={GITHUB_ISSUE_LINK} external icon={<HiMiniBugAnt className="h-4 w-4" aria-hidden="true" />}>
              {GITHUB_ISSUE_BUTTON_LABEL}
            </SidebarAction>
          </div>
        )}

        <div className="mt-auto pt-6">
          {!collapsed ? (
            <div className="mx-2 overflow-hidden rounded-xl border border-brand-blue/25 bg-gradient-to-br from-brand-blue/[0.05] to-brand-dark/[0.03]">
              <div className="space-y-2 px-3 pb-2.5 pt-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    <HiMiniShieldCheck className="h-3.5 w-3.5 text-brand-blue" />
                    <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-brand-blue">
                      Local Guard
                    </p>
                  </div>
                  <span className="rounded-full bg-brand-blue/15 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-brand-blue">
                    {props.queuedCount > 0 ? "Review" : "Clear"}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-brand-dark/70">
                  {props.queuedCount > 0
                    ? `${props.queuedCount} local ${props.queuedCount === 1 ? "action needs" : "actions need"} a Guard decision.`
                    : "No local approvals are waiting."}
                </p>
                <GuardUpdatePanel
                  guardVersion={props.guardVersion}
                  updateStatus={props.updateStatus}
                  updatePhase={props.updatePhase}
                  onUpdateGuard={props.onUpdateGuard}
                  onReinstallGuard={props.onReinstallGuard}
                />
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2">
              <span className={`inline-flex h-5 min-w-5 items-center justify-center rounded-full text-[10px] font-bold ${props.queuedCount > 0 ? "bg-brand-blue/15 text-brand-blue" : "bg-slate-200 text-slate-400"}`}>
                {props.queuedCount > 0 ? (props.queuedCount > 99 ? "99+" : props.queuedCount) : "0"}
              </span>
              {props.guardVersion ? (
                <span
                  className="font-mono text-[9px] text-brand-dark/50"
                  aria-label={`Guard version ${props.guardVersion}`}
                  title={`Guard version ${props.guardVersion}`}
                >
                  v{props.guardVersion}
                </span>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}

export function ShellFooter() {
  return (
    <footer
      className="mt-10 bg-gradient-to-r from-[#3f4174] to-brand-blue text-indigo-200"
      style={{ contain: "layout style paint", minHeight: 200 }}
    >
      <nav aria-label="Footer Navigation" className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 lg:py-12">
        <div className="grid grid-cols-1 gap-0 sm:grid-cols-2 sm:gap-8 lg:grid-cols-4">
          {footerSections.map((section) => (
            <FooterLinkList key={section.title} title={section.title} links={section.links} />
          ))}
        </div>
        <div className="mt-8 border-t border-indigo-200/20 pt-8">
          <p className="text-center text-[13px] font-medium text-blue-200">
            Copyright © {new Date().getFullYear()} HOL DAO LLC. All rights reserved.
          </p>
        </div>
      </nav>
    </footer>
  );
}

export function Surface(props: {
  children: ReactNode;
  className?: string;
  tone?: "default" | "accent" | "success" | "warning" | "danger" | "attention";
}) {
  const toneClass = surfaceToneClass(props.tone);
  return (
    <section
      className={`guard-surface-in rounded-xl border p-4 sm:p-5 ${toneClass}${props.className ? ` ${props.className}` : ""}`}
    >
      {props.children}
    </section>
  );
}

export function SectionLabel(props: { children: ReactNode }) {
  return <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-brand-blue">{props.children}</p>;
}

export function Badge(props: {
  children: ReactNode;
  tone?: "default" | "success" | "warning" | "info" | "destructive" | "attention";
}) {
  const toneClass = badgeToneClass(props.tone);
  return (
    <span className={`inline-flex items-center justify-center rounded-full border px-3 py-1 text-xs font-normal w-fit whitespace-nowrap shrink-0 [&>svg]:size-3 gap-1.5 [&>svg]:pointer-events-none transition-colors duration-200 overflow-hidden ${toneClass}`}>
      {props.children}
    </span>
  );
}

export function Tag(props: {
  children: ReactNode;
  tone?: "blue" | "green" | "purple" | "slate" | "red" | "attention";
}) {
  const toneClass = tagToneClass(props.tone);
  return (
    <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-normal whitespace-nowrap ${toneClass}`}>
      {props.children}
    </span>
  );
}

export function KeyValueGrid(props: {
  items: Array<[string, string]>;
  columns?: 1 | 2;
}) {
  return (
    <dl className={`grid gap-px overflow-hidden rounded-xl border border-border bg-surface-2 ${props.columns === 1 ? "grid-cols-1" : "grid-cols-1 sm:grid-cols-2"}`}>
      {props.items.map(([label, value]) => (
        <div key={`${label}-${value}`} className="bg-white px-4 py-3 transition-colors duration-150 hover:bg-surface-1">
          <dt className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{label}</dt>
          <dd className="mt-1 font-mono text-[13px] leading-5 text-brand-dark break-all">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function EmptyState(props: {
  title: string;
  body: string;
  action?: ReactNode;
  tone?: "default" | "teach";
}) {
  const isTeach = props.tone === "teach";
  return (
    <div className={`flex flex-col items-center justify-center py-12 text-center sm:py-16 ${isTeach ? "rounded-2xl border border-brand-blue/10 bg-gradient-to-br from-white to-brand-blue/[0.02] px-6" : "px-6"}`}>
      <div className={`mb-5 flex h-14 w-14 items-center justify-center rounded-full ${isTeach ? "bg-brand-blue/10" : "bg-slate-100"}`}>
        <HiMiniInformationCircle className={`h-7 w-7 ${isTeach ? "text-brand-blue" : "text-slate-400"}`} aria-hidden="true" />
      </div>
      <h3 className="text-lg font-semibold tracking-tight text-brand-dark">{props.title}</h3>
      <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-muted-foreground">{props.body}</p>
      {props.action ? <div className="mt-6">{props.action}</div> : null}
    </div>
  );
}

type ActionButtonProps = {
  children: ReactNode;
  onClick?: () => void;
  href?: string;
  variant?: "primary" | "secondary" | "danger" | "outline" | "ghost" | "success" | "quiet";
  disabled?: boolean;
} & Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "className" | "onClick" | "type">;

export const ActionButton = forwardRef<HTMLButtonElement | HTMLAnchorElement, ActionButtonProps>(
  ({ children, href, variant, disabled, onClick, ...buttonProps }, ref) => {
    const className = actionButtonClass(variant);
    if (href) {
      return (
        <a
          ref={ref as Ref<HTMLAnchorElement>}
          href={guardAwareHref(href)}
          target={href.startsWith("https://") ? "_blank" : undefined}
          rel={href.startsWith("https://") ? "noreferrer" : undefined}
          className={className}
        >
          {children}
        </a>
      );
    }
    return (
      <button ref={ref as Ref<HTMLButtonElement>} type="button" className={className} onClick={onClick} disabled={disabled} {...buttonProps}>
        {children}
      </button>
    );
  }
);
ActionButton.displayName = "ActionButton";

type IconActionButtonProps = {
  label: string;
  icon: ReactNode;
  variant?: "primary" | "outline" | "danger" | "ghost";
  onClick: () => void;
  disabled?: boolean;
  spinning?: boolean;
  "aria-label"?: string;
};

export function IconActionButton({ label, icon, variant = "outline", onClick, disabled, spinning, "aria-label": ariaLabel }: IconActionButtonProps) {
  const base = "inline-flex items-center justify-center gap-1.5 rounded-lg text-sm font-semibold transition-[color,background-color,border-color,opacity] duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 min-h-9 h-9 px-2.5 sm:px-3";
  const tone =
    variant === "primary"
      ? "bg-brand-blue text-white shadow-sm hover:bg-brand-blue/90"
      : variant === "danger"
        ? "bg-brand-purple text-white shadow-sm hover:bg-brand-purple/90"
        : variant === "ghost"
          ? "text-slate-600 hover:bg-slate-100"
          : "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 hover:border-slate-300";
  return (
    <button type="button" onClick={onClick} disabled={disabled} aria-label={ariaLabel ?? label} className={`${base} ${tone}`}>
      <span className={`h-4 w-4 ${spinning ? "animate-spin" : ""}`} aria-hidden="true">{icon}</span>
      <span className="hidden sm:inline">{spinning ? "Running..." : label}</span>
    </button>
  );
}

export function ListControls(props: {
  searchLabel: string;
  searchValue: string;
  searchPlaceholder: string;
  filterLabel: string;
  filterValue: string;
  filterOptions: string[];
  allLabel: string;
  onSearchChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onFilterChange: (event: ChangeEvent<HTMLSelectElement>) => void;
  className?: string;
}) {
  return (
    <div className={`grid gap-2 sm:grid-cols-[minmax(0,1fr)_180px]${props.className ? ` ${props.className}` : ""}`}>
      <label className="block">
        <span className="sr-only">{props.searchLabel}</span>
        <input
          type="search"
          value={props.searchValue}
          onChange={props.onSearchChange}
          placeholder={props.searchPlaceholder}
          className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </label>
      <label className="block">
        <span className="sr-only">{props.filterLabel}</span>
        <select
          value={props.filterValue}
          onChange={props.onFilterChange}
          className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        >
          <option value="all">{props.allLabel}</option>
          {props.filterOptions.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

export function PaginationControls(props: {
  page: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPrevious: () => void;
  onNext: () => void;
  className?: string;
}) {
  const firstItem = props.totalItems === 0 ? 0 : (props.page - 1) * props.pageSize + 1;
  const lastItem = Math.min(props.totalItems, props.page * props.pageSize);
  return (
    <div className={`flex flex-col gap-2 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between${props.className ? ` ${props.className}` : ""}`}>
      <span>
        {firstItem}-{lastItem} of {props.totalItems}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={props.onPrevious}
          disabled={props.page <= 1}
          className="min-h-9 rounded-lg border border-slate-200 bg-white px-3 font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-blue/30 disabled:pointer-events-none disabled:opacity-40"
        >
          Previous
        </button>
        <span className="font-mono text-[11px] text-slate-400">
          {props.page}/{props.totalPages}
        </span>
        <button
          type="button"
          onClick={props.onNext}
          disabled={props.page >= props.totalPages}
          className="min-h-9 rounded-lg border border-slate-200 bg-white px-3 font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-blue/30 disabled:pointer-events-none disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

function SidebarLink(props: {
  href: string;
  children: ReactNode;
  active?: boolean;
  icon?: ReactNode;
  badgeCount?: number;
  collapsed?: boolean;
}) {
  const collapsed = props.collapsed ?? false;
  return (
    <a
      href={guardAwareHref(props.href)}
      aria-current={props.active ? "page" : undefined}
      title={collapsed ? String(props.children) : undefined}
      className={`flex min-h-10 items-center rounded-lg no-underline transition-colors duration-150 ${
        collapsed ? "justify-center px-2 py-2" : "gap-2.5 px-3 py-2 text-sm font-medium"
      } ${
        props.active
          ? "bg-brand-blue/[0.05] font-semibold text-brand-dark"
          : "text-slate-600 hover:bg-slate-200/50 hover:text-slate-900"
      }`}
    >
      {props.icon ? (
        <span className={`shrink-0 ${props.active ? "text-brand-blue" : "text-slate-400"}`}>
          {props.icon}
        </span>
      ) : null}
      {!collapsed && <span className="flex-1 truncate">{props.children}</span>}
      {!collapsed && props.badgeCount && props.badgeCount > 0 ? (
        <span className="ml-auto inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-brand-blue/15 px-1.5 text-[10px] font-bold text-brand-blue">
          {props.badgeCount > 99 ? "99+" : props.badgeCount}
        </span>
      ) : null}
    </a>
  );
}

function SidebarAction(props: { href: string; children: ReactNode; icon: ReactNode; external?: boolean; collapsed?: boolean }) {
  const collapsed = props.collapsed ?? false;
  return (
    <a
      href={props.external ? props.href : guardAwareHref(props.href)}
      target={props.external ? "_blank" : undefined}
      rel={props.external ? "noopener noreferrer" : undefined}
      title={collapsed ? String(props.children) : undefined}
      className={`flex min-h-10 items-center rounded-lg border border-slate-200 bg-white no-underline transition-colors duration-150 hover:border-brand-blue/30 hover:text-brand-dark ${collapsed ? "justify-center px-2 py-2" : "gap-2.5 px-3 py-2 text-sm font-medium text-slate-700"}`}
    >
      <span className="shrink-0 text-slate-400">{props.icon}</span>
      {!collapsed && <span className="flex-1 truncate">{props.children}</span>}
      {!collapsed && props.external ? <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5 shrink-0 text-slate-300" /> : null}
    </a>
  );
}

function surfaceToneClass(tone: "default" | "accent" | "success" | "warning" | "danger" | "attention" | undefined): string {
  if (tone === "accent") return "border-brand-blue/15 bg-gradient-to-b from-white to-blue-50/30";
  if (tone === "success") return "border-brand-green/15 bg-brand-green-bg/20";
  if (tone === "warning") return "border-brand-blue/20 bg-brand-blue/[0.03]";
  if (tone === "danger") return "border-brand-purple/20 bg-brand-purple/[0.03]";
  if (tone === "attention") return "border-brand-attention/15 bg-brand-attention-bg/60";
  return "border-slate-100 bg-white/60";
}

function badgeToneClass(tone: "default" | "success" | "warning" | "info" | "destructive" | "attention" | undefined): string {
  if (tone === "success") return "border-transparent bg-accent/10 text-accent border-accent/20";
  if (tone === "warning") return "border-transparent bg-brand-blue/10 text-brand-blue border-brand-blue/20";
  if (tone === "info") return "border-transparent bg-blue-500/10 text-blue-700 border-blue-500/20";
  if (tone === "destructive") return "border-transparent bg-brand-purple/10 text-brand-purple border-brand-purple/20";
  if (tone === "attention") return "border-transparent bg-brand-attention-bg text-brand-attention border-brand-attention/20";
  return "border-transparent bg-gray-100 text-gray-600 border-gray-200";
}

function tagToneClass(tone: "blue" | "green" | "purple" | "slate" | "red" | "attention" | undefined): string {
  if (tone === "green") return "border-transparent bg-brand-green-bg/60 text-brand-green-text";
  if (tone === "purple") return "border-transparent bg-brand-purple/10 text-brand-purple";
  if (tone === "red") return "border-transparent bg-brand-purple/10 text-brand-purple";
  if (tone === "slate") return "border-gray-200 bg-gray-100 text-gray-500";
  if (tone === "attention") return "border-transparent bg-brand-attention-bg text-brand-attention";
  return "border-transparent bg-blue-500/10 text-blue-700";
}

function actionButtonClass(variant: "primary" | "secondary" | "danger" | "outline" | "ghost" | "success" | "quiet" | undefined): string {
  const base = "inline-flex items-center justify-center rounded-lg text-sm font-semibold ring-offset-background transition-[color,background-color,border-color,opacity,transform,box-shadow] duration-150 active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 min-w-0";
  const sizeDefault = "min-h-11 h-auto px-3 py-1.5 sm:px-4 sm:py-2";
  if (variant === "outline") return `${base} ${sizeDefault} border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 text-slate-900`;
  if (variant === "secondary") return `${base} ${sizeDefault} border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 text-slate-900`;
  if (variant === "ghost") return `${base} ${sizeDefault} hover:bg-slate-100 hover:text-slate-900`;
  if (variant === "danger") return `${base} ${sizeDefault} bg-brand-purple text-white shadow-lg shadow-brand-blue/10 hover:bg-brand-purple/90 hover:shadow-brand-blue/20`;
  if (variant === "success") return `${base} ${sizeDefault} bg-[#059669] text-white shadow-lg shadow-emerald-500/15 hover:bg-[#047857] hover:shadow-emerald-500/20`;
  if (variant === "quiet") return `${base} ${sizeDefault} bg-transparent text-brand-dark hover:bg-surface-1`;
  return `${base} ${sizeDefault} bg-brand-blue text-white shadow-lg shadow-brand-blue/20 hover:bg-brand-blue/90 hover:shadow-brand-blue/30`;
}

function FooterLinkList(props: {
  title: string;
  links: ReadonlyArray<{ readonly href: string; readonly label: string }>;
}) {
  return (
    <details className="group border-b border-indigo-200/20 py-2 sm:border-none sm:py-0">
      <summary className="flex cursor-pointer select-none list-none items-center justify-between py-2 text-[15px] font-bold text-white transition-colors hover:text-indigo-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 rounded-sm [&::-webkit-details-marker]:hidden">
        {props.title}
        <span className="text-indigo-300 transition-transform duration-300 group-open:rotate-180">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="m6 9 6 6 6-6" />
          </svg>
        </span>
      </summary>
      <ul className="mt-3 space-y-4 pb-4 sm:pb-0">
        {props.links.map((link) => (
          <li key={`${props.title}-${link.href}`}>
            <a
              href={link.href}
              target="_blank"
              rel="noreferrer"
              className="block p-1 -m-1 text-[15px] font-medium text-indigo-100 transition-colors hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 rounded-sm"
            >
              {link.label}
            </a>
          </li>
        ))}
      </ul>
    </details>
  );
}

export function WelcomeState(props: {
  resolutionMessage: string | null;
  dashboardUrl: string | null;
  inboxUrl: string | null;
  fleetUrl: string | null;
  connectUrl: string | null;
}) {
  return (
    <div className="guard-surface-in flex flex-col items-center justify-center py-16 text-center sm:py-24">
      {props.resolutionMessage && (
        <div className="mb-10 w-full max-w-xl flex justify-center">
          <Surface tone="success">
            <p className="text-sm font-medium text-brand-green-text">{props.resolutionMessage}</p>
          </Surface>
        </div>
      )}

      <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-brand-green-bg/50 ring-1 ring-brand-green/20">
        <HiMiniShieldCheck className="h-10 w-10 text-brand-green" aria-hidden="true" />
      </div>
      <h2 className="text-2xl font-semibold tracking-tight text-brand-dark sm:text-3xl">{EMPTY_QUEUE_TITLE}</h2>
      <p className="mx-auto mt-4 max-w-lg text-[15px] leading-relaxed text-muted-foreground">
        Guard is still watching your apps. Nothing needs you right now.
      </p>

      <div className="mt-12 text-left w-full max-w-3xl">
        <div className="rounded-xl border border-border bg-card p-6 shadow-[0_4px_20px_rgba(85,153,254,0.04)]">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue mb-4">Sync decisions</p>
          {props.connectUrl ? (
            <div className="flex flex-wrap gap-3">
              <ActionButton href={props.connectUrl}>Open pairing flow</ActionButton>
              {props.dashboardUrl ? (
                <ActionButton href={props.dashboardUrl} variant="outline">
                  Open Home
                </ActionButton>
              ) : null}
              {props.inboxUrl ? (
                <ActionButton href={props.inboxUrl} variant="outline">
                  Review Queue
                </ActionButton>
              ) : null}
              {props.fleetUrl ? (
                <ActionButton href={props.fleetUrl} variant="outline">
                  Protect
                </ActionButton>
              ) : null}
            </div>
          ) : (
            <div className="flex items-center gap-3 rounded-lg bg-surface-1 px-5 py-3 font-mono text-sm">
              <span className="text-muted-foreground">$</span>
              <span className="text-brand-dark">hol-guard connect</span>
            </div>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            Sign in once. Guard handles the first sync automatically.
          </p>
        </div>

        <div className="mt-6 grid gap-4 sm:grid-cols-3">
          <TrustCard title="Team Policy Sync" body="Share approval decisions and blocklists." />
          <TrustCard title="Global Trust Feeds" body="Check publisher identity and trust data." />
          <TrustCard title="0-Day Revocation" body="Override local trust when a tool is flagged." />
        </div>
      </div>
    </div>
  );
}

function TrustCard(props: { title: string; body: string }) {
  return (
    <div className="space-y-1.5 rounded-xl border border-border bg-card p-5">
      <p className="text-sm font-semibold text-brand-dark">{props.title}</p>
      <p className="text-xs leading-relaxed text-muted-foreground">{props.body}</p>
    </div>
  );
}

export function GuardHero(props: {
  status: "clear" | "needs_review" | "setup_gap";
  headline: string;
  subheadline: string;
  cta?: ReactNode;
  secondaryCta?: ReactNode;
}) {
  const bgClass =
    props.status === "needs_review"
      ? "bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(245,158,11,0.08)_100%)]"
      : props.status === "setup_gap"
      ? "bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(85,153,254,0.06)_100%)]"
      : "bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(72,223,123,0.10)_100%)]";

  const statusBadge =
    props.status === "needs_review" ? (
      <Badge tone="attention">Needs your choice</Badge>
    ) : props.status === "setup_gap" ? (
      <Badge tone="default">Setup needed</Badge>
    ) : (
      <Badge tone="success">Protected</Badge>
    );

  const HeroIcon =
    props.status === "needs_review"
      ? HiMiniExclamationTriangle
      : props.status === "setup_gap"
      ? HiMiniInformationCircle
      : HiMiniShieldCheck;

  const iconColorClass =
    props.status === "needs_review"
      ? "text-brand-attention"
      : props.status === "setup_gap"
      ? "text-brand-blue"
      : "text-brand-green";

  const iconBgClass =
    props.status === "needs_review"
      ? "bg-brand-attention/10"
      : props.status === "setup_gap"
      ? "bg-brand-blue/10"
      : "bg-brand-green/10";

  return (
    <section
      className={`guard-surface-in relative overflow-hidden rounded-2xl border border-brand-blue/10 ${bgClass} p-5 sm:p-6 lg:p-7`}
      role="region"
      aria-label="Protection status"
    >
      <div className="relative space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <SectionLabel>Protection status</SectionLabel>
          {statusBadge}
        </div>
        <div className="max-w-3xl">
          <div className="flex items-start gap-3">
            <span className={`mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${iconBgClass}`}>
              <HeroIcon className={`h-4 w-4 ${iconColorClass}`} aria-hidden="true" />
            </span>
            <div>
              <h2 className="text-xl font-semibold tracking-tight text-brand-dark sm:text-2xl">{props.headline}</h2>
              <p className="mt-2 text-sm leading-relaxed text-brand-dark/70">{props.subheadline}</p>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-3">
          {props.cta}
          {props.secondaryCta}
        </div>
      </div>
    </section>
  );
}

export function ProofStrip(props: {
  items: Array<{ label: string; value: string | number; tone?: "blue" | "green" | "purple" | "slate" | "attention"; icon?: ReactNode; hint?: string }>;
}) {
  return (
    <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2 lg:grid-cols-4">
      {props.items.map((item) => {
        const toneColor = item.tone === "blue" ? "text-brand-blue" : item.tone === "green" ? "text-emerald-600" : item.tone === "purple" ? "text-brand-purple" : item.tone === "attention" ? "text-amber-600" : "text-brand-dark";
        return (
          <div key={item.label} className="flex flex-col" title={item.hint}>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{item.label}</p>
            <p className={`text-2xl font-semibold tracking-tight ${toneColor}`}>{item.value}</p>
          </div>
        );
      })}
    </div>
  );
}

export function NextActionCard(props: {
  title: string;
  body: string;
  cta: ReactNode;
  tone?: "blue" | "green" | "purple";
}) {
  const borderClass =
    props.tone === "green"
      ? "border-brand-green/20"
      : props.tone === "purple"
      ? "border-brand-purple/20"
      : "border-brand-blue/20";
  const bgClass =
    props.tone === "green"
      ? "bg-brand-green-bg/20"
      : props.tone === "purple"
      ? "bg-brand-purple/[0.03]"
      : "bg-brand-blue/[0.03]";

  return (
    <div className={`rounded-xl border ${borderClass} ${bgClass} p-4 sm:p-5`}>
      <SectionLabel>{props.title}</SectionLabel>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/70">{props.body}</p>
      <div className="mt-4">{props.cta}</div>
    </div>
  );
}

export function SegmentedControl<T extends string>(props: {
  options: Array<{ value: T; label: string }>;
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="inline-flex rounded-lg border border-slate-200 bg-slate-50 p-0.5">
      {props.options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => props.onChange(opt.value)}
          className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
            props.value === opt.value
              ? "bg-white text-brand-dark shadow-sm"
              : "text-slate-500 hover:text-brand-dark"
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export function ListRow(props: {
  children: ReactNode;
  accent?: "green" | "attention" | "blue" | "none";
  onClick?: () => void;
  href?: string;
}) {
  const accentClass =
    props.accent === "green"
      ? "border-l-2 border-emerald-500 pl-3"
      : props.accent === "attention"
      ? "border-l-2 border-brand-attention pl-3"
      : props.accent === "blue"
      ? "border-l-2 border-brand-blue pl-3"
      : "pl-3.5";
  const clickable = props.onClick !== undefined || props.href !== undefined;
  const content = (
    <div
      className={`flex items-center gap-3 border-b border-slate-100 py-2.5 transition-colors hover:bg-slate-50/60 ${accentClass} ${
        clickable ? "cursor-pointer" : ""
      }`}
      onClick={props.onClick}
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onKeyDown={
        clickable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                props.onClick?.();
              }
            }
          : undefined
      }
    >
      {props.children}
    </div>
  );
  if (props.href) {
    return (
      <a href={guardAwareHref(props.href)} className="block no-underline">
        {content}
      </a>
    );
  }
  return content;
}

export function TabBar<T extends string>(props: {
  tabs: Array<{ value: T; label: string; id?: string }>;
  active: T;
  onChange: (value: T) => void;
}) {
  return (
    <div role="tablist" className="flex flex-wrap gap-1 rounded-lg border border-slate-200 bg-slate-50 p-0.5">
      {props.tabs.map((tab) => (
        <button
          key={tab.value}
          id={tab.id ?? tab.value}
          type="button"
          role="tab"
          aria-selected={props.active === tab.value}
          onClick={() => props.onChange(tab.value)}
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            props.active === tab.value
              ? "bg-white text-brand-dark shadow-sm"
              : "text-slate-500 hover:text-brand-dark"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export function AccordionSection(props: {
  title: string;
  subtitle?: string;
  expanded: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-slate-100 overflow-hidden">
      <button
        onClick={props.onToggle}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50/60"
        aria-expanded={props.expanded}
      >
        <div>
          <p className="text-sm font-semibold text-brand-dark">{props.title}</p>
          {props.subtitle ? <p className="text-xs text-slate-400">{props.subtitle}</p> : null}
        </div>
        {props.expanded ? (
          <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
        ) : (
          <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
        )}
      </button>
      {props.expanded && (
        <div className="border-t border-slate-100 px-4 py-4">
          {props.children}
        </div>
      )}
    </div>
  );
}

export function StickyActionBar(props: {
  children: ReactNode;
}) {
  return (
    <div className="sticky bottom-4 z-30 rounded-xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur">
      {props.children}
    </div>
  );
}
