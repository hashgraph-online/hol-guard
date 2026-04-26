import type { ChangeEvent, ReactNode } from "react";
import {
  HiMiniArrowTopRightOnSquare,
  HiMiniCloud,
  HiMiniCommandLine,
  HiMiniDocumentText,
  HiMiniHome,
  HiMiniInbox,
  HiMiniServerStack,
  HiMiniAdjustmentsHorizontal,
  HiMiniShieldCheck,
} from "react-icons/hi2";

import { guardAwareHref } from "./guard-api";

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
      { href: "https://hol.org/points/legal/privacy", label: "Privacy Policy" },
      { href: "https://hol.org/points/legal/terms", label: "Terms of Service" }
    ]
  }
] as const;

export function ShellHeader(props: {
  queuedCount: number;
  activeHarness: string | null;
  view: "home" | "inbox" | "fleet" | "evidence" | "settings";
  onNavigate: (pathname: string) => void;
}) {
  function handleMobileNavigationChange(event: ChangeEvent<HTMLSelectElement>) {
    props.onNavigate(event.target.value);
  }

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
          <span className="font-mono text-base font-semibold tracking-tight text-white">HOL Guard</span>
        </a>
        <div className="min-w-0 flex-1">
          <select
            aria-label="Navigate Guard sections"
            className="h-11 w-full rounded-full border border-white/25 bg-white/95 px-4 text-sm font-medium text-brand-dark shadow-none transition-colors duration-150 focus:border-white focus:outline-none focus:ring-2 focus:ring-white/40"
            onChange={handleMobileNavigationChange}
            value={sidebarLinks.find((item) => item.view === props.view)?.href ?? "/"}
          >
            {sidebarLinks.map((item) => (
              <option key={item.href} value={item.href}>
                {item.label}
              </option>
            ))}
          </select>
        </div>
        <a
          href={guardAwareHref("/inbox")}
          className="inline-flex min-h-11 shrink-0 items-center rounded-full border border-white/25 bg-white/10 px-3 py-2 text-sm font-semibold text-white no-underline transition-colors duration-150 hover:bg-white/15"
          aria-label={`${props.queuedCount} Guard actions queued`}
        >
          {props.queuedCount > 99 ? "99+" : props.queuedCount}
        </a>
      </div>
    </header>
  );
}

const sidebarLinks = [
  { href: "/", label: "Home", view: "home", icon: HiMiniHome },
  { href: "/inbox", label: "Review Queue", view: "inbox", icon: HiMiniInbox },
  { href: "/fleet", label: "Watched Apps", view: "fleet", icon: HiMiniServerStack },
  { href: "/evidence", label: "History", view: "evidence", icon: HiMiniDocumentText },
  { href: "/settings", label: "Settings", view: "settings", icon: HiMiniAdjustmentsHorizontal }
] as const;

export function ShellSidebar(props: {
  queuedCount: number;
  activeHarness: string | null;
  view: "home" | "inbox" | "fleet" | "evidence" | "settings";
}) {
  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 flex-col border-r border-slate-200 bg-[#f8fafc] lg:flex">
      <div className="flex min-h-[72px] shrink-0 items-center border-b border-brand-blue/20 bg-gradient-to-r from-brand-blue to-brand-dark px-6">
        <a href={guardAwareHref("/")} className="flex items-center gap-2.5 text-white no-underline transition-opacity hover:opacity-85">
          <img src="/brand/Logo_Icon_Dark.png" alt="HOL" className="h-10 w-10 shrink-0 rounded-none bg-transparent object-contain" />
          <span className="font-mono text-base font-semibold tracking-tight text-white">HOL Guard</span>
        </a>
      </div>
      <div className="flex flex-1 flex-col overflow-y-auto px-3 py-5">
        <p className="mb-2 px-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-400">
          Dashboard
        </p>
        <nav className="flex flex-col gap-0.5" aria-label="Guard dashboard">
          {sidebarLinks.map((item) => {
            const Icon = item.icon;
            return (
              <SidebarLink
                key={item.href}
                href={item.href}
                active={props.view === item.view}
                icon={<Icon className="h-4 w-4" />}
                badgeCount={item.view === "inbox" ? props.queuedCount : 0}
              >
                {item.label}
              </SidebarLink>
            );
          })}
        </nav>

        <div className="mt-6 space-y-2">
          <p className="px-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-slate-400">
            Quick Actions
          </p>
          <SidebarAction href="/" icon={<HiMiniCommandLine className="h-4 w-4" />}>
            Local dashboard
          </SidebarAction>
          <SidebarAction href="https://hol.org/guard" external icon={<HiMiniCloud className="h-4 w-4" />}>
            Open Guard Cloud
          </SidebarAction>
        </div>

        <div className="mt-auto pt-6">
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
              {props.activeHarness ? (
                <span className="inline-flex rounded-full bg-white/70 px-2 py-1 font-mono text-[10px] font-semibold text-slate-500">
                  {props.activeHarness}
                </span>
              ) : null}
            </div>
          </div>
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
  tone?: "default" | "accent" | "success" | "warning" | "danger";
}) {
  const toneClass = surfaceToneClass(props.tone);
  return (
    <section
      className={`guard-surface-in rounded-[1.35rem] border shadow-sm p-5 sm:p-6 ${toneClass}${props.className ? ` ${props.className}` : ""}`}
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
  tone?: "default" | "success" | "warning" | "info" | "destructive";
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
  tone?: "blue" | "green" | "purple" | "slate" | "red";
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
}) {
  return (
    <div className="rounded-lg bg-gray-50 px-6 py-8 text-left">
      <h3 className="text-base font-semibold tracking-tight text-brand-dark">{props.title}</h3>
      <p className="mt-2 max-w-xl text-sm leading-6 text-gray-500">{props.body}</p>
      {props.action ? <div className="mt-4">{props.action}</div> : null}
    </div>
  );
}

export function ActionButton(props: {
  children: ReactNode;
  onClick?: () => void;
  href?: string;
  variant?: "primary" | "secondary" | "danger" | "outline" | "ghost" | "success";
  disabled?: boolean;
}) {
  const className = actionButtonClass(props.variant);
  if (props.href) {
    return (
      <a
        href={guardAwareHref(props.href)}
        target={props.href.startsWith("https://") ? "_blank" : undefined}
        rel={props.href.startsWith("https://") ? "noreferrer" : undefined}
        className={className}
      >
        {props.children}
      </a>
    );
  }
  return (
    <button type="button" className={className} onClick={props.onClick} disabled={props.disabled}>
      {props.children}
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
}) {
  return (
    <a
      href={guardAwareHref(props.href)}
      aria-current={props.active ? "page" : undefined}
      className={`flex min-h-10 items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium no-underline transition-colors duration-150 ${
        props.active
          ? "bg-brand-blue/10 font-semibold text-brand-dark"
          : "text-slate-600 hover:bg-slate-200/50 hover:text-slate-900"
      }`}
    >
      {props.icon ? (
        <span className={`shrink-0 ${props.active ? "text-brand-blue" : "text-slate-400"}`}>
          {props.icon}
        </span>
      ) : null}
      <span className="flex-1 truncate">{props.children}</span>
      {props.badgeCount && props.badgeCount > 0 ? (
        <span className="ml-auto inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-brand-blue/15 px-1.5 text-[10px] font-bold text-brand-blue">
          {props.badgeCount > 99 ? "99+" : props.badgeCount}
        </span>
      ) : null}
    </a>
  );
}

function SidebarAction(props: { href: string; children: ReactNode; icon: ReactNode; external?: boolean }) {
  return (
    <a
      href={props.external ? props.href : guardAwareHref(props.href)}
      target={props.external ? "_blank" : undefined}
      rel={props.external ? "noreferrer" : undefined}
      className="flex min-h-10 items-center gap-2.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 no-underline transition-colors duration-150 hover:border-brand-blue/30 hover:text-brand-dark"
    >
      <span className="shrink-0 text-slate-400">{props.icon}</span>
      <span className="flex-1 truncate">{props.children}</span>
      {props.external ? <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5 shrink-0 text-slate-300" /> : null}
    </a>
  );
}

function surfaceToneClass(tone: "default" | "accent" | "success" | "warning" | "danger" | undefined): string {
  if (tone === "accent") return "border-brand-blue/20 bg-gradient-to-b from-white to-blue-50/40";
  if (tone === "success") return "border-brand-green/20 bg-brand-green-bg/30";
  if (tone === "warning") return "border-brand-blue/25 bg-brand-blue/[0.04]";
  if (tone === "danger") return "border-brand-purple/25 bg-brand-purple/[0.05]";
  return "border-gray-200/50 bg-white/80";
}

function badgeToneClass(tone: "default" | "success" | "warning" | "info" | "destructive" | undefined): string {
  if (tone === "success") return "border-transparent bg-accent/10 text-accent border-accent/20";
  if (tone === "warning") return "border-transparent bg-brand-blue/10 text-brand-blue border-brand-blue/20";
  if (tone === "info") return "border-transparent bg-blue-500/10 text-blue-700 border-blue-500/20";
  if (tone === "destructive") return "border-transparent bg-brand-purple/10 text-brand-purple border-brand-purple/20";
  return "border-transparent bg-gray-100 text-gray-600 border-gray-200";
}

function tagToneClass(tone: "blue" | "green" | "purple" | "slate" | "red" | undefined): string {
  if (tone === "green") return "border-transparent bg-brand-green-bg/60 text-brand-green-text";
  if (tone === "purple") return "border-transparent bg-brand-purple/10 text-brand-purple";
  if (tone === "red") return "border-transparent bg-brand-purple/10 text-brand-purple";
  if (tone === "slate") return "border-gray-200 bg-gray-100 text-gray-500";
  return "border-transparent bg-blue-500/10 text-blue-700";
}

function actionButtonClass(variant: "primary" | "secondary" | "danger" | "outline" | "ghost" | "success" | undefined): string {
  const base = "inline-flex items-center justify-center rounded-lg text-sm font-semibold ring-offset-background transition-[color,background-color,border-color,opacity,transform,box-shadow] duration-150 active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 min-w-0";
  const sizeDefault = "min-h-11 h-auto px-4 py-2";
  if (variant === "outline") return `${base} ${sizeDefault} border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 text-slate-900`;
  if (variant === "secondary") return `${base} ${sizeDefault} border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 text-slate-900`;
  if (variant === "ghost") return `${base} ${sizeDefault} hover:bg-slate-100 hover:text-slate-900`;
  if (variant === "danger") return `${base} ${sizeDefault} bg-brand-purple text-white shadow-lg shadow-brand-blue/10 hover:bg-brand-purple/90 hover:shadow-brand-blue/20`;
  if (variant === "success") return `${base} ${sizeDefault} bg-[#059669] text-white shadow-lg shadow-emerald-500/15 hover:bg-[#047857] hover:shadow-emerald-500/20`;
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
      <h2 className="text-2xl font-semibold tracking-tight text-brand-dark sm:text-3xl">Your environment is secure</h2>
      <p className="mx-auto mt-4 max-w-lg text-[15px] leading-relaxed text-muted-foreground">
        HOL Guard is watching connected apps on this machine. Connect Cloud when you want shared decisions across the team.
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
                  Watched Apps
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
