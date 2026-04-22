import type { ReactNode } from "react";

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
  view: "home" | "inbox" | "fleet" | "evidence";
}) {
  return (
    <header
      className="sticky top-0 z-50 border-b border-white/10 bg-gradient-to-r from-[#3f4174] to-brand-blue text-white shadow-[0_10px_30px_-20px_rgba(37,42,89,0.8)]"
      style={{ contain: "layout style paint" }}
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex min-h-[64px] items-center justify-between gap-4 py-2">
          <div className="flex min-w-0 items-center gap-4 sm:gap-6">
            <a href="/" className="flex items-center gap-3 no-underline hover:no-underline">
              <img src="/brand/Logo_Whole.png" alt="HOL" className="h-8 w-auto sm:h-9" />
            </a>
            <nav className="flex items-center gap-1" aria-label="Primary">
              <NavPill href="/" active={props.view === "home"}>Home</NavPill>
              <NavPill href="/inbox" active={props.view === "inbox"}>Inbox</NavPill>
              <NavPill href="/fleet" active={props.view === "fleet"}>Fleet</NavPill>
              <NavPill href="/evidence" active={props.view === "evidence"}>Evidence</NavPill>
              <NavPill href="https://hol.org/guard" external>hol.org</NavPill>
            </nav>
          </div>
          <div className="ml-auto flex items-center gap-2 sm:gap-3">
            {props.queuedCount > 0 ? (
              <NavBadge tone="warning">{props.queuedCount} blocked</NavBadge>
            ) : (
              <NavBadge tone="success">All clear</NavBadge>
            )}
            {props.activeHarness ? <NavBadge tone="default">{props.activeHarness}</NavBadge> : null}
          </div>
        </div>
      </div>
    </header>
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
      className={`guard-surface-in rounded-xl border shadow-sm p-5 sm:p-6 ${toneClass}${props.className ? ` ${props.className}` : ""}`}
    >
      {props.children}
    </section>
  );
}

export function SectionLabel(props: { children: ReactNode }) {
  return <p className="text-xs font-medium text-gray-500">{props.children}</p>;
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
  variant?: "primary" | "secondary" | "danger" | "outline" | "ghost";
  disabled?: boolean;
}) {
  const className = actionButtonClass(props.variant);
  if (props.href) {
    return (
      <a
        href={props.href}
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

function NavPill(props: { href: string; children: ReactNode; active?: boolean; external?: boolean }) {
  return (
    <a
      href={props.href}
      target={props.external ? "_blank" : undefined}
      rel={props.external ? "noreferrer" : undefined}
      className={`inline-flex min-h-11 items-center rounded-md px-3 py-1.5 font-medium no-underline transition-colors duration-200 ${
        props.active
          ? "bg-white/15 text-white"
          : "text-white/80 hover:bg-white/10 hover:text-white"
      }`}
    >
      {props.children}
    </a>
  );
}

function NavBadge(props: { children: ReactNode; tone?: "default" | "success" | "warning" }) {
  const toneClass = navBadgeToneClass(props.tone);
  return (
    <span className={`inline-flex items-center rounded-md px-3 py-1 font-mono text-[13px] border ${toneClass}`}>
      {props.children}
    </span>
  );
}

function surfaceToneClass(tone: "default" | "accent" | "success" | "warning" | "danger" | undefined): string {
  if (tone === "accent") return "border-brand-blue/20 bg-gradient-to-b from-white to-blue-50/40";
  if (tone === "success") return "border-brand-green/20 bg-brand-green-bg/30";
  if (tone === "warning") return "border-orange-300/30 bg-orange-50/40";
  if (tone === "danger") return "border-red-200/50 bg-red-50/40";
  return "border-gray-200/50 bg-white/80";
}

function badgeToneClass(tone: "default" | "success" | "warning" | "info" | "destructive" | undefined): string {
  if (tone === "success") return "border-transparent bg-accent/10 text-accent border-accent/20";
  if (tone === "warning") return "border-transparent bg-orange-500/10 text-orange-700 border-orange-500/20";
  if (tone === "info") return "border-transparent bg-blue-500/10 text-blue-700 border-blue-500/20";
  if (tone === "destructive") return "border-transparent bg-destructive/10 text-destructive border-destructive/20";
  return "border-transparent bg-gray-100 text-gray-600 border-gray-200";
}

function tagToneClass(tone: "blue" | "green" | "purple" | "slate" | "red" | undefined): string {
  if (tone === "green") return "border-transparent bg-brand-green-bg/60 text-brand-green-text";
  if (tone === "purple") return "border-transparent bg-brand-purple/10 text-brand-purple";
  if (tone === "red") return "border-transparent bg-red-100/80 text-red-700";
  if (tone === "slate") return "border-gray-200 bg-gray-100 text-gray-500";
  return "border-transparent bg-blue-500/10 text-blue-700";
}

function navBadgeToneClass(tone: "default" | "success" | "warning" | undefined): string {
  if (tone === "success") return "bg-white/10 text-green-200 border-white/10";
  if (tone === "warning") return "bg-white/10 text-amber-200 border-white/10";
  return "bg-white/10 text-white/80 border-white/10";
}

function actionButtonClass(variant: "primary" | "secondary" | "danger" | "outline" | "ghost" | undefined): string {
  const base = "inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-[color,background-color,border-color,opacity] duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 min-w-0";
  const sizeDefault = "min-h-11 h-auto px-4 py-2";
  if (variant === "outline") return `${base} ${sizeDefault} border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 text-slate-900`;
  if (variant === "secondary") return `${base} ${sizeDefault} border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 text-slate-900`;
  if (variant === "ghost") return `${base} ${sizeDefault} hover:bg-slate-100 hover:text-slate-900`;
  if (variant === "danger") return `${base} ${sizeDefault} bg-red-600 text-white shadow-lg shadow-red-600/20 hover:bg-red-700 hover:shadow-red-600/30`;
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
        <svg className="h-10 w-10 text-brand-green" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" /></svg>
      </div>
      <h2 className="text-2xl font-semibold tracking-tight text-brand-dark sm:text-3xl">Your environment is secure</h2>
      <p className="mx-auto mt-4 max-w-lg text-[15px] leading-relaxed text-muted-foreground">
        Guard is actively watching your harness configs. When your queue is clear, connect to Guard Cloud for team-wide protection.
      </p>
      
      <div className="mt-12 text-left w-full max-w-3xl">
        <div className="rounded-xl border border-border bg-card p-6 shadow-[0_4px_20px_rgba(85,153,254,0.04)]">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue mb-4">Sync your decisions</p>
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
                  Open Inbox
                </ActionButton>
              ) : null}
              {props.fleetUrl ? (
                <ActionButton href={props.fleetUrl} variant="outline">
                  Open Fleet
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
            Open the browser pairing flow, sign in once, and let Guard finish the first sync automatically.
          </p>
        </div>

        <div className="mt-6 grid gap-4 sm:grid-cols-3">
          <div className="space-y-1.5 rounded-xl border border-border bg-card p-5">
            <p className="text-sm font-semibold text-brand-dark">Team Policy Sync</p>
            <p className="text-xs leading-relaxed text-muted-foreground">Share approval decisions and blocklists across your engineering team.</p>
          </div>
          <div className="space-y-1.5 rounded-xl border border-border bg-card p-5">
            <p className="text-sm font-semibold text-brand-dark">Global Trust Feeds</p>
            <p className="text-xs leading-relaxed text-muted-foreground">Enrich local approvals with verified publisher identity and trust data.</p>
          </div>
          <div className="space-y-1.5 rounded-xl border border-border bg-card p-5">
            <p className="text-sm font-semibold text-brand-dark">0-Day Revocation</p>
            <p className="text-xs leading-relaxed text-muted-foreground">When a tool is flagged malicious, Guard Cloud overrides local trust automatically.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
