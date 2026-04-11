import type { ReactNode } from "react";

export function ShellHeader(props: {
  queuedCount: number;
  activeHarness: string | null;
}) {
  return (
    <header className="sticky top-0 z-40 border-b border-white/12 bg-gradient-to-r from-[#3f4174] via-[#474983] to-brand-blue text-white shadow-[0_20px_40px_-30px_rgba(15,23,42,0.65)]">
      <div className="mx-auto flex w-[min(1240px,calc(100vw-32px))] items-center justify-between gap-6 py-3">
        <a href="/" className="flex items-center gap-3 rounded-full px-1 py-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/60">
          <img src="/brand/Logo_Whole.png" alt="HOL Logo" className="h-8 w-auto sm:h-9" />
          <span className="rounded-full bg-white/12 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.18em] text-white/84">
            Local approval center
          </span>
        </a>

        <nav className="hidden items-center gap-2 lg:flex">
          <NavLink href="/">Queue</NavLink>
          <NavLink href="/v1/receipts">Receipts</NavLink>
          <NavLink href="https://hol.org/guard" external>
            Sync on hol.org
          </NavLink>
        </nav>

        <div className="flex flex-wrap items-center justify-end gap-2">
          <StatusPill tone={props.queuedCount > 0 ? "warning" : "success"}>
            {props.queuedCount > 0 ? `${props.queuedCount} paused launch${props.queuedCount === 1 ? "" : "es"}` : "No paused launches"}
          </StatusPill>
          {props.activeHarness ? <StatusPill tone="neutral">{props.activeHarness}</StatusPill> : null}
        </div>
      </div>
    </header>
  );
}

export function ShellFooter() {
  return (
    <footer className="mt-10 bg-gradient-to-r from-[#3f4174] to-brand-blue text-indigo-200">
      <nav aria-label="Footer Navigation" className="mx-auto w-[min(1240px,calc(100vw-32px))] py-8 lg:py-12">
        <div className="grid grid-cols-1 gap-0 sm:grid-cols-2 sm:gap-8 lg:grid-cols-4">
          <FooterSection
            title="Guard"
            links={[
              { href: "https://hol.org/guard", label: "Cloud dashboard" },
              { href: "https://hol.org/guard/pricing", label: "Pricing" }
            ]}
          />
          <FooterSection
            title="Docs"
            links={[
              { href: "https://hol.org/docs/registry-broker/mcp-server", label: "Hashnet MCP server" },
              { href: "https://hol.org/docs/libraries/standards-sdk", label: "Standards SDK" }
            ]}
          />
          <FooterSection
            title="Community"
            links={[
              { href: "https://x.com/HashgraphOnline", label: "X" },
              { href: "https://t.me/hashinals", label: "Telegram" }
            ]}
          />
          <FooterSection
            title="More"
            links={[
              { href: "https://hol.org/blog", label: "Blog" },
              { href: "https://github.com/hashgraph-online", label: "GitHub" }
            ]}
          />
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
  tone?: "default" | "accent" | "success" | "warning";
}) {
  const toneClass =
    props.tone === "accent"
      ? "border-brand-blue/14 bg-white/94"
      : props.tone === "success"
        ? "border-brand-green/25 bg-brand-green-bg/70"
        : props.tone === "warning"
          ? "border-amber-200 bg-amber-50/80"
          : "border-slate-200/70 bg-white/88";
  return (
    <section
      className={`guard-surface-in rounded-[28px] border p-5 shadow-[0_22px_54px_-36px_rgba(15,23,42,0.24)] backdrop-blur-xl sm:p-6 ${toneClass}${props.className ? ` ${props.className}` : ""}`}
    >
      {props.children}
    </section>
  );
}

export function SectionEyebrow(props: { children: ReactNode }) {
  return (
    <p className="font-mono text-[11px] font-black uppercase tracking-[0.18em] text-brand-blue">
      {props.children}
    </p>
  );
}

export function StatusPill(props: {
  children: ReactNode;
  tone?: "success" | "warning" | "neutral";
}) {
  const toneClass =
    props.tone === "success"
      ? "bg-brand-green-bg/70 text-brand-green-text"
      : props.tone === "warning"
        ? "bg-white/14 text-white"
        : "bg-slate-900/6 text-white";
  return (
    <span className={`inline-flex min-h-8 items-center rounded-full px-3 text-xs font-bold uppercase tracking-[0.14em] ${toneClass}`}>
      {props.children}
    </span>
  );
}

export function Tag(props: {
  children: ReactNode;
  tone?: "blue" | "green" | "purple" | "slate" | "red";
}) {
  const toneClass =
    props.tone === "green"
      ? "bg-brand-green-bg text-brand-green-text"
      : props.tone === "purple"
        ? "bg-brand-purple/12 text-brand-purple"
        : props.tone === "red"
          ? "bg-red-50 text-red-700"
          : props.tone === "slate"
            ? "bg-slate-900/6 text-slate-600"
            : "bg-brand-blue/10 text-brand-blue";
  return (
    <span className={`inline-flex min-h-8 items-center rounded-full px-3 text-xs font-bold uppercase tracking-[0.14em] ${toneClass}`}>
      {props.children}
    </span>
  );
}

export function KeyValueGrid(props: {
  items: Array<[string, string]>;
  columns?: 1 | 2;
}) {
  return (
    <dl className={`grid gap-4 ${props.columns === 1 ? "grid-cols-1" : "grid-cols-1 sm:grid-cols-2"}`}>
      {props.items.map(([label, value]) => (
        <div key={`${label}-${value}`} className="rounded-[20px] border border-slate-200/70 bg-slate-50/88 px-4 py-4">
          <dt className="font-mono text-[11px] font-black uppercase tracking-[0.18em] text-brand-dark/48">{label}</dt>
          <dd className="mt-2 text-sm leading-6 text-brand-dark/82">{value}</dd>
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
    <div className="rounded-[24px] border border-dashed border-slate-200/80 bg-slate-50/65 px-6 py-12 text-center">
      <h3 className="text-[1.55rem] font-semibold tracking-[-0.04em] text-brand-dark">{props.title}</h3>
      <p className="mx-auto mt-3 max-w-2xl text-sm leading-7 text-brand-dark/68">{props.body}</p>
      {props.action ? <div className="mt-5">{props.action}</div> : null}
    </div>
  );
}

export function ActionButton(props: {
  children: ReactNode;
  onClick?: () => void;
  href?: string;
  variant?: "primary" | "secondary";
  disabled?: boolean;
}) {
  const className =
    props.variant === "secondary"
      ? "inline-flex min-h-11 items-center justify-center rounded-full border border-slate-200/70 px-5 text-sm font-semibold text-brand-dark transition-colors duration-200 hover:border-brand-blue/20 hover:text-brand-blue"
      : "inline-flex min-h-11 items-center justify-center rounded-full bg-brand-blue px-5 text-sm font-semibold text-white shadow-sm shadow-brand-blue/30 transition-colors duration-200 hover:bg-brand-blue/92 disabled:cursor-not-allowed disabled:bg-brand-blue/50";
  if (props.href) {
    return (
      <a href={props.href} target={props.href.startsWith("https://") ? "_blank" : undefined} rel={props.href.startsWith("https://") ? "noreferrer" : undefined} className={className}>
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

function NavLink(props: {
  href: string;
  children: ReactNode;
  external?: boolean;
}) {
  return (
    <a
      href={props.href}
      target={props.external ? "_blank" : undefined}
      rel={props.external ? "noreferrer" : undefined}
      className="inline-flex min-h-10 items-center rounded-md px-3 py-1.5 text-[15px] font-medium text-white/94 transition-colors duration-200 hover:bg-white/10 hover:text-white"
    >
      {props.children}
    </a>
  );
}

function FooterSection(props: {
  title: string;
  links: Array<{ href: string; label: string }>;
}) {
  return (
    <details className="group border-b border-indigo-200/20 py-2 sm:border-none sm:py-0">
      <summary className="flex cursor-pointer list-none items-center justify-between py-2 text-[15px] font-bold text-white transition-colors hover:text-indigo-100 [&::-webkit-details-marker]:hidden">
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
            <a href={link.href} target="_blank" rel="noreferrer" className="block p-1 text-[15px] font-medium text-indigo-100 transition-colors hover:text-white">
              {link.label}
            </a>
          </li>
        ))}
      </ul>
    </details>
  );
}
