import { j as jsxRuntimeExports, T as Tag, d$ as Surface, a6 as Badge, r as reactExports, co as HiMiniArrowTopRightOnSquare, df as HiMiniCheckBadge } from "../guard-dashboard.js";
import { b as ABOUT_TRUST_CONTRACT_CLAIMS, c as ALLOWED_LINKS, d as ABOUT_DATA_BOUNDARY_ROWS, e as ABOUT_STANDARDS_NODES, f as ABOUT_PATH_CARDS, g as ABOUT_PARTNER_SECTION_BODY, h as ABOUT_PARTNER_SECTION_TITLE, i as ABOUT_PARTNER_LEVELS, j as ABOUT_PARTNER_CTA, k as ABOUT_PARTNER_CTA_HREF, l as ABOUT_AFFILIATE_SECTION_BODY, m as ABOUT_AFFILIATE_SECTION_TITLE, n as ABOUT_AFFILIATE_TERMS, o as ABOUT_AFFILIATE_CTA, p as ABOUT_AFFILIATE_CTA_HREF, q as ABOUT_AFFILIATE_DISCLOSURE } from "./about-content-Bsz4ilTC.js";
function AboutRuntimeProofStrip({
  summary
}) {
  if (!summary) return null;
  const items = [
    {
      label: "Local protection",
      value: summary.pendingCount > 0 ? `${summary.pendingCount} pending` : "Active",
      tone: summary.pendingCount > 0 ? "attention" : "green"
    },
    {
      label: "Guard version",
      value: summary.guardVersion ?? "Unknown",
      tone: "slate"
    },
    {
      label: "Sync",
      value: summary.cloudStateLabel,
      tone: summary.syncConfigured ? "blue" : "slate"
    },
    {
      label: "Receipts",
      value: String(summary.receiptCount),
      tone: "green"
    }
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-x-4 gap-y-2 pt-4", children: items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: item.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: item.tone, children: item.value })
  ] }, item.label)) });
}
const toneClasses = {
  blue: "border-brand-blue/30 bg-brand-blue/[0.04]",
  green: "border-brand-green/30 bg-brand-green-bg/20",
  purple: "border-brand-purple/20 bg-brand-purple/[0.03]",
  slate: "border-brand-dark/10 bg-surface-1"
};
const badgeTones = {
  blue: "info",
  green: "success",
  purple: "attention",
  slate: "default"
};
function TrustContractPanel({
  runtimeSummary
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(Surface, { className: "h-full", tone: "accent", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-5 flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-semibold text-brand-dark", children: "Trust Contract" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Local-first" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", children: ABOUT_TRUST_CONTRACT_CLAIMS.map((claim) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: `rounded-lg border p-3 ${toneClasses[claim.tone] ?? toneClasses.slate}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-1 flex items-center justify-between gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: claim.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: badgeTones[claim.tone] ?? "default", children: claim.proofLabel })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/75", children: claim.body })
        ]
      },
      claim.id
    )) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(AboutRuntimeProofStrip, { summary: runtimeSummary })
  ] });
}
class AboutExternalLinkError extends Error {
  constructor(message) {
    super(message);
    this.name = "AboutExternalLinkError";
  }
}
function isPrivateHost(rawHostname) {
  const hostname = rawHostname.startsWith("[") && rawHostname.endsWith("]") ? rawHostname.slice(1, -1) : rawHostname;
  if (hostname === "localhost" || hostname.startsWith("127.") || hostname === "::1" || hostname === "0.0.0.0") {
    return true;
  }
  if (hostname.startsWith("10.")) return true;
  if (hostname.startsWith("192.168.")) return true;
  if (hostname.startsWith("172.")) {
    const secondOctet = parseInt(hostname.split(".")[1] ?? "", 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  if (hostname === "169.254.0.0" || hostname.startsWith("169.254.")) return true;
  if (hostname.endsWith(".local") || hostname.endsWith(".internal")) return true;
  if (hostname.startsWith("fe80:")) return true;
  return false;
}
function assertSafeAboutExternalUrl(linkId, raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new AboutExternalLinkError(`Invalid URL: ${raw}`);
  }
  if (parsed.protocol === "mailto:") {
    return {
      url: raw,
      hostname: "",
      rel: "",
      target: ""
    };
  }
  if (parsed.protocol !== "https:") {
    throw new AboutExternalLinkError(`URL must use HTTPS: ${raw}`);
  }
  if (parsed.username || parsed.password) {
    throw new AboutExternalLinkError(`URL must not contain credentials: ${raw}`);
  }
  if (isPrivateHost(parsed.hostname)) {
    throw new AboutExternalLinkError(`URL must not point to localhost or private host: ${raw}`);
  }
  const allowed = ALLOWED_LINKS[linkId];
  if (!allowed) {
    throw new AboutExternalLinkError(`Unknown link ID: ${linkId}`);
  }
  if (parsed.hostname !== allowed.host && !parsed.hostname.endsWith(`.${allowed.host}`)) {
    throw new AboutExternalLinkError(
      `Host mismatch for ${linkId}: expected ${allowed.host}, got ${parsed.hostname}`
    );
  }
  if (allowed.exactPath ? parsed.pathname !== allowed.pathPrefix : !parsed.pathname.startsWith(allowed.pathPrefix)) {
    throw new AboutExternalLinkError(
      `Path mismatch for ${linkId}: expected ${allowed.exactPath ? "exact" : "prefix"} ${allowed.pathPrefix}, got ${parsed.pathname}`
    );
  }
  const forbiddenParams = ["guard-token", "guardDaemon", "workspace", "device", "install", "user", "referral", "ref"];
  for (const param of forbiddenParams) {
    if (parsed.searchParams.has(param)) {
      throw new AboutExternalLinkError(`URL must not contain parameter ${param}: ${raw}`);
    }
  }
  return {
    url: raw,
    hostname: parsed.hostname,
    rel: "noopener noreferrer",
    target: "_blank"
  };
}
function TrackedExternalButton({
  linkId,
  href,
  children,
  variant = "primary"
}) {
  let safe = null;
  let errorReason = "";
  try {
    safe = assertSafeAboutExternalUrl(linkId, href);
  } catch (e) {
    errorReason = e instanceof Error ? e.message : "Invalid URL";
  }
  const handleClick = reactExports.useCallback(() => {
  }, [linkId]);
  const base = "inline-flex items-center justify-center rounded-lg text-sm font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2";
  const size = "min-h-11 h-auto px-4 py-2";
  const tone = variant === "outline" ? "border border-slate-200 bg-white hover:bg-slate-50 text-slate-900" : "bg-brand-blue text-white shadow-lg shadow-brand-blue/20 hover:bg-brand-blue/90";
  if (!safe) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: `${base} ${size} ${tone} opacity-50 cursor-not-allowed`,
        title: errorReason,
        children
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "a",
    {
      href,
      target: safe.target,
      rel: safe.rel,
      onClick: handleClick,
      className: `${base} ${size} ${tone} no-underline`,
      children
    }
  );
}
function AboutHero({
  runtimeSummary
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-8 lg:grid-cols-[minmax(0,1fr)_420px] lg:items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "h1",
        {
          id: "about-hero-heading",
          className: "text-4xl font-bold leading-[1.05] tracking-[-0.03em] text-brand-dark sm:text-5xl lg:text-[3.5rem]",
          children: "About HOL Guard"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 max-w-[60ch] text-lg leading-8 text-brand-dark/75", children: "A local-first safety layer for AI harnesses, built by HOL as part of open trust infrastructure for the agent internet." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-7 flex flex-wrap gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(TrackedExternalButton, { linkId: "guard_docs", href: "https://hol.org/guard/docs", variant: "primary", children: "Read Guard docs" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(TrackedExternalButton, { linkId: "hol_guard_source", href: "https://github.com/hashgraph-online/hol-guard", variant: "outline", children: "View source" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(TrustContractPanel, { runtimeSummary })
  ] });
}
function AboutSectionHeading(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-[68ch]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "h2",
      {
        id: props.id,
        className: "text-2xl font-semibold tracking-[-0.02em] text-brand-dark",
        children: props.title
      }
    ),
    props.lead ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-base leading-7 text-brand-dark/75", children: props.lead }) : null
  ] });
}
function DataBoundaryPanel() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      AboutSectionHeading,
      {
        id: "about-data-boundary-heading",
        title: "Where your data goes",
        lead: "Guard keeps your decisions on this device. Sync is strictly opt-in."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 hidden md:block", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "overflow-hidden rounded-xl border border-brand-dark/10", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-[1fr_180px_180px_180px] border-b border-brand-dark/10 bg-surface-1 px-4 py-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Data" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Local by default" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Syncs only when enabled" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Never send from About" })
      ] }),
      ABOUT_DATA_BOUNDARY_ROWS.map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "div",
        {
          className: "grid grid-cols-[1fr_180px_180px_180px] border-b border-brand-dark/10 px-4 py-3 last:border-b-0",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: row.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/75", children: row.localDefault }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/75", children: row.optionalSync }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/75", children: row.neverFromAbout })
          ]
        },
        row.id
      ))
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 space-y-3 md:hidden", children: ABOUT_DATA_BOUNDARY_ROWS.map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs(Surface, { className: "!p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-2 text-sm font-semibold text-brand-dark", children: row.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Local" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-right text-sm text-brand-dark/75", children: row.localDefault })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Sync" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-right text-sm text-brand-dark/75", children: row.optionalSync })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Never" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-right text-sm text-brand-dark/75", children: row.neverFromAbout })
        ] })
      ] })
    ] }, row.id)) })
  ] });
}
function OpenStandardsMap() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      AboutSectionHeading,
      {
        id: "about-open-standards-heading",
        title: "Open standards map",
        lead: "HOL builds directional infrastructure for the agent internet. These are the areas we are working on."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "mt-6 grid gap-x-10 border-t border-brand-dark/10 sm:grid-cols-2", children: ABOUT_STANDARDS_NODES.map((node, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "li",
      {
        className: "flex items-start gap-3 border-b border-brand-dark/10 py-4",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "span",
            {
              className: "mt-px font-mono text-xs font-semibold tabular-nums text-brand-blue",
              "aria-hidden": "true",
              children: String(index + 1).padStart(2, "0")
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: node.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-brand-dark/75", children: node.body })
          ] })
        ]
      },
      node.id
    )) })
  ] });
}
function AboutExternalLink({
  linkId,
  href,
  children,
  className
}) {
  let safe = null;
  let errorReason = "";
  try {
    safe = assertSafeAboutExternalUrl(linkId, href);
  } catch (e) {
    errorReason = e instanceof Error ? e.message : "Invalid URL";
  }
  const handleClick = reactExports.useCallback(() => {
  }, [linkId]);
  if (!safe) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: [`text-brand-dark/75 cursor-not-allowed`, className ?? ""].join(" "),
        title: errorReason,
        children
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "a",
    {
      href,
      target: safe.target,
      rel: safe.rel,
      onClick: handleClick,
      className: [
        `inline-flex items-center gap-1 transition-colors`,
        className?.includes("hover:") ? "" : "hover:text-brand-blue",
        className ?? "",
        `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2`
      ].join(" "),
      children: [
        children,
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3.5 w-3.5 opacity-60", "aria-hidden": "true" })
      ]
    }
  );
}
const CARD_LINK_MAP = {
  protect_locally: "hol_guard_install",
  sync_team: "hol_guard_cloud",
  validate_ci: "plugin_scanner_ci_docs",
  standards_partner: "hol_partners",
  affiliate_starter_kit: "hol_affiliates"
};
function PathCard({ card }) {
  const isPrimary = card.priority === "primary";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    Surface,
    {
      className: `flex h-full flex-col ${isPrimary ? "sm:col-span-2 lg:col-span-1" : ""}`,
      tone: isPrimary ? "accent" : "default",
      children: [
        card.disclosureRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-2 text-[11px] font-medium text-brand-dark/75", children: "Disclosure required" }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: isPrimary ? "text-lg font-semibold text-brand-dark" : "text-base font-semibold text-brand-dark", children: card.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 flex-1 text-sm leading-6 text-brand-dark/75", children: card.description }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          AboutExternalLink,
          {
            linkId: CARD_LINK_MAP[card.id],
            href: card.ctaHref,
            className: "text-sm font-semibold text-brand-blue underline decoration-brand-blue/30 underline-offset-[3px] transition-colors duration-150 hover:decoration-brand-blue motion-reduce:transition-none",
            children: card.ctaLabel
          }
        ) })
      ]
    }
  );
}
function PathwayGrid() {
  const primary = ABOUT_PATH_CARDS.filter((c) => c.priority === "primary");
  const secondary = ABOUT_PATH_CARDS.filter((c) => c.priority === "secondary");
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      AboutSectionHeading,
      {
        id: "about-pathways-heading",
        title: "Choose your path",
        lead: "There are many ways to participate in the Guard ecosystem. Local protection comes first."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3", children: [
      primary.map((card) => /* @__PURE__ */ jsxRuntimeExports.jsx(PathCard, { card }, card.id)),
      secondary.map((card) => /* @__PURE__ */ jsxRuntimeExports.jsx(PathCard, { card }, card.id))
    ] })
  ] });
}
function EcosystemPrograms() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-8 lg:grid-cols-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        AboutSectionHeading,
        {
          id: "about-partner-heading",
          title: ABOUT_PARTNER_SECTION_TITLE,
          lead: ABOUT_PARTNER_SECTION_BODY
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-0", children: ABOUT_PARTNER_LEVELS.map((level, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-brand-dark/10 py-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs font-semibold tabular-nums text-brand-blue", children: String(i + 1).padStart(2, "0") }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: level.name })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "ml-7 mt-1 text-sm leading-6 text-brand-dark/75", children: level.description })
      ] }, level.name)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 border-t border-brand-dark/10 pt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        AboutExternalLink,
        {
          linkId: "hol_partners",
          href: ABOUT_PARTNER_CTA_HREF,
          className: "inline-flex items-center gap-1.5 rounded-lg bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white transition-colors duration-150 hover:bg-brand-blue/90 motion-reduce:transition-none",
          children: ABOUT_PARTNER_CTA
        }
      ) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        AboutSectionHeading,
        {
          id: "about-affiliate-heading",
          title: ABOUT_AFFILIATE_SECTION_TITLE,
          lead: ABOUT_AFFILIATE_SECTION_BODY
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 grid gap-3 sm:grid-cols-2", children: [
        { label: "Commission", value: ABOUT_AFFILIATE_TERMS.commissionRate },
        { label: "Duration", value: ABOUT_AFFILIATE_TERMS.commissionDuration },
        { label: "Cookie window", value: ABOUT_AFFILIATE_TERMS.cookieWindow },
        {
          label: "Qualification",
          value: ABOUT_AFFILIATE_TERMS.qualificationNote
        }
      ].map((metric) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-brand-dark/10 pt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-1 text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: metric.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: metric.value })
      ] }, metric.label)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-3 border-t border-brand-dark/10 pt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          AboutExternalLink,
          {
            linkId: "hol_affiliates",
            href: ABOUT_AFFILIATE_CTA_HREF,
            className: "inline-flex items-center gap-1.5 rounded-lg border border-brand-dark/15 bg-white px-4 py-2.5 text-sm font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-dark/25 hover:bg-surface-1 motion-reduce:transition-none",
            children: ABOUT_AFFILIATE_CTA
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-dark/75", children: ABOUT_AFFILIATE_DISCLOSURE })
      ] })
    ] })
  ] });
}
function AboutFooter() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("footer", { className: "border-t border-brand-dark/10 pt-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckBadge, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "HOL Guard" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Local-first" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-dark/75", children: "Built by Hashgraph Online. Open standards for the agent internet." })
  ] }) });
}
function useEditorialVisibility(threshold = 0.08) {
  const ref = reactExports.useRef(null);
  const [revealed, setRevealed] = reactExports.useState(
    typeof IntersectionObserver === "undefined"
  );
  reactExports.useEffect(() => {
    if (revealed) {
      return;
    }
    const el = ref.current;
    if (!el) {
      setRevealed(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setRevealed(true);
          observer.disconnect();
        }
      },
      { threshold, rootMargin: "0px 0px 10% 0px" }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold, revealed]);
  return { ref, revealed };
}
function SectionShell({
  children,
  className = "",
  threshold = 0.08,
  id,
  labelledBy
}) {
  const { ref, revealed } = useEditorialVisibility(threshold);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "section",
    {
      id,
      ref,
      "aria-labelledby": labelledBy,
      className: [
        className,
        "opacity-100 translate-y-0",
        revealed ? "motion-safe:transition-[opacity,transform] transition-opacity duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]" : ""
      ].join(" "),
      children
    }
  );
}
function AboutWorkspace({
  runtimeSummary
}) {
  reactExports.useEffect(() => {
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-20 pb-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "hero", labelledBy: "about-hero-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx(AboutHero, { runtimeSummary: runtimeSummary ?? null }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "data-boundary", labelledBy: "about-data-boundary-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx(DataBoundaryPanel, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "open-standards", labelledBy: "about-open-standards-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx(OpenStandardsMap, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "pathways", labelledBy: "about-pathways-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PathwayGrid, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "ecosystem", children: /* @__PURE__ */ jsxRuntimeExports.jsx(EcosystemPrograms, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "trust-footer", children: /* @__PURE__ */ jsxRuntimeExports.jsx(AboutFooter, {}) })
  ] });
}
export {
  AboutWorkspace
};
