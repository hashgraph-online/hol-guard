import { j as jsxRuntimeExports, ac as Tag, bp as Surface, B as Badge, r as reactExports, S as SectionLabel, aN as HiMiniArrowTopRightOnSquare, bq as HiMiniCheckBadge } from "../guard-dashboard.js";
const ABOUT_PARTNER_SECTION_TITLE = "Standards partner program";
const ABOUT_PARTNER_SECTION_BODY = "Join teams building on HOL open standards. Partners get early access to protocol drafts, co-marketing, and direct engineering support.";
const ABOUT_PARTNER_CTA = "Explore partner programs";
const ABOUT_PARTNER_CTA_HREF = "https://hol.org/guard/partners";
const ABOUT_AFFILIATE_SECTION_TITLE = "Affiliate starter kit";
const ABOUT_AFFILIATE_SECTION_BODY = "Approved affiliates can share Guard with their community and receive recurring commission on qualified paid referrals.";
const ABOUT_AFFILIATE_CTA = "Learn about affiliates";
const ABOUT_AFFILIATE_CTA_HREF = "https://hol.org/guard/affiliates";
const ABOUT_AFFILIATE_DISCLOSURE = "Affiliate earnings are paid on qualified paid customers after approval. Terms apply.";
const ABOUT_TRUST_CONTRACT_CLAIMS = [
  {
    id: "local_decisions",
    title: "Local decisions stay local",
    body: "Approvals and saved policy decisions are stored on this machine unless you enable sync.",
    proofLabel: "Local-first",
    tone: "blue"
  },
  {
    id: "exportable_receipts",
    title: "Receipts are inspectable",
    body: "Guard stores local receipts you can inspect, export, and compare over time.",
    proofLabel: "Auditable",
    tone: "green"
  },
  {
    id: "optional_sync",
    title: "Cloud sync is optional",
    body: "Guard Cloud adds team policy and shared history, but local protection works without it.",
    proofLabel: "Opt-in",
    tone: "purple"
  },
  {
    id: "open_standards",
    title: "Built around open standards",
    body: "HOL works on portable trust infrastructure for agent registries, identity, receipts, and coordination.",
    proofLabel: "Portable",
    tone: "slate"
  }
];
const ABOUT_DATA_BOUNDARY_ROWS = [
  {
    id: "approvals",
    label: "Approvals and saved decisions",
    localDefault: "Stored on this machine",
    optionalSync: "Policy summaries when enabled",
    neverFromAbout: "Raw prompts, local paths, secrets"
  },
  {
    id: "receipts",
    label: "Receipts",
    localDefault: "Inspectable and exportable locally",
    optionalSync: "Receipt history when enabled",
    neverFromAbout: "Guard token or install ID"
  },
  {
    id: "runtime_state",
    label: "Runtime state",
    localDefault: "Used to show local status",
    optionalSync: "Aggregate fleet status when enabled",
    neverFromAbout: "Workspace names or filesystem paths"
  },
  {
    id: "external_links",
    label: "About page links",
    localDefault: "No remote calls on first render",
    optionalSync: "None",
    neverFromAbout: "Referral IDs or user identifiers"
  }
];
const ABOUT_STANDARDS_NODES = [
  {
    id: "registries",
    label: "Registries",
    body: "Packages and agent capabilities should be discoverable and verifiable."
  },
  {
    id: "identity",
    label: "Identity",
    body: "Agents and tools need portable identity signals."
  },
  {
    id: "receipts",
    label: "Receipts",
    body: "Important actions should leave evidence users can audit."
  },
  {
    id: "privacy",
    label: "Privacy",
    body: "Local context should not leak just because a tool needs trust."
  },
  {
    id: "payments",
    label: "Payments",
    body: "Agent economies need trusted settlement rails."
  },
  {
    id: "communication",
    label: "Communication",
    body: "Agents need safe ways to coordinate across systems."
  }
];
const ABOUT_PATH_CARDS = [
  {
    id: "protect_locally",
    title: "Protect locally",
    description: "Install HOL Guard and start intercepting risky harness actions on this machine.",
    ctaLabel: "Get started",
    ctaHref: "https://hol.org/guard/install",
    ctaId: "path_protect_locally",
    priority: "primary",
    tone: "blue"
  },
  {
    id: "sync_team",
    title: "Sync with your team",
    description: "Connect to Guard Cloud for shared policy bundles and cross-device fleet visibility.",
    ctaLabel: "Guard Cloud",
    ctaHref: "https://hol.org/guard",
    ctaId: "path_sync_team",
    priority: "secondary",
    tone: "green"
  },
  {
    id: "validate_ci",
    title: "Validate packages in CI",
    description: "Add the plugin-scanner to your CI pipeline to catch risky dependencies before deploy.",
    ctaLabel: "CI docs",
    ctaHref: "https://hol.org/guard/docs/plugin-scanner/report-formats-and-ci",
    ctaId: "path_validate_ci",
    priority: "secondary",
    tone: "purple"
  },
  {
    id: "standards_partner",
    title: "Standards partner program",
    description: "Contribute to open trust standards for agent identity, registries, and receipts.",
    ctaLabel: "Explore partners",
    ctaHref: "https://hol.org/guard/partners",
    ctaId: "path_standards_partner",
    priority: "tertiary",
    tone: "slate"
  },
  {
    id: "affiliate_starter_kit",
    title: "Affiliate starter kit",
    description: "Approved affiliates can share Guard with their community and receive recurring commission on qualified paid referrals.",
    ctaLabel: "Learn about affiliates",
    ctaHref: "https://hol.org/guard/affiliates",
    ctaId: "path_affiliate_starter_kit",
    priority: "tertiary",
    tone: "slate",
    disclosureRequired: true
  }
];
const ABOUT_PARTNER_LEVELS = [
  {
    name: "Integrator",
    description: "Build Guard into your product or CI pipeline."
  },
  {
    name: "Standards contributor",
    description: "Propose and review open trust protocol drafts."
  },
  {
    name: "Advocate",
    description: "Publish guides, run workshops, and represent Guard in your community."
  }
];
const ABOUT_AFFILIATE_TERMS = {
  commissionRate: "25%",
  commissionDuration: "12 months",
  cookieWindow: "120 days",
  qualificationNote: "Qualified paid customers after approval"
};
const ALLOWED_LINKS = {
  guard_docs: { host: "hol.org", pathPrefix: "/guard/docs" },
  hol_home: { host: "hol.org", pathPrefix: "/" },
  hol_guard: { host: "hol.org", pathPrefix: "/guard" },
  hol_guard_install: { host: "hol.org", pathPrefix: "/guard/install" },
  hol_guard_cloud: { host: "hol.org", pathPrefix: "/guard" },
  plugin_scanner_ci_docs: { host: "hol.org", pathPrefix: "/guard/docs/plugin-scanner" },
  standards_sdk_github: { host: "github.com", pathPrefix: "/hashgraph-online/standards-sdk" },
  hol_partners: { host: "hol.org", pathPrefix: "/guard/partners" },
  hol_affiliates: { host: "hol.org", pathPrefix: "/guard/affiliates" },
  hol_guard_source: { host: "github.com", pathPrefix: "/hashgraph-online/hol-guard" }
};
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
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2 pt-3", children: items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-400", children: item.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: item.tone, children: item.value })
  ] }, item.label)) });
}
const toneClasses = {
  blue: "border-brand-blue/30 bg-brand-blue/[0.04]",
  green: "border-brand-green/30 bg-brand-green-bg/20",
  purple: "border-brand-purple/20 bg-brand-purple/[0.03]",
  slate: "border-slate-200 bg-slate-50/60"
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
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between mb-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-bold tracking-tight text-brand-dark", children: "Trust Contract" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Local-first" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", children: ABOUT_TRUST_CONTRACT_CLAIMS.map((claim) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: `rounded-lg border p-3 ${toneClasses[claim.tone] ?? toneClasses.slate}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2 mb-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: claim.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: badgeTones[claim.tone] ?? "default", children: claim.proofLabel })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-brand-dark/60", children: claim.body })
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
  if (!parsed.pathname.startsWith(allowed.pathPrefix)) {
    throw new AboutExternalLinkError(
      `Path prefix mismatch for ${linkId}: expected ${allowed.pathPrefix}, got ${parsed.pathname}`
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "grid gap-8 lg:grid-cols-[minmax(0,1fr)_420px] lg:items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Open standards. Local protection." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-4 text-4xl font-black tracking-tight text-brand-dark sm:text-5xl lg:text-6xl", children: "About HOL Guard" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 max-w-2xl text-lg leading-8 text-brand-dark/75", children: "A local-first safety layer for AI harnesses, built by HOL as part of open trust infrastructure for the agent internet." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-wrap gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(TrackedExternalButton, { linkId: "guard_docs", href: "https://hol.org/guard/docs", variant: "primary", children: "Read Guard docs" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(TrackedExternalButton, { linkId: "hol_guard_source", href: "https://github.com/hashgraph-online/hol-guard", variant: "outline", children: "View source" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(TrustContractPanel, { runtimeSummary })
  ] });
}
function DataBoundaryPanel() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Where your data goes" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-base leading-relaxed text-brand-dark/75", children: "Guard keeps your decisions on this device. Sync is strictly opt-in." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 hidden md:block", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "overflow-hidden rounded-xl border border-slate-100", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-[1fr_180px_180px_180px] border-b border-slate-100 bg-slate-50/60 px-4 py-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-500", children: "Data" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-500", children: "Local by default" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-500", children: "Syncs only when enabled" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-500", children: "Never send from About" })
      ] }),
      ABOUT_DATA_BOUNDARY_ROWS.map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "div",
        {
          className: "grid grid-cols-[1fr_180px_180px_180px] border-b border-slate-100 px-4 py-3 last:border-b-0",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: row.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/70", children: row.localDefault }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/70", children: row.optionalSync }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/70", children: row.neverFromAbout })
          ]
        },
        row.id
      ))
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 space-y-3 md:hidden", children: ABOUT_DATA_BOUNDARY_ROWS.map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs(Surface, { className: "!p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark mb-2", children: row.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-400", children: "Local" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/70 text-right", children: row.localDefault })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-400", children: "Sync" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/70 text-right", children: row.optionalSync })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-400", children: "Never" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark/70 text-right", children: row.neverFromAbout })
        ] })
      ] })
    ] }, row.id)) })
  ] });
}
function OpenStandardsMap() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Open standards map" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-base leading-relaxed text-brand-dark/75", children: "HOL builds directional infrastructure for the agent internet. These are the areas we are working on." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: ABOUT_STANDARDS_NODES.map((node, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      Surface,
      {
        className: "relative overflow-hidden",
        tone: index === 0 ? "accent" : "default",
        children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-brand-blue/10 text-brand-blue font-mono text-xs font-bold", children: String(index + 1).padStart(2, "0") }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: node.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-brand-dark/60", children: node.body })
          ] })
        ] })
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
        className: [`text-slate-400 cursor-not-allowed`, className ?? ""].join(" "),
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
function priorityLabel(priority) {
  if (priority === "primary") return "Primary";
  if (priority === "secondary") return "Secondary";
  return "Ecosystem";
}
function PathCard({ card }) {
  const isPrimary = card.priority === "primary";
  const isTertiary = card.priority === "tertiary";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    Surface,
    {
      className: `flex flex-col h-full ${isPrimary ? "sm:col-span-2 lg:col-span-2" : ""}`,
      tone: isPrimary ? "accent" : "default",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2 mb-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: isPrimary ? "info" : isTertiary ? "default" : "warning", children: priorityLabel(card.priority) }),
          card.disclosureRequired && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] text-slate-400", children: "Disclosure required" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-bold text-brand-dark", children: card.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-sm leading-relaxed text-brand-dark/70 flex-1", children: card.description }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          AboutExternalLink,
          {
            linkId: CARD_LINK_MAP[card.id],
            href: card.ctaHref,
            className: "text-sm font-semibold text-brand-blue hover:underline",
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
  const tertiary = ABOUT_PATH_CARDS.filter((c) => c.priority === "tertiary");
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Choose your path" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-base leading-relaxed text-brand-dark/75", children: "There are many ways to participate in the Guard ecosystem. Local protection comes first." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3", children: primary.map((card) => /* @__PURE__ */ jsxRuntimeExports.jsx(PathCard, { card }, card.id)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3", children: secondary.map((card) => /* @__PURE__ */ jsxRuntimeExports.jsx(PathCard, { card }, card.id)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-bold text-brand-dark mb-3", children: "Ecosystem programs" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-4 sm:grid-cols-2", children: tertiary.map((card) => /* @__PURE__ */ jsxRuntimeExports.jsx(PathCard, { card }, card.id)) })
    ] })
  ] });
}
function EcosystemPrograms() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-8 lg:grid-cols-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: ABOUT_PARTNER_SECTION_TITLE }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-base leading-relaxed text-brand-dark/75", children: ABOUT_PARTNER_SECTION_BODY }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-0", children: ABOUT_PARTNER_LEVELS.map((level, i) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 py-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs font-black text-brand-blue/70", children: String(i + 1).padStart(2, "0") }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-bold text-brand-dark", children: level.name })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 ml-7 text-sm leading-relaxed text-slate-500", children: level.description })
      ] }, level.name)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 pt-4 border-t border-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        AboutExternalLink,
        {
          linkId: "hol_partners",
          href: ABOUT_PARTNER_CTA_HREF,
          className: "inline-flex items-center gap-1.5 rounded-lg bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90",
          children: ABOUT_PARTNER_CTA
        }
      ) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: ABOUT_AFFILIATE_SECTION_TITLE }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-base leading-relaxed text-brand-dark/75", children: ABOUT_AFFILIATE_SECTION_BODY }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 grid gap-3 sm:grid-cols-2", children: [
        { label: "Commission", value: ABOUT_AFFILIATE_TERMS.commissionRate },
        { label: "Duration", value: ABOUT_AFFILIATE_TERMS.commissionDuration },
        { label: "Cookie window", value: ABOUT_AFFILIATE_TERMS.cookieWindow },
        {
          label: "Qualification",
          value: ABOUT_AFFILIATE_TERMS.qualificationNote
        }
      ].map((metric) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 pt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1", children: metric.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-bold text-brand-dark", children: metric.value })
      ] }, metric.label)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-3 pt-4 border-t border-slate-100", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          AboutExternalLink,
          {
            linkId: "hol_affiliates",
            href: ABOUT_AFFILIATE_CTA_HREF,
            className: "inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 hover:border-slate-300",
            children: ABOUT_AFFILIATE_CTA
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400", children: ABOUT_AFFILIATE_DISCLOSURE })
      ] })
    ] })
  ] });
}
function AboutFooter() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("footer", { className: "border-t border-slate-100 pt-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckBadge, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "HOL Guard" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Local-first" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400", children: "Built by Hashgraph Online. Open standards for the agent internet." })
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
  id
}) {
  const { ref, revealed } = useEditorialVisibility(threshold);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "section",
    {
      id,
      ref,
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
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "hero", children: /* @__PURE__ */ jsxRuntimeExports.jsx(AboutHero, { runtimeSummary: runtimeSummary ?? null }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "data-boundary", children: /* @__PURE__ */ jsxRuntimeExports.jsx(DataBoundaryPanel, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "open-standards", children: /* @__PURE__ */ jsxRuntimeExports.jsx(OpenStandardsMap, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "pathways", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PathwayGrid, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "ecosystem", children: /* @__PURE__ */ jsxRuntimeExports.jsx(EcosystemPrograms, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "trust-footer", children: /* @__PURE__ */ jsxRuntimeExports.jsx(AboutFooter, {}) })
  ] });
}
export {
  AboutWorkspace
};
