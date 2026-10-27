import { r as reactExports, j as jsxRuntimeExports, e2 as Surface, co as HiMiniArrowTopRightOnSquare, a6 as Badge } from "../guard-dashboard.js";
import { B as BrandHero, b as BrandHeroBadge, a as BrandHeroFacts, d as BrandMark } from "./brand-hero-COty1p6U.js";
import { b as ALLOWED_LINKS, c as ABOUT_HERO_TITLE, d as ABOUT_HERO_BODY, e as ABOUT_TRUST_CONTRACT_CLAIMS, f as ABOUT_DATA_BOUNDARY_ROWS, g as ABOUT_STANDARDS_NODES, h as ABOUT_PATH_CARDS, i as ABOUT_PARTNER_SECTION_BODY, j as ABOUT_PARTNER_SECTION_TITLE, k as ABOUT_PARTNER_LEVELS, l as ABOUT_PARTNER_CTA, m as ABOUT_PARTNER_CTA_HREF, n as ABOUT_AFFILIATE_SECTION_BODY, o as ABOUT_AFFILIATE_SECTION_TITLE, p as ABOUT_AFFILIATE_TERMS, q as ABOUT_AFFILIATE_CTA, r as ABOUT_AFFILIATE_CTA_HREF, s as ABOUT_AFFILIATE_DISCLOSURE } from "./about-content-Dr9zFg1V.js";
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
      "data-primary": variant === "primary" ? "true" : void 0,
      className: `${base} ${size} ${tone} no-underline`,
      children
    }
  );
}
const COUNT_FORMAT = new Intl.NumberFormat("en-US");
function formatAboutCount(value) {
  return COUNT_FORMAT.format(value);
}
function resolveSyncState(runtimeSummary) {
  switch (runtimeSummary?.cloudState) {
    case "paired_active":
      switch (runtimeSummary.syncHealth) {
        case "healthy":
        case "pending":
          return "on";
        case "failed":
        case "degraded":
        case "stale":
          return "stalled";
        case "disabled":
          return "off";
        default:
          return "unavailable";
      }
    case "paired_waiting":
      return "pairing";
    case "local_only":
      return "off";
    default:
      return "unavailable";
  }
}
const SYNC_STATE_LABEL = {
  on: "On",
  stalled: "Not syncing",
  pairing: "First sync",
  off: "Off",
  unavailable: "Unavailable"
};
const SYNC_CAPTION = {
  on: "Sync is on, so policy summaries and receipt history cross the gate to Guard Cloud.",
  stalled: "Guard Cloud is connected, but recent syncs have not landed, so nothing is crossing the gate right now.",
  pairing: "This device is paired with Guard Cloud and waiting for its first sync; nothing has crossed the gate yet.",
  off: "Sync is off, so nothing on this device crosses the gate.",
  unavailable: "Guard could not report its sync state, so this figure makes no claim about the gate."
};
function MachineFigure({
  runtimeSummary
}) {
  const sync = resolveSyncState(runtimeSummary);
  const open = sync === "on";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("figure", { "aria-labelledby": "about-figure-caption", className: "about-figure", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid lg:grid-cols-[minmax(0,1fr)_5rem_2.5rem_minmax(0,11rem)] lg:grid-rows-[minmax(0,1fr)_auto_minmax(0,1fr)]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(DevicePerimeter, { runtimeSummary }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SyncGate, { sync }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Crossing, { open }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(OutsideNode, { title: "Guard Cloud", className: "lg:col-start-4 lg:row-start-2 lg:self-center", children: "Team policy and shared history, when you opt in." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        OutsideNode,
        {
          title: "hol.org",
          callout: 4,
          className: "mt-3 lg:col-start-4 lg:row-start-3 lg:mt-0 lg:self-end",
          children: "Links only; this page sends nothing."
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "figcaption",
      {
        id: "about-figure-caption",
        className: "mt-4 max-w-[68ch] text-sm leading-6 text-brand-dark/75",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: "Fig. 1" }),
          " This device, and what can leave it.",
          " ",
          SYNC_CAPTION[sync]
        ]
      }
    )
  ] });
}
function DevicePerimeter({ runtimeSummary }) {
  const pending = runtimeSummary?.pendingCount ?? 0;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative rounded-2xl border border-brand-dark/25 px-4 pb-8 pt-6 sm:px-6 sm:pt-7 lg:row-span-3 lg:pb-6 lg:pr-24", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "absolute -top-2.5 left-4 bg-white px-2 text-xs font-semibold text-brand-dark sm:left-6", children: "This device" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { className: "about-flow", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(FlowNode, { title: "Agents and MCP tools", children: "Ask to run, edit or connect." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(FlowNode, { title: "HOL Guard", emphasis: true, arrow: true, children: [
        "Checks each action first.",
        runtimeSummary ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-3 flex flex-col gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Readout, { label: "Guard version", value: runtimeSummary.guardVersion ?? "Unknown" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            Readout,
            {
              label: "Local protection",
              value: pending > 0 ? `${pending} pending` : "Active",
              attention: pending > 0
            }
          )
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FlowNode, { title: "Your decision", callout: 1, arrow: true, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "relative flex flex-col gap-1 pl-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            "aria-hidden": "true",
            className: "absolute bottom-[0.7rem] left-0 top-[0.7rem] w-0.5 bg-brand-blue"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Outcome, { lead: "Clear", children: "runs" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Outcome, { lead: "Unclear", children: "waits for you" })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 border-t border-dashed border-brand-dark/20 pt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-brand-dark", children: "Stored on this device" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-1 flex flex-wrap gap-x-5 sm:grid sm:grid-cols-3 sm:divide-x sm:divide-brand-dark/12", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(StoreItem, { callout: 1, title: "Approvals and policy" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          StoreItem,
          {
            callout: 2,
            title: "Receipts",
            value: runtimeSummary ? formatAboutCount(runtimeSummary.receiptCount) : void 0
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(StoreItem, { title: "Runtime state" })
      ] })
    ] })
  ] });
}
function FlowNode({
  title,
  children,
  emphasis = false,
  arrow = false,
  callout
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "li",
    {
      className: `relative rounded-xl border p-3 sm:p-3.5 ${emphasis ? "border-brand-blue/50 bg-[#f1f6ff]" : "border-brand-dark/12 bg-surface-1"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: title }),
          callout ? /* @__PURE__ */ jsxRuntimeExports.jsx(Callout, { n: callout }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-sm leading-6 text-brand-dark/75", children }),
        arrow ? /* @__PURE__ */ jsxRuntimeExports.jsx(ArrowHead, {}) : null
      ]
    }
  );
}
function ArrowHead() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "svg",
    {
      "aria-hidden": "true",
      viewBox: "0 0 10 10",
      className: "about-arrowhead absolute -left-2.5 top-[1.375rem] size-2.5 -translate-y-1/2 text-brand-blue md:left-1/2 md:top-full md:-translate-x-1/2 md:translate-y-0 md:-rotate-90",
      children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { d: "M1 1 9 5 1 9Z", fill: "currentColor" })
    }
  );
}
function Outcome({ lead, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-baseline gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "-ml-3 h-0.5 w-3 shrink-0 translate-y-[-0.2rem] bg-brand-blue" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: lead }),
      " ",
      children
    ] })
  ] });
}
function StoreItem({
  title,
  callout,
  value
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center gap-2 py-1 sm:min-h-9 sm:px-4 sm:py-2 sm:first:pl-0 sm:last:pr-0", children: [
    callout ? /* @__PURE__ */ jsxRuntimeExports.jsx(Callout, { n: callout }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex min-w-0 flex-1 items-baseline justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: title }),
      value !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-sm font-semibold tabular-nums text-brand-dark", children: value }) : null
    ] })
  ] });
}
function SyncGate({ sync }) {
  const open = sync === "on";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "relative z-10 -mt-5 flex justify-center lg:col-start-2 lg:row-start-2 lg:mt-0 lg:-ml-20 lg:w-40 lg:self-center", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: `w-full max-w-60 rounded-xl border bg-white p-3 lg:max-w-none ${open ? "border-2 border-brand-blue" : "border-dashed border-brand-dark/40"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "Sync gate" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Callout, { n: 3 })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-2 block", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          Readout,
          {
            label: "Sync",
            value: SYNC_STATE_LABEL[sync],
            attention: sync === "pairing" || sync === "stalled"
          }
        ) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-2 block text-xs leading-5 text-brand-dark/75", children: GATE_CARRIES[sync] })
      ]
    }
  ) });
}
const GATE_CARRIES = {
  on: "Carries policy summaries and receipt history.",
  stalled: "Would carry policy summaries and receipt history once sync recovers.",
  pairing: "Waiting for the first sync to land.",
  off: "Would carry policy summaries and receipt history.",
  unavailable: "Would carry policy summaries and receipt history."
};
function OutsideNode({
  title,
  callout,
  children,
  className = ""
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-xl border border-dashed border-brand-dark/25 p-3 ${className}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: title }),
      callout ? /* @__PURE__ */ jsxRuntimeExports.jsx(Callout, { n: callout }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-xs leading-5 text-brand-dark/75", children })
  ] });
}
function Crossing({ open }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-hidden": "true", className: "flex items-center justify-center lg:col-start-3 lg:row-start-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
    "span",
    {
      className: `block h-6 w-0 border-l-2 lg:h-0 lg:w-full lg:border-l-0 lg:border-t-2 ${open ? "border-brand-blue" : "border-dashed border-brand-dark/30"}`
    }
  ) });
}
function Readout({
  label,
  value,
  attention = false
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-baseline justify-between gap-3 text-xs", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-brand-dark/75", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: `font-semibold tabular-nums text-brand-dark ${attention ? "rounded-full bg-brand-attention-bg px-2" : ""}`,
        children: value
      }
    )
  ] });
}
function Callout({ n }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex size-5 shrink-0 items-center justify-center rounded-full bg-brand-dark text-[11px] font-semibold tabular-nums text-white", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Claim " }),
    n
  ] });
}
const SYNC_FACT = {
  on: "Cloud sync on",
  stalled: "Cloud sync stalled",
  pairing: "Cloud sync waiting for first upload",
  off: "Cloud sync off",
  unavailable: "Cloud sync unavailable"
};
function resolveAboutHeroState(runtimeSummary) {
  if (!runtimeSummary) {
    return {
      tone: "setup",
      badge: "Not reporting",
      liveLabel: "Local-first",
      facts: ["Open source under Apache-2.0"]
    };
  }
  const pending = runtimeSummary.pendingCount;
  const version = runtimeSummary.guardVersion?.trim();
  const facts = [
    version && version.toLowerCase() !== "unknown" ? `Version ${version}` : null,
    SYNC_FACT[resolveSyncState(runtimeSummary)],
    "Open source under Apache-2.0"
  ].filter((fact) => fact !== null);
  if (pending > 0) {
    return {
      tone: "review",
      badge: `${pending} waiting for you`,
      liveLabel: `${pending} waiting`,
      facts
    };
  }
  return { tone: "setup", badge: "Running on this device", liveLabel: "Local-first", facts };
}
function AboutHero({
  runtimeSummary
}) {
  const hero = resolveAboutHeroState(runtimeSummary);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(BrandHero, { tone: hero.tone, liveLabel: hero.liveLabel, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(BrandHeroBadge, { tone: hero.tone, children: hero.badge }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "h1",
          {
            id: "about-hero-heading",
            className: "guard-hero-title text-4xl font-semibold tracking-[-0.03em] text-white sm:text-5xl",
            children: ABOUT_HERO_TITLE
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 max-w-xl text-base leading-7 text-white/80 sm:text-lg sm:leading-8", children: ABOUT_HERO_BODY })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-hero-ctas flex flex-wrap gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(TrackedExternalButton, { linkId: "guard_docs", href: "https://hol.org/guard/docs", variant: "primary", children: "Read Guard docs" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(TrackedExternalButton, { linkId: "hol_guard_source", href: "https://github.com/hashgraph-online/hol-guard", variant: "outline", children: "View source" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(BrandHeroFacts, { facts: hero.facts })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(MachineFigure, { runtimeSummary })
  ] });
}
function TrustContractPanel() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "about-trust-heading", className: "text-2xl font-semibold tracking-[-0.02em] text-brand-dark", children: "Trust Contract" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "mt-5 grid gap-x-8 border-t border-brand-dark/10 sm:grid-cols-2 xl:grid-cols-4", children: ABOUT_TRUST_CONTRACT_CLAIMS.map((claim, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "border-b border-brand-dark/10 py-4 xl:border-b-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Callout, { n: index + 1 }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: claim.title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: claim.body }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs font-semibold text-brand-dark", children: claim.proofLabel })
    ] }, claim.id)) })
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
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-[minmax(0,1.1fr)_repeat(3,minmax(0,1fr))] gap-x-6 border-b border-brand-dark/10 bg-surface-1 px-4 py-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Data" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Local by default" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Syncs only when enabled" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-wider text-brand-dark/75", children: "Never send from About" })
      ] }),
      ABOUT_DATA_BOUNDARY_ROWS.map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "div",
        {
          className: "grid grid-cols-[minmax(0,1.1fr)_repeat(3,minmax(0,1fr))] gap-x-6 border-b border-brand-dark/10 px-4 py-3 last:border-b-0",
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "lg:grid lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)] lg:gap-x-12", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      AboutSectionHeading,
      {
        id: "about-open-standards-heading",
        title: "Open standards map",
        lead: "HOL builds directional infrastructure for the agent internet. These are the areas we are working on."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-6 grid gap-x-10 border-t border-brand-dark/10 sm:grid-cols-2 lg:mt-1", children: ABOUT_STANDARDS_NODES.map((node) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "border-b border-brand-dark/10 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: node.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm leading-6 text-brand-dark/75", children: node.body })
    ] }, node.id)) })
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-col border-t border-brand-dark/10 py-5 lg:border-l lg:border-t-0 lg:px-6 lg:py-1 lg:first:border-l-0 lg:first:pl-0", children: [
    card.disclosureRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-2 text-[11px] font-medium text-brand-dark/75", children: "Disclosure required" }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: card.title }),
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
  ] });
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
    /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-6 grid lg:grid-cols-3", children: [
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-0", children: ABOUT_PARTNER_LEVELS.map((level) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-brand-dark/10 py-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: level.name }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-brand-dark/75", children: level.description })
      ] }, level.name)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 border-t border-brand-dark/10 pt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        AboutExternalLink,
        {
          linkId: "hol_partners",
          href: ABOUT_PARTNER_CTA_HREF,
          className: "inline-flex min-h-11 items-center gap-1.5 rounded-lg border border-brand-dark/15 bg-white px-4 py-2.5 text-sm font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-dark/25 hover:bg-surface-1 motion-reduce:transition-none",
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
            className: "inline-flex min-h-11 items-center gap-1.5 rounded-lg border border-brand-dark/15 bg-white px-4 py-2.5 text-sm font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-dark/25 hover:bg-surface-1 motion-reduce:transition-none",
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
      /* @__PURE__ */ jsxRuntimeExports.jsx(BrandMark, { color: "currentColor", className: "size-6 text-brand-dark" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "HOL Guard" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Local-first" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-dark/75", children: "Built by HOL. Open standards for the agent internet." })
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "about-page space-y-16 pb-10 lg:space-y-20", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "hero", labelledBy: "about-hero-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx(AboutHero, { runtimeSummary: runtimeSummary ?? null }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionShell, { id: "trust-contract", labelledBy: "about-trust-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx(TrustContractPanel, {}) }),
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
