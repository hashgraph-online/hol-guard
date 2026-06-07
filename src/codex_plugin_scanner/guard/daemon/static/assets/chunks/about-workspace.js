import { j as jsxRuntimeExports, H as HiMiniShieldCheck, an as HiMiniDocumentText, D as HiMiniLockClosed, o as HiMiniCloud, ao as HiMiniArrowTopRightOnSquare, ap as HiMiniCheckBadge, B as Badge, r as reactExports } from "../guard-dashboard.js";
const ALLOWED_HOSTS = /* @__PURE__ */ new Set([
  "hol.org",
  "www.hol.org",
  "github.com",
  "x.com",
  "t.me"
]);
class AboutExternalLinkError extends Error {
  constructor(message) {
    super(message);
    this.name = "AboutExternalLinkError";
  }
}
function isLocalhost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1" || hostname.startsWith("192.168.") || hostname.startsWith("10.") || hostname.startsWith("172.") || hostname.endsWith(".local") || hostname.endsWith(".internal");
}
function assertSafeAboutExternalUrl(raw) {
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
  if (isLocalhost(parsed.hostname)) {
    throw new AboutExternalLinkError(`URL must not point to localhost or loopback: ${raw}`);
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new AboutExternalLinkError(`Unknown host not in allowlist: ${parsed.hostname}`);
  }
  const forbiddenParams = ["guard-token", "guardDaemon", "workspace", "device", "install", "user"];
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
const ABOUT_HERO_TITLE = "Open standards. Local protection.";
const ABOUT_HERO_SUBTITLE = "A local safety layer for the agent internet.";
const ABOUT_HERO_BODY = "HOL Guard protects local AI harness activity before risky work executes. HOL is building open trust infrastructure for the agent ecosystem — registries, identity, receipts, privacy, payments, and communication that agents can rely on.";
const ABOUT_LOCAL_SECTION_TITLE = "What stays local";
const ABOUT_LOCAL_SECTION_BODY = "Your approvals, receipts, and runtime snapshots stay on this device. Guard Cloud sync is optional and off by default. You control what leaves your machine.";
const ABOUT_MISSION_SECTION_TITLE = "Why HOL exists";
const ABOUT_MISSION_SECTION_BODY = "HOL is building open trust infrastructure and standards for AI-agent ecosystems. We believe agents deserve registries they can verify, identities they can prove, receipts they can audit, and communication they can trust — without locking into any single vendor.";
const ABOUT_OPEN_SOURCE_NOTE = "Open-source core. View the repository license for the authoritative terms.";
const ABOUT_PARTNER_SECTION_TITLE = "Standards partner program";
const ABOUT_PARTNER_SECTION_BODY = "Join teams building on HOL open standards. Partners get early access to protocol drafts, co-marketing, and direct engineering support.";
const ABOUT_PARTNER_CTA = "Become a partner";
const ABOUT_PARTNER_CTA_HREF = "https://hol.org";
const ABOUT_AFFILIATE_SECTION_TITLE = "Affiliate starter kit";
const ABOUT_AFFILIATE_SECTION_BODY = "Share Guard with your community and score a recurring commission on qualified referrals.";
const ABOUT_AFFILIATE_CTA = "Learn about affiliates";
const ABOUT_AFFILIATE_CTA_HREF = "https://hol.org/guard/affiliates";
const ABOUT_AFFILIATE_DISCLOSURE = "Affiliate earnings are paid on qualified paid customers after approval. Terms apply.";
const ABOUT_TRUST_CARDS = [
  {
    title: "Approvals stay here",
    description: "Every allow, block, and policy decision is stored locally. No cloud required."
  },
  {
    title: "Receipts are yours",
    description: "Guard generates tamper-evident receipts on this device. You own the audit trail."
  },
  {
    title: "Snapshots stay local",
    description: "Runtime state, inventory, and settings remain on this machine unless you choose to sync."
  },
  {
    title: "Optional cloud sync",
    description: "Guard Cloud is available for teams who want shared policy bundles and fleet visibility. It is off by default."
  }
];
const ABOUT_PATH_CARDS = [
  {
    title: "Protect locally",
    description: "Install HOL Guard and start intercepting risky harness actions on this machine.",
    ctaLabel: "Get started",
    ctaHref: "https://hol.org/guard/install"
  },
  {
    title: "Sync with your team",
    description: "Connect to Guard Cloud for shared policy bundles and cross-device fleet visibility.",
    ctaLabel: "Guard Cloud",
    ctaHref: "https://hol.org/guard"
  },
  {
    title: "Validate packages in CI",
    description: "Add the plugin-scanner to your CI pipeline to catch risky dependencies before deploy.",
    ctaLabel: "CI docs",
    ctaHref: "https://hol.org/guard/docs/plugin-scanner/report-formats-and-ci"
  },
  {
    title: "Build standards",
    description: "Contribute to open trust standards for agent identity, registries, and receipts.",
    ctaLabel: "Standards repo",
    ctaHref: "https://github.com/hashgraph-online/standards-sdk"
  },
  {
    title: "Teach or promote Guard",
    description: "Create content, run workshops, or share Guard with your community.",
    ctaLabel: "Affiliate program",
    ctaHref: "https://hol.org/guard/affiliates"
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
function useEditorialVisibility(threshold = 0.08) {
  const ref = reactExports.useRef(null);
  const [state, setState] = reactExports.useState("idle");
  reactExports.useEffect(() => {
    if (typeof IntersectionObserver === "undefined") {
      setState("visible");
      return;
    }
    setState("hidden");
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setState("visible");
          observer.disconnect();
        }
      },
      { threshold }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold]);
  return { ref, state };
}
function EditorialSection({
  children,
  className = "",
  threshold = 0.08
}) {
  const { ref, state } = useEditorialVisibility(threshold);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "section",
    {
      ref,
      className: [
        className,
        state === "idle" ? "" : "motion-safe:transition-[opacity,transform] transition-opacity duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]",
        state === "idle" || state === "visible" ? "opacity-100 translate-y-0" : "opacity-0 motion-safe:translate-y-6"
      ].join(" "),
      children
    }
  );
}
function AboutExternalLink({
  href,
  children,
  className
}) {
  let safe = null;
  let errorReason = "";
  try {
    safe = assertSafeAboutExternalUrl(href);
  } catch (e) {
    errorReason = e instanceof Error ? e.message : "Invalid URL";
  }
  const handleClick = reactExports.useCallback(() => {
  }, [href]);
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
        `inline-flex items-center gap-1 transition-colors hover:text-brand-blue`,
        `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2`,
        className ?? ""
      ].join(" "),
      children: [
        children,
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3.5 w-3.5 opacity-60", "aria-hidden": "true" })
      ]
    }
  );
}
function TrustPillar({
  title,
  desc,
  icon
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-l-4 border-brand-blue/60 pl-6 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 mb-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0 flex h-8 w-8 items-center justify-center rounded-lg bg-brand-blue/[0.06] text-brand-blue", children: icon }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-bold text-brand-dark", children: title })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-relaxed text-slate-500", children: desc })
  ] });
}
function PathStep({
  index,
  title,
  desc,
  ctaLabel,
  ctaHref
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative grid grid-cols-[48px_1fr] gap-4 sm:gap-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "relative z-10 flex h-12 w-12 items-center justify-center rounded-full border-2 border-brand-blue bg-white", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-sm font-black text-brand-blue", children: String(index + 1).padStart(2, "0") }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "pt-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-base font-bold text-brand-dark", children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-sm leading-relaxed text-slate-500", children: desc }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        AboutExternalLink,
        {
          href: ctaHref,
          className: "text-sm font-semibold text-brand-blue hover:underline",
          children: ctaLabel
        }
      ) })
    ] })
  ] });
}
function PartnerLevelRow({
  level,
  index
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 py-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs font-black text-brand-blue/70", children: String(index + 1).padStart(2, "0") }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-bold text-brand-dark", children: level.name })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 ml-7 text-sm leading-relaxed text-slate-500", children: level.description })
  ] });
}
function AboutWorkspace() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-20 pb-10", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(EditorialSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-4xl sm:text-5xl font-black tracking-tight text-brand-dark leading-[0.95] mb-6", children: ABOUT_HERO_TITLE }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xl sm:text-2xl font-medium text-brand-blue mb-6", children: ABOUT_HERO_SUBTITLE }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base leading-relaxed text-brand-dark/75 max-w-2xl", children: ABOUT_HERO_BODY })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(EditorialSection, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-8", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-bold tracking-widest uppercase text-brand-blue mb-3 block", children: ABOUT_LOCAL_SECTION_TITLE }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base leading-relaxed text-slate-500 max-w-2xl", children: ABOUT_LOCAL_SECTION_BODY })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid sm:grid-cols-2 gap-x-12 gap-y-8", children: ABOUT_TRUST_CARDS.map((card, i) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        TrustPillar,
        {
          title: card.title,
          desc: card.description,
          icon: i === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4" }) : i === 1 ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-4 w-4" }) : i === 2 ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "h-4 w-4" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "h-4 w-4" })
        },
        card.title
      )) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EditorialSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-bold tracking-widest uppercase text-brand-blue mb-3 block", children: ABOUT_MISSION_SECTION_TITLE }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-lg leading-relaxed text-brand-dark/75", children: ABOUT_MISSION_SECTION_BODY }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm text-slate-400", children: ABOUT_OPEN_SOURCE_NOTE })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(EditorialSection, { threshold: 0.15, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-10", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-bold tracking-widest uppercase text-brand-blue mb-3 block", children: "Choose your path" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base leading-relaxed text-slate-500 max-w-2xl", children: "There are many ways to participate in the Guard ecosystem." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute left-[23px] top-0 bottom-0 w-[2px] bg-slate-100" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-12", children: ABOUT_PATH_CARDS.map((card, i) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          PathStep,
          {
            index: i,
            title: card.title,
            desc: card.description,
            ctaLabel: card.ctaLabel,
            ctaHref: card.ctaHref
          },
          card.title
        )) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EditorialSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-bold tracking-widest uppercase text-brand-blue mb-3 block", children: ABOUT_PARTNER_SECTION_TITLE }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base leading-relaxed text-brand-dark/75 mb-8", children: ABOUT_PARTNER_SECTION_BODY }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: ABOUT_PARTNER_LEVELS.map((level, i) => /* @__PURE__ */ jsxRuntimeExports.jsx(PartnerLevelRow, { level, index: i }, level.name)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 pt-4 border-t border-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        AboutExternalLink,
        {
          href: ABOUT_PARTNER_CTA_HREF,
          className: "inline-flex items-center gap-1.5 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-brand-blue/90",
          children: [
            ABOUT_PARTNER_CTA,
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-4 w-4", "aria-hidden": "true" })
          ]
        }
      ) })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EditorialSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-3xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-bold tracking-widest uppercase text-brand-blue mb-3 block", children: ABOUT_AFFILIATE_SECTION_TITLE }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base leading-relaxed text-brand-dark/75 mb-8", children: ABOUT_AFFILIATE_SECTION_BODY }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8", children: [
        { label: "Commission", value: ABOUT_AFFILIATE_TERMS.commissionRate },
        { label: "Duration", value: ABOUT_AFFILIATE_TERMS.commissionDuration },
        { label: "Cookie window", value: ABOUT_AFFILIATE_TERMS.cookieWindow },
        {
          label: "Qualification",
          value: ABOUT_AFFILIATE_TERMS.qualificationNote
        }
      ].map((metric) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 pt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400 mb-1", children: metric.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-lg font-bold text-brand-dark", children: metric.value })
      ] }, metric.label)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3 pt-4 border-t border-slate-100", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          AboutExternalLink,
          {
            href: ABOUT_AFFILIATE_CTA_HREF,
            className: "inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 hover:border-slate-300",
            children: [
              ABOUT_AFFILIATE_CTA,
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-4 w-4", "aria-hidden": "true" })
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400", children: ABOUT_AFFILIATE_DISCLOSURE })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EditorialSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsx("footer", { className: "border-t border-slate-100 pt-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckBadge, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: "HOL Guard" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Local-first" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400", children: "Built by Hashgraph Online. Open standards for the agent internet." })
    ] }) }) })
  ] });
}
export {
  AboutWorkspace
};
