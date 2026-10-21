const ABOUT_LOCAL_SECTION_TITLE = "What stays local";
const ABOUT_LOCAL_SECTION_BODY = "Your approvals, receipts, and runtime snapshots stay on this device. Guard Cloud sync is optional and off by default. You control what leaves your machine.";
const ABOUT_PARTNER_SECTION_TITLE = "Standards partner program";
const ABOUT_PARTNER_SECTION_BODY = "Join teams building on HOL open standards. Partners get early access to protocol drafts, co-marketing, and direct engineering support.";
const ABOUT_PARTNER_CTA = "Explore partner programs";
const ABOUT_PARTNER_CTA_HREF = "https://hol.org";
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
    ctaHref: "https://hol.org",
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
  hol_partners: { host: "hol.org", pathPrefix: "/", exactPath: true },
  hol_affiliates: { host: "hol.org", pathPrefix: "/guard/affiliates" },
  hol_guard_source: { host: "github.com", pathPrefix: "/hashgraph-online/hol-guard" }
};
export {
  ABOUT_LOCAL_SECTION_TITLE as A,
  ABOUT_LOCAL_SECTION_BODY as a,
  ABOUT_TRUST_CONTRACT_CLAIMS as b,
  ALLOWED_LINKS as c,
  ABOUT_DATA_BOUNDARY_ROWS as d,
  ABOUT_STANDARDS_NODES as e,
  ABOUT_PATH_CARDS as f,
  ABOUT_PARTNER_SECTION_TITLE as g,
  ABOUT_PARTNER_SECTION_BODY as h,
  ABOUT_PARTNER_LEVELS as i,
  ABOUT_PARTNER_CTA as j,
  ABOUT_PARTNER_CTA_HREF as k,
  ABOUT_AFFILIATE_SECTION_TITLE as l,
  ABOUT_AFFILIATE_SECTION_BODY as m,
  ABOUT_AFFILIATE_TERMS as n,
  ABOUT_AFFILIATE_CTA as o,
  ABOUT_AFFILIATE_CTA_HREF as p,
  ABOUT_AFFILIATE_DISCLOSURE as q
};
