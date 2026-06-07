import type { TrustCard, PathCard, PartnerLevel, AffiliateTerms } from "./about-types";

export const ABOUT_HERO_TITLE = "Open standards. Local protection.";
export const ABOUT_HERO_SUBTITLE =
  "A local safety layer for the agent internet.";
export const ABOUT_HERO_BODY =
  "HOL Guard protects local AI harness activity before risky work executes. HOL is building open trust infrastructure for the agent ecosystem — registries, identity, receipts, privacy, payments, and communication that agents can rely on.";

export const ABOUT_LOCAL_SECTION_TITLE = "What stays local";
export const ABOUT_LOCAL_SECTION_BODY =
  "Your approvals, receipts, and runtime snapshots stay on this device. Guard Cloud sync is optional and off by default. You control what leaves your machine.";

export const ABOUT_MISSION_SECTION_TITLE = "Why HOL exists";
export const ABOUT_MISSION_SECTION_BODY =
  "HOL is building open trust infrastructure and standards for AI-agent ecosystems. We believe agents deserve registries they can verify, identities they can prove, receipts they can audit, and communication they can trust — without locking into any single vendor.";

export const ABOUT_OPEN_SOURCE_NOTE =
  "Open-source core. View the repository license for the authoritative terms.";

export const ABOUT_PARTNER_SECTION_TITLE = "Standards partner program";
export const ABOUT_PARTNER_SECTION_BODY =
  "Join teams building on HOL open standards. Partners get early access to protocol drafts, co-marketing, and direct engineering support.";

export const ABOUT_PARTNER_CTA = "Become a partner";
export const ABOUT_PARTNER_CTA_HREF = "https://hol.org/partners";

export const ABOUT_AFFILIATE_SECTION_TITLE = "Affiliate starter kit";
export const ABOUT_AFFILIATE_SECTION_BODY =
  "Share Guard with your community and earn a recurring commission on qualified referrals.";
export const ABOUT_AFFILIATE_CTA = "Learn about affiliates";
export const ABOUT_AFFILIATE_CTA_HREF = "https://hol.org/guard/affiliates";

export const ABOUT_AFFILIATE_DISCLOSURE =
  "Affiliate earnings are paid on qualified paid customers after approval. Terms apply.";

export const ABOUT_TRUST_CARDS: TrustCard[] = [
  {
    title: "Approvals stay here",
    description:
      "Every allow, block, and policy decision is stored locally. No cloud required.",
  },
  {
    title: "Receipts are yours",
    description:
      "Guard generates tamper-evident receipts on this device. You own the audit trail.",
  },
  {
    title: "Snapshots stay local",
    description:
      "Runtime state, inventory, and settings remain on this machine unless you choose to sync.",
  },
  {
    title: "Optional cloud sync",
    description:
      "Guard Cloud is available for teams who want shared policy bundles and fleet visibility. It is off by default.",
  },
];

export const ABOUT_PATH_CARDS: PathCard[] = [
  {
    title: "Protect locally",
    description: "Install HOL Guard and start intercepting risky harness actions on this machine.",
    ctaLabel: "Get started",
    ctaHref: "https://hol.org/guard/docs/install",
  },
  {
    title: "Sync with your team",
    description: "Connect to Guard Cloud for shared policy bundles and cross-device fleet visibility.",
    ctaLabel: "Guard Cloud",
    ctaHref: "https://hol.org/guard/cloud",
  },
  {
    title: "Validate packages in CI",
    description: "Add the plugin-scanner to your CI pipeline to catch risky dependencies before deploy.",
    ctaLabel: "CI docs",
    ctaHref: "https://hol.org/guard/docs/ci",
  },
  {
    title: "Build standards",
    description: "Contribute to open trust standards for agent identity, registries, and receipts.",
    ctaLabel: "Standards repo",
    ctaHref: "https://github.com/hashgraph-online/standards-sdk",
  },
  {
    title: "Teach or promote Guard",
    description: "Create content, run workshops, or share Guard with your community.",
    ctaLabel: "Affiliate program",
    ctaHref: "https://hol.org/guard/affiliates",
  },
];

export const ABOUT_PARTNER_LEVELS: PartnerLevel[] = [
  {
    name: "Integrator",
    description: "Build Guard into your product or CI pipeline.",
  },
  {
    name: "Standards contributor",
    description: "Propose and review open trust protocol drafts.",
  },
  {
    name: "Advocate",
    description: "Publish guides, run workshops, and represent Guard in your community.",
  },
];

export const ABOUT_AFFILIATE_TERMS: AffiliateTerms = {
  commissionRate: "25%",
  commissionDuration: "12 months",
  cookieWindow: "120 days",
  qualificationNote: "Qualified paid customers after approval",
};
