/**
 * About page content version.
 * Bump when the content shape changes in a way that tests must validate.
 */
export const ABOUT_CONTENT_VERSION = "2.0.0";

export type AboutSectionId =
  | "hero"
  | "data_boundary"
  | "open_standards"
  | "pathways"
  | "partner_program"
  | "affiliate_program"
  | "trust_footer";

export type AboutLinkId =
  | "guard_docs"
  | "hol_home"
  | "hol_guard"
  | "hol_guard_install"
  | "hol_guard_cloud"
  | "plugin_scanner_ci_docs"
  | "standards_sdk_github"
  | "hol_partners"
  | "hol_affiliates"
  | "hol_guard_source";

export type AboutCtaId =
  | "hero_docs"
  | "hero_source"
  | "path_protect_locally"
  | "path_sync_team"
  | "path_validate_ci"
  | "path_standards_partner"
  | "path_affiliate_starter_kit"
  | "partner_program"
  | "affiliate_program";

export type TrustContractClaim = {
  id: "local_decisions" | "exportable_receipts" | "optional_sync" | "open_standards";
  title: string;
  body: string;
  proofLabel: string;
  tone: "blue" | "green" | "purple" | "slate";
};

export type DataBoundaryRow = {
  id: "approvals" | "receipts" | "runtime_state" | "external_links";
  label: string;
  localDefault: string;
  optionalSync: string;
  neverFromAbout: string;
};

export type StandardsNode = {
  id: "registries" | "identity" | "receipts" | "privacy" | "payments" | "communication";
  label: string;
  body: string;
};

export type AboutPathPriority = "primary" | "secondary" | "tertiary";

export type AboutPathCard = {
  id:
    | "protect_locally"
    | "sync_team"
    | "validate_ci"
    | "standards_partner"
    | "affiliate_starter_kit";
  title: string;
  description: string;
  ctaLabel: string;
  ctaHref: string;
  ctaId: AboutCtaId;
  priority: AboutPathPriority;
  tone: "blue" | "green" | "purple" | "slate";
  disclosureRequired?: boolean;
};

export type AboutRuntimeSummary = {
  guardVersion: string | null;
  cloudState: "local_only" | "paired_waiting" | "paired_active" | "unknown";
  cloudStateLabel: string;
  syncConfigured: boolean;
  pendingCount: number;
  receiptCount: number;
  protectedAppCount: number;
};

// Legacy types preserved for backward compatibility during transition
export type AboutSection = {
  id: string;
  heading: string;
  body: string;
};

export type TrustCard = {
  title: string;
  description: string;
};

export type PathCard = {
  title: string;
  description: string;
  ctaLabel: string;
  ctaHref: string;
};

export type PartnerLevel = {
  name: string;
  description: string;
};

export type AffiliateTerms = {
  commissionRate: string;
  commissionDuration: string;
  cookieWindow: string;
  qualificationNote: string;
};
