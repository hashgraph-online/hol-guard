/**
 * The release archive as the Guard daemon serves it.
 *
 * These types mirror the native projection in `guard-runtime`'s
 * `release_feed_op`, which is the only thing that ever reads hol.org's bytes.
 * Every field here has already been bounded, range-checked and stripped of
 * markup by that op, so the dashboard renders it without re-validating shapes.
 */

export type ReleaseChannel = "stable" | "preview";

export type ReleaseAttributionState = "complete" | "in-progress" | "unknown";
export type ReleaseHistoryCoverage = "complete" | "partial";

export type ReleaseCoverage = {
  attributionState: ReleaseAttributionState;
  historyCoverage: ReleaseHistoryCoverage;
  verifiedAt: string | null;
};

export type ReleaseIdentity = {
  slug: string;
  rawTag: string;
  channel: ReleaseChannel;
  train: string;
  versionLabel: string;
  title: string;
  publishedAt: string;
  coverage: ReleaseCoverage;
};

export type ReleaseSummary = ReleaseIdentity & {
  path: string;
  isRecommended: boolean;
};

export type ReleaseIndex = {
  kind: "index";
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  generatedAt: string;
  releases: ReleaseSummary[];
};

export type ReleaseChangeKind = "added" | "changed" | "fixed" | "security" | "removed" | "other";

export type ReleaseChange = {
  id: string;
  kind: ReleaseChangeKind;
  summary: string;
  evidenceUrl: string | null;
};

export type ReleaseContributorType = "human" | "organization" | "automation" | "unresolved";

export type ReleaseVerificationMethod =
  | "pull-request-author"
  | "verified-direct-commit-author"
  | "verified-coauthor";

export type ReleaseContributor = {
  creditId: string;
  githubNumericId: number;
  login: string | null;
  type: ReleaseContributorType;
  roles: string[];
  verificationMethod: ReleaseVerificationMethod;
  evidenceUrl: string | null;
};

export type ReleaseAsset = {
  name: string;
  url: string;
};

export type ReleaseComparison =
  | { available: true; predecessorSlug: string; predecessorRawTag: string }
  | { available: false; reason: "unverified-predecessor" | "first-release" };

export type ReleaseSourceNotes = {
  scope: "exact_release" | "train_overview";
  text: string;
} | null;

export type ReleaseDetail = ReleaseIdentity & {
  kind: "detail";
  summary: string;
  comparison: ReleaseComparison;
  changes: ReleaseChange[];
  roster: ReleaseContributor[];
  assets: ReleaseAsset[];
  sourceNotes: ReleaseSourceNotes;
};

/**
 * Why a release read could not be answered. The daemon distinguishes an
 * upstream problem from a local one, and the screen says which it was rather
 * than showing one blank state for everything.
 */
export type ReleaseFeedFailure =
  | "unavailable"
  | "offline"
  | "not-found"
  | "unsupported"
  | "disabled";
