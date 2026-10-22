import type {
  ReleaseChange,
  ReleaseChangeKind,
  ReleaseComparison,
  ReleaseContributor,
  ReleaseCoverage,
  ReleaseFeedFailure,
  ReleaseIndex,
  ReleaseSummary,
  ReleaseVerificationMethod,
} from "./releases-types";

/**
 * Presentation decisions for the release archive. Everything here is pure so
 * the wording the screen shows — above all the honesty lines about partial
 * attribution — can be tested without rendering.
 */

const CHANGE_ORDER: readonly ReleaseChangeKind[] = [
  "security",
  "added",
  "changed",
  "fixed",
  "removed",
  "other",
];

const CHANGE_LABELS: Record<ReleaseChangeKind, string> = {
  security: "Security",
  added: "Added",
  changed: "Changed",
  fixed: "Fixed",
  removed: "Removed",
  other: "Also in this release",
};

export type ReleaseChangeSection = {
  kind: ReleaseChangeKind;
  label: string;
  changes: ReleaseChange[];
};

/** Group a release's changes into the sections the detail view renders, in a
 * fixed order so security never lands below a cosmetic fix. */
export function groupChangesByKind(changes: readonly ReleaseChange[]): ReleaseChangeSection[] {
  return CHANGE_ORDER.map((kind) => ({
    kind,
    label: CHANGE_LABELS[kind],
    changes: changes.filter((change) => change.kind === kind),
  })).filter((section) => section.changes.length > 0);
}

/** Strip the `v` an installed version may or may not carry. */
export function normalizeVersionLabel(version: string): string {
  const trimmed = version.trim();
  return trimmed.startsWith("v") ? trimmed.slice(1) : trimmed;
}

/**
 * The release this device is running, if the archive page in hand contains it.
 * An installed build newer than anything published — an alpha, or a release
 * that has not reached the archive yet — simply has no match, and the screen
 * says so rather than pointing at the wrong version.
 */
export function installedRelease(
  releases: readonly ReleaseSummary[],
  installedVersion: string | null | undefined,
): ReleaseSummary | null {
  if (!installedVersion) return null;
  const wanted = normalizeVersionLabel(installedVersion);
  if (!wanted) return null;
  return releases.find((release) => normalizeVersionLabel(release.versionLabel) === wanted) ?? null;
}

const WHATS_NEW_STORAGE_PREFIX = "guard.releases.whats-new.";

/** Dismissal is keyed by version, so the next release raises the card again. */
export function whatsNewStorageKey(versionLabel: string): string {
  return `${WHATS_NEW_STORAGE_PREFIX}${normalizeVersionLabel(versionLabel)}`;
}

export function isWhatsNewDismissed(versionLabel: string): boolean {
  try {
    return window.localStorage.getItem(whatsNewStorageKey(versionLabel)) === "dismissed";
  } catch {
    // Storage can be blocked; an undismissable card beats a thrown render.
    return false;
  }
}

export function dismissWhatsNew(versionLabel: string): void {
  try {
    window.localStorage.setItem(whatsNewStorageKey(versionLabel), "dismissed");
  } catch {
    // Nothing to do: the card simply returns on the next visit.
  }
}

export function channelLabel(channel: "stable" | "preview"): string {
  return channel === "stable" ? "Stable" : "Preview";
}

/** Dates are rendered in the reader's locale; an unparseable one falls back to
 * the raw instant rather than printing "Invalid Date". */
export function formatReleaseDate(instant: string): string {
  const parsed = new Date(instant);
  if (Number.isNaN(parsed.getTime())) {
    return instant;
  }
  return parsed.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
}

/**
 * What the archive can and cannot claim about this release. Guard publishes
 * the gaps instead of implying a complete record.
 */
export function coverageNote(coverage: ReleaseCoverage): string | null {
  if (coverage.attributionState === "complete" && coverage.historyCoverage === "complete") {
    return null;
  }
  if (coverage.attributionState === "unknown") {
    return "Contributor attribution for this release has not been verified yet, so the list below may be incomplete.";
  }
  if (coverage.attributionState === "in-progress") {
    return "Contributor attribution for this release is still being verified; names may still be added.";
  }
  return "Guard's published history does not cover every release before this one.";
}

export function comparisonLine(comparison: ReleaseComparison): string {
  if (comparison.available) {
    return `Changes since ${comparison.predecessorRawTag}.`;
  }
  if (comparison.reason === "first-release") {
    return "The first published release, so there is nothing to compare it against.";
  }
  return "The release before this one has not been verified, so the change list is not a verified comparison.";
}

/** A contributor's display name. An unresolved account still has a verified
 * numeric identity, which is what Guard shows rather than guessing a name. */
export function contributorName(contributor: ReleaseContributor): string {
  if (contributor.login) return contributor.login;
  return `GitHub user ${contributor.githubNumericId}`;
}

const VERIFICATION_LABELS: Record<ReleaseVerificationMethod, string> = {
  "pull-request-author": "Verified from the merged pull request",
  "verified-direct-commit-author": "Verified from a signed commit",
  "verified-coauthor": "Verified co-author trailer",
};

export function verificationLabel(method: ReleaseVerificationMethod): string {
  return VERIFICATION_LABELS[method];
}

/** What the screen says about the version this device runs.
 *
 * The archive is paged and a device can be many releases behind, so the
 * installed release is not always on the page in front of the reader. Saying
 * so beats a page that silently marks nothing as installed. */
export function installedNote(
  releases: ReleaseSummary[],
  installedVersion: string | null | undefined,
): string {
  const label = normalizeVersionLabel((installedVersion ?? "").trim());
  if (!label) return "";
  if (installedRelease(releases, installedVersion)) return ` This device is running ${label}.`;
  return ` This device is running ${label}, which is not on this page of the archive.`;
}

export type ReleaseFailureCopy = { title: string; body: string };

const FAILURE_COPY: Record<ReleaseFeedFailure, ReleaseFailureCopy> = {
  offline: {
    title: "Guard could not reach the release archive",
    body: "The archive is published by hol.org and read through Guard on this device. Check this device's connection and try again.",
  },
  unavailable: {
    title: "The release archive did not answer",
    body: "hol.org could not serve the archive just now. Nothing on this device is affected; try again in a few minutes.",
  },
  "not-found": {
    title: "That release is not published",
    body: "Guard only shows releases that have been published and verified. Pick another version from the list.",
  },
  unsupported: {
    title: "This Guard build cannot read the archive",
    body: "The release archive needs Guard's native runtime. Update Guard to see release history here.",
  },
  disabled: {
    title: "Release history is turned off on this device",
    body: "Guard is set to skip the release archive (HOL_GUARD_RELEASE_FEED=off). Nothing on hol.org is affected; clear that setting and restart Guard to read release history here.",
  },
};

export function failureCopy(failure: ReleaseFeedFailure): ReleaseFailureCopy {
  return FAILURE_COPY[failure];
}

/** Only a failure that could clear on its own is worth a retry button: an old
 * build and a switched-off archive both stay failed however often the reader
 * presses it, and a release that was never published stays unpublished. */
export function isRetryable(failure: ReleaseFeedFailure): boolean {
  return failure === "unavailable" || failure === "offline";
}

/** Which release the detail pane should open.
 *
 * The archive and the installed version are two separate reads, and the
 * installed one often lands second. Until the reader opens a release
 * themselves, the screen follows the installed version when the page holds it
 * and the newest release otherwise, so a cold visit never settles on the wrong
 * release just because Guard answered in that order. */
export function openingSlug(
  releases: ReleaseSummary[],
  installedVersion: string | null | undefined,
  current: string | null,
  readerChose: boolean,
): string | null {
  const held = current !== null && releases.some((release) => release.slug === current);
  if (held && readerChose) return current;
  return installedRelease(releases, installedVersion)?.slug ?? releases[0]?.slug ?? null;
}

export function hasNextPage(index: ReleaseIndex): boolean {
  return index.page < index.totalPages;
}

export function hasPreviousPage(index: ReleaseIndex): boolean {
  return index.page > 1;
}

/** "Showing 1–25 of 61 releases", so the page controls say what they page. */
export function pageRangeLabel(index: ReleaseIndex): string {
  if (index.total === 0) return "No published releases";
  const first = (index.page - 1) * index.pageSize + 1;
  const last = Math.min(index.total, first + index.releases.length - 1);
  return `Showing ${first}–${last} of ${index.total} ${index.total === 1 ? "release" : "releases"}`;
}
