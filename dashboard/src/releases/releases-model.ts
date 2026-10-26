import type {
  ReleaseAsset,
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

/**
 * One tone per change kind, so "security" reads as security wherever it
 * appears instead of being another bold heading. The classes come from the
 * dashboard's own palette; nothing here introduces a colour.
 */
const CHANGE_TONES: Record<ReleaseChangeKind, string> = {
  security: "bg-brand-purple/10 text-brand-purple",
  added: "bg-brand-green-bg text-brand-green-text",
  changed: "bg-brand-blue/10 text-brand-blue",
  fixed: "bg-brand-attention-bg text-brand-attention",
  removed: "bg-brand-dark/[0.07] text-brand-dark/75",
  other: "bg-brand-dark/[0.07] text-brand-dark/75",
};

export function changeKindTone(kind: ReleaseChangeKind): string {
  return CHANGE_TONES[kind];
}

/** The one-word noun each kind counts in, for the header's tally. */
const CHANGE_NOUNS: Record<ReleaseChangeKind, string> = {
  security: "security",
  added: "added",
  changed: "changed",
  fixed: "fixed",
  removed: "removed",
  other: "other",
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

/** "1 security \u00b7 3 fixed \u00b7 2 added": what this release holds, in the order the
 * sections themselves run, so the reader can tell at a glance whether it is
 * worth opening before reading a word of it. */
export function changeCountLabel(sections: readonly ReleaseChangeSection[]): string {
  return sections
    .map((section) => `${section.changes.length} ${CHANGE_NOUNS[section.kind]}`)
    .join(" \u00b7 ");
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

/**
 * Where this device stands in the published history.
 *
 * This is the one fact the archive exists to answer and the hardest one to
 * read off a list of version numbers, so it is computed once, here, and said
 * outright at the top of the screen.
 *
 * The archive is paged, which bounds what can honestly be claimed. A release
 * the page in hand does not hold is reported as exactly that rather than
 * silently marking nothing as installed, and the newest published release is
 * only named from the first page, where it really is the first row.
 */
export type InstalledStanding =
  | { kind: "unknown" }
  | { kind: "off-page"; label: string }
  | { kind: "current"; release: ReleaseSummary }
  | { kind: "behind"; release: ReleaseSummary; behind: number; newest: ReleaseSummary | null };

export function installedStanding(
  index: ReleaseIndex,
  installedVersion: string | null | undefined,
): InstalledStanding {
  const label = normalizeVersionLabel((installedVersion ?? "").trim());
  if (!label) return { kind: "unknown" };
  const position = index.releases.findIndex(
    (release) => normalizeVersionLabel(release.versionLabel) === label,
  );
  if (position === -1) return { kind: "off-page", label };
  const release = index.releases[position];
  // Everything above this row on this page, plus every page before it. The
  // daemon echoes the page size hol.org actually served, so this counts
  // published releases rather than the page size the screen asked for.
  const behind = (index.page - 1) * index.pageSize + position;
  if (behind === 0) return { kind: "current", release };
  // The screen offers to open this release, so it has to be one this device
  // can actually move to. A device on previews takes either channel; a stable
  // install is not sent to read a preview's notes. Only page 1 holds the top
  // of the history, so only page 1 can name the newest release there is; when
  // nothing above this row is on offer, there is none to name.
  const onOffer = (candidate: ReleaseSummary): boolean =>
    release.channel === "preview" || candidate.channel === "stable";
  const newest =
    index.page === 1 ? (index.releases.slice(0, position).find(onOffer) ?? null) : null;
  return { kind: "behind", release, behind, newest };
}

export type StandingCopy = { title: string; body: string };

/** What the status band says, as prose, so the wording can be read back in a
 * test without rendering the band. */
export function standingCopy(standing: InstalledStanding): StandingCopy {
  if (standing.kind === "unknown") {
    return {
      title: "Guard's published releases",
      body: "Every published version, what it changed, and who is verified to have changed it.",
    };
  }
  if (standing.kind === "off-page") {
    return {
      title: standing.label,
      body: "This device's version is not on this page of the archive.",
    };
  }
  if (standing.kind === "current") {
    return {
      title: normalizeVersionLabel(standing.release.versionLabel),
      body: `Running here, and the newest published release. Released ${formatReleaseDate(standing.release.publishedAt)}.`,
    };
  }
  const count =
    standing.behind === 1 ? "One newer release has" : `${standing.behind} newer releases have`;
  // The count covers every channel, because every one of them was published;
  // the release named is the newest one this device is actually offered.
  const newest = standing.newest
    ? ` The newest ${channelLabel(standing.newest.channel).toLowerCase()} release is ${normalizeVersionLabel(standing.newest.versionLabel)}.`
    : "";
  return {
    title: normalizeVersionLabel(standing.release.versionLabel),
    body: `Running here. ${count} been published since.${newest}`,
  };
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

/**
 * The feed describes one pull request up to three times: once in the authored
 * notes, once as a classified change, and once more as the raw merge commit
 * ("Merged pull request #5496: ..."). Reading the same release three times
 * over is the loudest problem on this screen, so entries that point at the
 * same pull request collapse to the one that carries a classification.
 */
const PULL_REQUEST_PATTERN = /#(\d{1,7})\b/g;
const TRAILING_PULL_REQUEST = /\(#(\d{1,7})\)\s*$/;
const DOCUMENTED_PREFIX = /^documented change:/i;
const MERGE_PREFIX = /^merged pull request\b/i;
const MERGE_PULL_REQUEST = /^merged pull request\s+#(\d{1,7})\b/i;

function pullRequestKey(change: ReleaseChange): string | null {
  const fromEvidence = change.evidenceUrl?.match(/\/pull\/(\d{1,7})(?:\D|$)/);
  if (fromEvidence) return fromEvidence[1];
  const summary = change.summary.trim();
  // A merge commit names its pull request first and anything it cites after,
  // so the leading number is the one that identifies the change.
  const merge = MERGE_PULL_REQUEST.exec(summary);
  if (merge) return merge[1];
  // A squash-merge title carries the pull request last — "Fix the crash from
  // #12 (#5500)" — while anything earlier is an issue it mentions. Keying on
  // the first number would fold two changes that cite the same issue into one.
  const trailing = TRAILING_PULL_REQUEST.exec(summary);
  if (trailing) return trailing[1];
  const numbers = [...summary.matchAll(PULL_REQUEST_PATTERN)];
  return numbers.length > 0 ? numbers[numbers.length - 1][1] : null;
}

export function dedupeChanges(
  changes: readonly ReleaseChange[],
  hasSourceNotes: boolean,
): ReleaseChange[] {
  const byPullRequest = new Map<string, number>();
  const kept: ReleaseChange[] = [];
  for (const change of changes) {
    const summary = change.summary.trim();
    // The documented-change entry restates the notes verbatim; it is only
    // worth keeping when there are no notes to restate.
    if (hasSourceNotes && DOCUMENTED_PREFIX.test(summary)) continue;
    const key = pullRequestKey(change);
    if (key === null) {
      kept.push(change);
      continue;
    }
    const seen = byPullRequest.get(key);
    if (seen === undefined) {
      byPullRequest.set(key, kept.length);
      kept.push(change);
      continue;
    }
    // Same pull request twice: the merge-commit restatement loses to anything
    // that was actually classified, and to anything that reads like prose.
    const incumbent = kept[seen];
    const incumbentIsMerge = MERGE_PREFIX.test(incumbent.summary.trim());
    const candidateIsMerge = MERGE_PREFIX.test(summary);
    if (incumbentIsMerge && !candidateIsMerge) kept[seen] = change;
    else if (incumbent.kind === "other" && change.kind !== "other" && !candidateIsMerge) {
      kept[seen] = change;
    }
  }
  return kept;
}

/**
 * A release carries every build for every platform plus its provenance
 * sidecars — seventeen files for a recent alpha. Nobody wants seventeen
 * buttons; they want the one for the machine they are on.
 */
export type ReleaseAssetGroup = { id: string; label: string; assets: ReleaseAsset[] };

const ASSET_GROUPS: { id: string; label: string; test: (name: string) => boolean }[] = [
  { id: "macos", label: "macOS", test: (n) => n.includes("apple-darwin") || n.includes("macosx") },
  {
    id: "linux",
    label: "Linux",
    test: (n) => n.includes("linux"),
  },
  { id: "windows", label: "Windows", test: (n) => n.includes("win_") || n.includes("windows") },
  { id: "any", label: "Any platform", test: (n) => n.includes("py3-none-any") || n.endsWith(".tar.gz") },
];

/** Signed attestations are evidence, not downloads; they belong apart. */
function isProvenance(name: string): boolean {
  return name.includes(".attested.") || name.includes(".intoto.") || name.endsWith(".sigstore");
}

export function groupReleaseAssets(assets: readonly ReleaseAsset[]): {
  groups: ReleaseAssetGroup[];
  provenance: ReleaseAsset[];
} {
  const groups = new Map<string, ReleaseAssetGroup>();
  const provenance: ReleaseAsset[] = [];
  const other: ReleaseAsset[] = [];
  for (const asset of assets) {
    const name = asset.name.toLowerCase();
    if (isProvenance(name)) {
      provenance.push(asset);
      continue;
    }
    const match = ASSET_GROUPS.find((group) => group.test(name));
    if (match === undefined) {
      other.push(asset);
      continue;
    }
    const existing = groups.get(match.id);
    if (existing) existing.assets.push(asset);
    else groups.set(match.id, { id: match.id, label: match.label, assets: [asset] });
  }
  const ordered = ASSET_GROUPS.map((group) => groups.get(group.id)).filter(
    (group): group is ReleaseAssetGroup => group !== undefined,
  );
  if (other.length > 0) ordered.push({ id: "other", label: "Other files", assets: other });
  return { groups: ordered, provenance };
}

/**
 * Contributor avatars would be fetched from GitHub, which would tell GitHub
 * which release each reader opened. The monogram is derived from the login
 * instead, so the screen stays on the device's own origin.
 */
const MONOGRAM_TONES = [
  "bg-brand-blue/10 text-brand-blue",
  "bg-brand-green-bg text-brand-green-text",
  "bg-brand-purple/10 text-brand-purple",
  "bg-brand-attention-bg text-brand-attention-text",
  "bg-brand-dark/[0.07] text-brand-dark/75",
];

export function contributorMonogram(contributor: ReleaseContributor): string {
  const name = contributorName(contributor).replace(/^@/, "");
  const letters = name.match(/\p{Letter}|\p{Number}/gu) ?? [];
  return (letters.slice(0, 2).join("") || "?").toUpperCase();
}

export function contributorTone(contributor: ReleaseContributor): string {
  const seed = contributor.githubNumericId ?? 0;
  const login = contributor.login ?? "";
  let hash = Math.abs(seed);
  for (const char of login) hash = (hash * 31 + char.codePointAt(0)!) >>> 0;
  return MONOGRAM_TONES[hash % MONOGRAM_TONES.length];
}

/**
 * A page of the archive is twenty versions of the same few trains. Grouping
 * them gives the rail a spine to scroll against, and keeps the feed's own
 * newest-first order inside each run.
 */
export type ReleaseTrainGroup = { train: string; releases: ReleaseSummary[] };

export function groupReleasesByTrain(releases: readonly ReleaseSummary[]): ReleaseTrainGroup[] {
  const groups: ReleaseTrainGroup[] = [];
  for (const release of releases) {
    const current = groups[groups.length - 1];
    if (current && current.train === release.train) current.releases.push(release);
    else groups.push({ train: release.train, releases: [release] });
  }
  return groups;
}

/**
 * One person credited once. The feed carries a credit row per change, so a
 * release where a single maintainer merged eleven pull requests arrives as
 * eleven identical contributors. Fold them by GitHub identity, union the
 * roles, and keep the count so the screen can still say how much they did.
 */
export type MergedContributor = ReleaseContributor & { credits: number };

export function mergeContributors(roster: ReleaseContributor[]): MergedContributor[] {
  const byIdentity = new Map<string, MergedContributor>();
  for (const contributor of roster) {
    const key = contributor.githubNumericId
      ? `id:${contributor.githubNumericId}`
      : `login:${contributor.login ?? contributor.creditId}`;
    const seen = byIdentity.get(key);
    if (!seen) {
      byIdentity.set(key, { ...contributor, roles: [...contributor.roles], credits: 1 });
      continue;
    }
    seen.credits += 1;
    for (const role of contributor.roles) {
      if (!seen.roles.includes(role)) seen.roles.push(role);
    }
    // Direct-commit and co-author evidence is weaker than a merged pull
    // request, so the strongest proof this person has wins the chip.
    if (seen.verificationMethod !== "pull-request-author" && contributor.verificationMethod === "pull-request-author") {
      seen.verificationMethod = contributor.verificationMethod;
      // Stronger proof only replaces the link when it brings one: a credit row
      // without a URL must not cost the contributor the link they had.
      if (contributor.evidenceUrl) seen.evidenceUrl = contributor.evidenceUrl;
    }
    // Rows for one numeric identity can arrive before the feed resolved the
    // login, so take the name as soon as any row carries it rather than
    // leaving the chip on its "GitHub user 1234" fallback.
    if (!seen.login && contributor.login) {
      seen.login = contributor.login;
      if (seen.type === "unresolved") seen.type = contributor.type;
    }
    if (seen.type === "unresolved" && contributor.type !== "unresolved") seen.type = contributor.type;
    if (!seen.evidenceUrl && contributor.evidenceUrl) seen.evidenceUrl = contributor.evidenceUrl;
  }
  for (const merged of byIdentity.values()) merged.roles.sort();
  return [...byIdentity.values()].sort((a, b) => b.credits - a.credits || contributorName(a).localeCompare(contributorName(b)));
}
