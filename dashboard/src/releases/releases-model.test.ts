import assert from "node:assert/strict";

import {
  channelLabel,
  comparisonLine,
  contributorName,
  coverageNote,
  dismissWhatsNew,
  failureCopy,
  formatReleaseDate,
  groupChangesByKind,
  hasNextPage,
  hasPreviousPage,
  installedNote,
  installedRelease,
  isRetryable,
  isWhatsNewDismissed,
  openingSlug,
  normalizeVersionLabel,
  pageRangeLabel,
  verificationLabel,
  whatsNewStorageKey,
} from "./releases-model";
import type { ReleaseChange, ReleaseIndex, ReleaseSummary } from "./releases-types";

function installLocalStorage(): Map<string, string> {
  const store = new Map<string, string>();
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      localStorage: {
        getItem: (key: string) => store.get(key) ?? null,
        setItem: (key: string, value: string) => void store.set(key, value),
      },
    },
  });
  return store;
}

function installThrowingLocalStorage(): void {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      get localStorage(): never {
        throw new Error("storage blocked");
      },
    },
  });
}

const coverage = {
  attributionState: "complete" as const,
  historyCoverage: "complete" as const,
  verifiedAt: "2026-10-01T00:00:00Z",
};

function summary(overrides: Partial<ReleaseSummary> = {}): ReleaseSummary {
  return {
    slug: "v3-53-0",
    rawTag: "v3.53.0",
    channel: "stable",
    train: "3.53",
    versionLabel: "3.53.0",
    title: "Guard 3.53.0",
    publishedAt: "2026-10-18T00:00:00Z",
    path: "/guard/releases/v3-53-0",
    isRecommended: true,
    coverage,
    ...overrides,
  };
}

function change(kind: ReleaseChange["kind"], id: string): ReleaseChange {
  return { id, kind, summary: `${kind} ${id}`, evidenceUrl: null };
}

// Security has to lead a change list; a reader scanning for what was patched
// must not have to read past a cosmetic fix to find it.
{
  const sections = groupChangesByKind([
    change("other", "d"),
    change("fixed", "c"),
    change("added", "b"),
    change("security", "a"),
  ]);
  assert.deepEqual(
    sections.map((section) => section.kind),
    ["security", "added", "fixed", "other"],
  );
  assert.equal(sections[0].label, "Security");
  assert.equal(groupChangesByKind([]).length, 0, "no empty sections are rendered");
}

// The installed version arrives from Guard with or without a leading v.
{
  const releases = [summary(), summary({ slug: "v3-52-0", versionLabel: "3.52.0" })];
  assert.equal(normalizeVersionLabel("v3.53.0"), "3.53.0");
  assert.equal(installedRelease(releases, "v3.53.0")?.slug, "v3-53-0");
  assert.equal(installedRelease(releases, "3.52.0")?.slug, "v3-52-0");
  assert.equal(installedRelease(releases, null), null);
  assert.equal(installedRelease(releases, "  "), null);
  // An alpha that the archive has not published yet must not match a stable
  // release; the screen says nothing rather than pointing at the wrong one.
  assert.equal(installedRelease(releases, "3.54.0a1"), null);
}

// Dismissal is per version, so the next release raises the card again.
{
  const store = installLocalStorage();
  assert.equal(whatsNewStorageKey("v3.53.0"), "guard.releases.whats-new.3.53.0");
  assert.equal(isWhatsNewDismissed("3.53.0"), false);
  dismissWhatsNew("3.53.0");
  assert.equal(store.get("guard.releases.whats-new.3.53.0"), "dismissed");
  assert.equal(isWhatsNewDismissed("3.53.0"), true);
  assert.equal(isWhatsNewDismissed("3.54.0"), false, "a newer release is not pre-dismissed");
}

// Blocked storage must not throw through a render.
{
  installThrowingLocalStorage();
  assert.equal(isWhatsNewDismissed("3.53.0"), false);
  assert.doesNotThrow(() => dismissWhatsNew("3.53.0"));
}

// A device can be many releases behind, and the archive is paged. Saying the
// installed version is not on this page beats a page that marks nothing.
{
  const releases = [summary(), summary({ slug: "v3-52-0", versionLabel: "3.52.0" })];
  assert.equal(installedNote(releases, "v3.53.0"), " This device is running 3.53.0.");
  assert.match(installedNote(releases, "3.0.57"), /not on this page of the archive/);
  assert.equal(installedNote(releases, null), "");
  assert.equal(installedNote(releases, "  "), "");
}

// Coverage is published, not implied.
{
  assert.equal(coverageNote(coverage), null);
  assert.match(
    coverageNote({ ...coverage, attributionState: "in-progress" }) ?? "",
    /still being verified/,
  );
  assert.match(coverageNote({ ...coverage, attributionState: "unknown" }) ?? "", /not been verified/);
  assert.match(
    coverageNote({ ...coverage, historyCoverage: "partial" }) ?? "",
    /does not cover every release/,
  );
}

// A change list is only a comparison when the predecessor is verified.
{
  assert.equal(
    comparisonLine({ available: true, predecessorSlug: "v3-52-0", predecessorRawTag: "v3.52.0" }),
    "Changes since v3.52.0.",
  );
  assert.match(comparisonLine({ available: false, reason: "first-release" }), /first published release/);
  assert.match(
    comparisonLine({ available: false, reason: "unverified-predecessor" }),
    /not a verified comparison/,
  );
}

// An unresolved account keeps its verified numeric identity rather than a guess.
{
  const base = {
    creditId: "credit-1",
    githubNumericId: 4242,
    type: "human" as const,
    roles: ["Author"],
    verificationMethod: "pull-request-author" as const,
    evidenceUrl: null,
  };
  assert.equal(contributorName({ ...base, login: "kantorcodes" }), "kantorcodes");
  assert.equal(contributorName({ ...base, login: null }), "GitHub user 4242");
  assert.equal(verificationLabel("verified-coauthor"), "Verified co-author trailer");
}

// Failure copy names what failed and tells the reader their device is fine.
{
  assert.match(failureCopy("offline").body, /connection/);
  assert.match(failureCopy("unavailable").body, /Nothing on this device is affected/);
  assert.match(failureCopy("unsupported").body, /native runtime/);
  assert.match(failureCopy("not-found").title, /not published/);
  // The kill switch is this device's own doing, so the copy must not blame
  // hol.org for an archive Guard was told not to read.
  assert.match(failureCopy("disabled").title, /turned off on this device/);
  assert.match(failureCopy("disabled").body, /Nothing on hol.org is affected/);
}

// A retry button is only offered where pressing it could change the answer.
{
  assert.equal(isRetryable("unavailable"), true);
  assert.equal(isRetryable("offline"), true);
  assert.equal(isRetryable("disabled"), false, "the switch stays off however often it is pressed");
  assert.equal(isRetryable("unsupported"), false);
  assert.equal(isRetryable("not-found"), false);
}

// The archive and the installed version are separate reads. When the installed
// one lands second, the screen moves to it rather than leaving the reader on
// the newest release they never asked for — unless they opened one themselves.
{
  const releases = [summary(), summary({ slug: "v3-52-0", versionLabel: "3.52.0" })];
  assert.equal(openingSlug(releases, null, null, false), "v3-53-0", "the newest opens first");
  assert.equal(
    openingSlug(releases, "3.52.0", "v3-53-0", false),
    "v3-52-0",
    "a late installed version takes over from the default",
  );
  assert.equal(
    openingSlug(releases, "3.52.0", "v3-53-0", true),
    "v3-53-0",
    "the reader's own choice outranks the installed version",
  );
  // A page that does not hold the chosen release opens its own first entry.
  assert.equal(openingSlug(releases, null, "v2-0-0", true), "v3-53-0");
  assert.equal(openingSlug([], null, null, false), null);
}

// Paging controls say what they page.
{
  const index: ReleaseIndex = {
    kind: "index",
    page: 2,
    pageSize: 25,
    total: 61,
    totalPages: 3,
    generatedAt: "2026-10-21T00:00:00Z",
    releases: Array.from({ length: 25 }, (_value, offset) =>
      summary({ slug: `v3-${offset}-0`, versionLabel: `3.${offset}.0` }),
    ),
  };
  assert.equal(pageRangeLabel(index), "Showing 26–50 of 61 releases");
  assert.equal(hasNextPage(index), true);
  assert.equal(hasPreviousPage(index), true);
  assert.equal(hasNextPage({ ...index, page: 3 }), false);
  assert.equal(hasPreviousPage({ ...index, page: 1 }), false);
  assert.equal(pageRangeLabel({ ...index, total: 0, releases: [] }), "No published releases");
  assert.equal(
    pageRangeLabel({ ...index, page: 1, total: 1, releases: [summary()] }),
    "Showing 1–1 of 1 release",
  );
}

// A date Guard cannot parse is shown as published rather than "Invalid Date".
{
  assert.equal(formatReleaseDate("not-a-date"), "not-a-date");
  assert.notEqual(formatReleaseDate("2026-10-18T00:00:00Z"), "Invalid Date");
  assert.equal(channelLabel("preview"), "Preview");
}

console.log("releases-model.test.ts passed");
