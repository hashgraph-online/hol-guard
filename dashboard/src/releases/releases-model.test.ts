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
  contributorMonogram,
  mergeContributors,
  contributorTone,
  dedupeChanges,
  groupReleaseAssets,
  groupReleasesByTrain,
} from "./releases-model";
import type { ReleaseChange, ReleaseContributor, ReleaseIndex, ReleaseSummary } from "./releases-types";

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

// The range follows the page size hol.org answered with, not the one asked for.
{
  const clamped: ReleaseIndex = {
    kind: "index",
    page: 3,
    pageSize: 20,
    total: 2079,
    totalPages: 104,
    generatedAt: "2026-10-22T00:00:00Z",
    releases: Array.from({ length: 20 }, (_value, offset) =>
      summary({ slug: `v3-${offset}-1`, versionLabel: `3.${offset}.1` }),
    ),
  };
  assert.equal(pageRangeLabel(clamped), "Showing 41–60 of 2079 releases");
}

// A date Guard cannot parse is shown as published rather than "Invalid Date".
{
  assert.equal(formatReleaseDate("not-a-date"), "not-a-date");
  assert.notEqual(formatReleaseDate("2026-10-18T00:00:00Z"), "Invalid Date");
  assert.equal(channelLabel("preview"), "Preview");
}

// The feed tells one pull request three ways. Taken from a real alpha, whose
// 23 entries describe 11 merges: the generated lead, the classified change,
// and the raw merge commit behind it.
{
  const change = (over: Partial<ReleaseChange>): ReleaseChange => ({
    id: over.id ?? "c",
    kind: over.kind ?? "other",
    summary: over.summary ?? "",
    evidenceUrl: over.evidenceUrl ?? null,
  });
  const raw: ReleaseChange[] = [
    change({ id: "1", summary: "Documented change: Guard 3.53.0a3 retires the Python shim." }),
    change({
      id: "2",
      kind: "fixed",
      summary: "**runtime**: retire the Python data-flow projection shim (#5496)",
      evidenceUrl: "https://github.com/hashgraph-online/hol-guard/pull/5496",
    }),
    change({
      id: "3",
      summary: "Merged pull request #5496: refactor(runtime): retire the Python shim (#5496)",
      evidenceUrl: "https://github.com/hashgraph-online/hol-guard/pull/5496",
    }),
    change({ id: "4", kind: "security", summary: "Bound the release feed response (#5500)" }),
  ];
  const deduped = dedupeChanges(raw, true);
  assert.deepEqual(
    deduped.map((entry) => entry.id),
    ["2", "4"],
    "one entry per pull request, keeping the classified prose",
  );
  // The merge-commit restatement wins nothing even when it arrives first.
  assert.equal(dedupeChanges([raw[2], raw[1]], true)[0].id, "2");
  // Without notes the generated lead is the only prose there is, so it stays.
  assert.equal(dedupeChanges(raw, false).length, 3);
  // An entry naming no pull request cannot be folded into another.
  const loose = [change({ id: "a", summary: "Rebuilt the catalog" }), change({ id: "b", summary: "Rotated keys" })];
  assert.equal(dedupeChanges(loose, true).length, 2);
}

// Seventeen files for one alpha: the platform someone is on, then provenance.
{
  const asset = (name: string) => ({ name, url: `https://example.test/${name}` });
  const { groups, provenance } = groupReleaseAssets([
    asset("hol-guard-core-3.53.0a3-aarch64-apple-darwin"),
    asset("hol-guard-core-3.53.0a3-aarch64-apple-darwin.attested.json"),
    asset("hol-guard-core-3.53.0a3-x86_64-unknown-linux-gnu"),
    asset("hol_guard-3.53.0a3-py3-none-win_amd64.whl"),
    asset("hol_guard-3.53.0a3-py3-none-any.whl"),
    asset("hol-guard-v3.53.0a3.intoto.jsonl"),
    asset("something-else.bin"),
  ]);
  assert.deepEqual(
    groups.map((group) => [group.label, group.assets.length]),
    [
      ["macOS", 1],
      ["Linux", 1],
      ["Windows", 1],
      ["Any platform", 1],
      ["Other files", 1],
    ],
  );
  assert.equal(provenance.length, 2, "attestations are evidence, not downloads");
}

// The rail groups a page of versions by the train they belong to.
{
  const groups = groupReleasesByTrain([
    summary({ slug: "a", versionLabel: "3.53.1", train: "3.53" }),
    summary({ slug: "b", versionLabel: "3.53.0", train: "3.53" }),
    summary({ slug: "c", versionLabel: "3.52.0", train: "3.52" }),
  ]);
  assert.deepEqual(
    groups.map((group) => [group.train, group.releases.length]),
    [
      ["3.53", 2],
      ["3.52", 1],
    ],
  );
}

// Contributor chips are derived here rather than fetched from GitHub, so the
// screen stays on the device's own origin.
{
  const contributor = (over: Partial<ReleaseContributor>): ReleaseContributor =>
    ({
      creditId: "x",
      contributorType: "human",
      login: "zerocodefast",
      displayName: null,
      githubNumericId: 4211,
      roles: ["author"],
      verificationMethod: "pull-request-author",
      evidenceUrl: null,
      ...over,
    }) as ReleaseContributor;
  assert.equal(contributorMonogram(contributor({})), "ZE");
  assert.equal(contributorMonogram(contributor({ login: "a", displayName: null })), "A");
  // A login of nothing but punctuation still produces a chip.
  assert.equal(contributorMonogram(contributor({ login: "---" })), "?");
  // The same contributor always gets the same tone, across releases.
  assert.equal(contributorTone(contributor({})), contributorTone(contributor({})));
}

// One credit row per change folds into one person per release.
{
  const credit = (over: Partial<ReleaseContributor>): ReleaseContributor =>
    ({
      creditId: "c",
      contributorType: "human",
      login: "zerocodefast",
      displayName: null,
      githubNumericId: 4211,
      roles: ["implementation"],
      verificationMethod: "pull-request-author",
      evidenceUrl: null,
      ...over,
    }) as ReleaseContributor;

  const roster = mergeContributors([
    credit({ creditId: "1" }),
    credit({ creditId: "2", roles: ["implementation", "tests"] }),
    credit({ creditId: "3", roles: ["docs"] }),
    credit({ creditId: "4", login: "someone-else", githubNumericId: 99, roles: ["review"] }),
  ]);
  assert.equal(roster.length, 2);
  assert.equal(roster[0].login, "zerocodefast");
  assert.equal(roster[0].credits, 3);
  assert.deepEqual(roster[0].roles, ["docs", "implementation", "tests"]);
  assert.equal(roster[1].credits, 1);

  // The strongest proof a person has carries the chip.
  const promoted = mergeContributors([
    credit({ creditId: "1", verificationMethod: "verified-coauthor", evidenceUrl: null }),
    credit({ creditId: "2", evidenceUrl: "https://github.com/o/r/pull/5" }),
  ]);
  assert.equal(promoted[0].verificationMethod, "pull-request-author");
  assert.equal(promoted[0].evidenceUrl, "https://github.com/o/r/pull/5");
}

// Two pull requests that both cite the same issue are two changes: the key
// has to come from the pull request, not from the first number in the line.
{
  const change = (over: Partial<ReleaseChange>): ReleaseChange => ({
    id: over.id ?? "x",
    kind: over.kind ?? "other",
    summary: over.summary ?? "",
    evidenceUrl: over.evidenceUrl ?? null,
  });
  const deduped = dedupeChanges(
    [
      change({ id: "1", summary: "fix(native): close #5400 for the resident (#5501)" }),
      change({ id: "2", summary: "fix(dashboard): close #5400 for the panel (#5502)" }),
    ],
    true,
  );
  assert.equal(deduped.length, 2, "distinct pull requests citing one issue stay distinct");
  // The evidence URL outranks any number in the prose.
  const byUrl = dedupeChanges(
    [
      change({ id: "3", summary: "Rework #5400 (#5501)", evidenceUrl: "https://github.com/o/r/pull/5600" }),
      change({ id: "4", summary: "Rework again (#5502)", evidenceUrl: "https://github.com/o/r/pull/5600" }),
    ],
    true,
  );
  assert.equal(byUrl.length, 1);
  // A merge commit names its pull request first, so it still folds into the
  // classified entry even when the title cites an issue after it.
  const merged = dedupeChanges(
    [
      change({ id: "5", kind: "fixed", summary: "**runtime**: fix the crash from #12 (#5496)" }),
      change({ id: "6", summary: "Merged pull request #5496: fix the crash from #12" }),
    ],
    true,
  );
  assert.deepEqual(
    merged.map((entry) => entry.id),
    ["5"],
    "a merge restatement keys on its own pull request, not the issue it cites",
  );
}

// A roster row that resolved the person outranks one that did not: the chip
// must not keep an unresolved type or a missing link when a sibling has them.
{
  const credit = (over: Partial<ReleaseContributor>): ReleaseContributor =>
    ({
      creditId: "c",
      type: "unresolved",
      login: null,
      githubNumericId: 7788,
      roles: ["implementation"],
      verificationMethod: "verified-coauthor",
      evidenceUrl: null,
      ...over,
    }) as ReleaseContributor;

  const merged = mergeContributors([
    credit({ creditId: "1" }),
    credit({ creditId: "2", type: "human", login: "kantorcodes", evidenceUrl: "https://github.com/o/r/pull/9" }),
  ]);
  assert.equal(merged[0].login, "kantorcodes");
  assert.equal(merged[0].type, "human");
  assert.equal(merged[0].evidenceUrl, "https://github.com/o/r/pull/9");

  // Stronger proof without a link must not cost the contributor the link.
  const kept = mergeContributors([
    credit({ creditId: "1", type: "human", login: "kantorcodes", evidenceUrl: "https://github.com/o/r/pull/9" }),
    credit({ creditId: "2", type: "human", login: "kantorcodes", verificationMethod: "pull-request-author" }),
  ]);
  assert.equal(kept[0].evidenceUrl, "https://github.com/o/r/pull/9");
}

console.log("releases-model.test.ts passed");
