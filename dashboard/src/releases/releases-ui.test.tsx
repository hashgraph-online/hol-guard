import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { resolveView, viewTitle } from "../app";
import { SHELL_NAV_ITEMS, canonicalNavigationView, navigationItemForView } from "../shell-navigation-model";
import { ReleaseArchiveList } from "./components/release-archive-list";
import { ReleaseDetailPanel } from "./components/release-detail-panel";
import { WhatsNewCard } from "./components/whats-new-card";
import type { ReleaseDetail, ReleaseIndex, ReleaseSummary } from "./releases-types";

const coverage = {
  attributionState: "complete" as const,
  historyCoverage: "complete" as const,
  verifiedAt: "2026-10-01T00:00:00Z",
};

const installed: ReleaseSummary = {
  slug: "v3-53-0",
  rawTag: "v3.53.0",
  channel: "stable",
  train: "3.53",
  versionLabel: "3.53.0",
  title: "Extensions move to the primary sidebar",
  publishedAt: "2026-10-18T00:00:00Z",
  path: "/guard/releases/v3-53-0",
  isRecommended: true,
  coverage,
};

const older: ReleaseSummary = {
  ...installed,
  slug: "v3-52-0",
  rawTag: "v3.52.0",
  versionLabel: "3.52.0",
  title: "Windows daemon bootstrap repair",
  channel: "preview",
  publishedAt: "2026-10-11T00:00:00Z",
  path: "/guard/releases/v3-52-0",
  isRecommended: false,
};

const index: ReleaseIndex = {
  kind: "index",
  page: 1,
  pageSize: 25,
  total: 2,
  totalPages: 1,
  generatedAt: "2026-10-21T00:00:00Z",
  releases: [installed, older],
};

const detail: ReleaseDetail = {
  ...installed,
  kind: "detail",
  summary: "Extensions are now the first thing you see.",
  comparison: { available: true, predecessorSlug: "v3-52-0", predecessorRawTag: "v3.52.0" },
  changes: [
    { id: "c1", kind: "fixed", summary: "Named why a connector scan failed.", evidenceUrl: null },
    {
      id: "c2",
      kind: "security",
      summary: "Verified the extension-control authority in the resident.",
      evidenceUrl: "https://github.com/hashgraph-online/hol-guard/pull/5534",
    },
  ],
  roster: [
    {
      creditId: "credit-1",
      githubNumericId: 4242,
      login: "kantorcodes",
      type: "human",
      roles: ["Author"],
      verificationMethod: "pull-request-author",
      evidenceUrl: "https://github.com/kantorcodes",
    },
    {
      creditId: "credit-2",
      githubNumericId: 99,
      login: null,
      type: "unresolved",
      roles: ["Co-author"],
      verificationMethod: "verified-coauthor",
      evidenceUrl: null,
    },
  ],
  assets: [{ name: "hol_guard-3.53.0-py3-none-any.whl", url: "https://example.org/guard.whl" }],
  sourceNotes: { scope: "exact_release", text: "Published notes for 3.53.0." },
};

// The tab exists, is reachable, and is named the same in every place that
// names it — a nav item whose route resolves elsewhere is a dead tab.
{
  const item = SHELL_NAV_ITEMS.find((candidate) => candidate.view === "releases");
  assert.ok(item, "the shell has a Releases tab");
  assert.equal(item?.href, "/releases");
  assert.equal(resolveView("/releases"), "releases");
  assert.equal(viewTitle("releases"), "Releases");
  assert.equal(canonicalNavigationView("releases"), "releases");
  assert.equal(navigationItemForView("releases").href, "/releases");
  assert.ok(item && item.description.length > 0, "the tab says what it is for");
}

// The layout must route the view to its own slot, or the tab renders blank.
{
  const layout = readFileSync(new URL("../approval-center-layout.tsx", import.meta.url), "utf8");
  assert.match(layout, /releasesContent\?: ReactNode;/);
  assert.match(layout, /props\.view === "releases"/);
}

// What's new names the installed version and offers a way out of the card.
{
  const markup = renderToStaticMarkup(
    createElement(WhatsNewCard, { release: installed, onRead: () => {}, onDismiss: () => {} }),
  );
  assert.match(markup, /What&#x27;s new in Guard 3.53.0/);
  assert.match(markup, /Read the notes/);
  assert.match(markup, /aria-label="Dismiss what&#x27;s new in Guard 3.53.0"/);
}

// The archive marks the version running here and labels a preview build.
{
  const markup = renderToStaticMarkup(
    createElement(ReleaseArchiveList, {
      index,
      selectedSlug: "v3-53-0",
      installedSlug: "v3-53-0",
      onSelect: () => {},
      onPage: () => {},
    }),
  );
  assert.match(markup, /Installed here/);
  assert.match(markup, /Preview/);
  assert.match(markup, /aria-current="true"/);
  assert.match(markup, /Showing 1–2 of 2 releases/);
  assert.match(markup, /aria-label="Published Guard releases"/);
  // Both paging controls are disabled on a single-page archive.
  assert.equal(markup.match(/disabled=""/g)?.length, 2);
}

// The detail renders changes security-first, the verified roster with its
// method, the downloads, and the comparison it is entitled to claim.
{
  const markup = renderToStaticMarkup(createElement(ReleaseDetailPanel, { detail }));
  assert.ok(
    markup.indexOf(">Security<") < markup.indexOf(">Fixed<"),
    "security leads the change list",
  );
  assert.match(markup, /Changes since v3.52.0./);
  assert.match(markup, /kantorcodes/);
  assert.match(markup, /GitHub user 99/);
  assert.match(markup, /Verified co-author trailer/);
  assert.match(markup, /hol_guard-3.53.0-py3-none-any.whl/);
  assert.match(markup, /Published release notes/);
  // Every outbound link leaves safely.
  for (const match of markup.matchAll(/<a [^>]*href="https:[^"]*"[^>]*>/g)) {
    assert.match(match[0], /rel="noopener noreferrer"/);
    assert.match(match[0], /target="_blank"/);
  }
}

// Partial coverage is stated on the release it applies to, not hidden.
{
  const markup = renderToStaticMarkup(
    createElement(ReleaseDetailPanel, {
      detail: {
        ...detail,
        coverage: { ...coverage, attributionState: "in-progress" },
        comparison: { available: false, reason: "unverified-predecessor" },
      },
    }),
  );
  assert.match(markup, /still being verified/);
  assert.match(markup, /not a verified comparison/);
}

// A release with nothing itemised says so rather than rendering an empty list.
{
  const markup = renderToStaticMarkup(
    createElement(ReleaseDetailPanel, { detail: { ...detail, changes: [], roster: [], assets: [] } }),
  );
  assert.match(markup, /No itemised changes were published/);
  assert.ok(!markup.includes("Verified contributors"), "no empty roster heading");
  assert.ok(!markup.includes("Downloads"), "no empty downloads heading");
}

// The portal mints version labels with the leading v of the git tag. The
// screen names a version once — "Guard v3.0.99" reads as a different product.
// This shape is taken from real portal output (an index/detail pair captured
// from the release feed read service), down to the empty assets list and the
// release with no published notes of its own.
{
  const real: ReleaseDetail = {
    ...detail,
    slug: "v3.0.99",
    rawTag: "v3.0.99",
    versionLabel: "v3.0.99",
    title: "v3.0.99",
    coverage: { attributionState: "complete", historyCoverage: "partial", verifiedAt: null },
    assets: [],
    sourceNotes: null,
  };
  const markup = renderToStaticMarkup(createElement(ReleaseDetailPanel, { detail: real }));
  assert.match(markup, />Guard 3.0.99</);
  assert.ok(!markup.includes("Guard v3.0.99"), "the v is not doubled onto the label");
  assert.match(markup, /does not cover every release/, "partial history is stated");
  assert.ok(!markup.includes("Downloads"), "a release with no assets shows no downloads");

  const archive = renderToStaticMarkup(
    createElement(ReleaseArchiveList, {
      index: { ...index, releases: [{ ...installed, versionLabel: "v3.0.99" }] },
      selectedSlug: null,
      installedSlug: null,
      onSelect: () => {},
      onPage: () => {},
    }),
  );
  assert.match(archive, />3.0.99</);
}

// Two rules the workspace has to keep that only its wiring can show.
//
// A card dismissed last week must not paint once before an effect hides it:
// the decision is read while rendering, so the first frame is already right.
// And the archive read must not depend on the installed version, or the
// version landing second refetches the whole page the reader is looking at.
{
  const workspace = readFileSync(new URL("./releases-workspace.tsx", import.meta.url), "utf8");
  assert.ok(
    !/useEffect\([^)]*setDismissed/s.test(workspace),
    "dismissal is decided during render, not in an effect",
  );
  assert.match(workspace, /const whatsNewDismissed =/);
  assert.match(workspace, /\}, \[page, reloadToken\]\);/, "the archive read pages, nothing else");
}

// hol.org publishes the Markdown a maintainer wrote. The panel renders it as
// structure, and never as markup: no path from upstream bytes to innerHTML.
{
  const markup = renderToStaticMarkup(
    createElement(ReleaseDetailPanel, {
      detail: {
        ...detail,
        sourceNotes: {
          scope: "exact_release",
          text: [
            "## Fixes",
            "",
            "- **runtime**: retire the shim ([#5496](https://github.com/hashgraph-online/hol-guard/pull/5496))",
            "",
            "## Install",
            "",
            "```bash",
            "hol-guard update --alpha",
            "```",
            "",
            "<img src=x onerror=alert(1)>",
          ].join("\n"),
        },
      },
    }),
  );
  assert.match(markup, /<h5[^>]*>(<span>)?Fixes</, "a heading is a heading");
  assert.match(markup, /<li[^>]*>.*<strong[^>]*>(<span>)?runtime</s, "a list item with bold text");
  assert.match(
    markup,
    /href="https:\/\/github.com\/hashgraph-online\/hol-guard\/pull\/5496"/,
    "the link resolves",
  );
  assert.match(markup, /<pre[^>]*>.*hol-guard update --alpha/s, "a fenced command is a code block");
  assert.ok(!markup.includes("<img src=x"), "upstream HTML never becomes markup");
  assert.match(markup, /&lt;img src=x onerror=alert\(1\)&gt;/, "it survives as its own text");
  // The same release is not told three times over: the derived list is there,
  // one disclosure away, rather than repeating the notes down the page.
  assert.match(markup, /<details[^>]*>/, "the itemised list is collapsed behind the notes");
}

// Asked for a release the reader has installed, the panel says so.
{
  const markup = renderToStaticMarkup(
    createElement(ReleaseDetailPanel, { detail, isInstalled: true }),
  );
  assert.match(markup, /Running here/);
}

// Notes published for the whole series describe the series, so this release's
// own summary and its documented changes stay on the page beside them.
{
  const markup = renderToStaticMarkup(
    createElement(ReleaseDetailPanel, {
      detail: {
        ...detail,
        summary: "Extensions are now the first thing you see.",
        changes: [
          ...detail.changes,
          {
            id: "doc-1",
            kind: "other" as const,
            summary: "Documented change: the sidebar groups extensions first.",
            evidenceUrl: null,
          },
        ],
        sourceNotes: {
          scope: "train_overview",
          text: "## 3.53 series\n\n- Rolling notes for the series.",
        },
      },
    }),
  );
  assert.match(markup, /Extensions are now the first thing you see\./, "the release summary survives series notes");
  assert.match(markup, /the sidebar groups extensions first/, "a documented change is the only record of this version");
  assert.ok(
    !markup.includes("Itemised changes"),
    "series notes do not speak for this release, so the change list is not collapsed behind them",
  );
}

console.log("releases-ui.test.tsx passed");
