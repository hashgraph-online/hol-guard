import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ReleaseDetailPanel } from "./components/release-detail-panel";
import type { ReleaseDetail } from "./releases-types";

const detail: ReleaseDetail = {
  slug: "v3.59.0",
  rawTag: "v3.59.0",
  channel: "stable",
  train: "3.59",
  versionLabel: "3.59.0",
  title: "A long release",
  publishedAt: "2026-11-01T00:00:00Z",
  coverage: { attributionState: "complete", historyCoverage: "complete", verifiedAt: "2026-11-01T00:00:00Z" },
  kind: "detail",
  summary: "Many changes.",
  comparison: { available: false, reason: "first-release" },
  changes: [
    { id: "c1", kind: "fixed", summary: "Fixed one thing.", evidenceUrl: null },
    { id: "c2", kind: "added", summary: "Added another thing.", evidenceUrl: null },
  ],
  changesTotal: 2,
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
      githubNumericId: 4242,
      login: "kantorcodes",
      type: "human",
      roles: ["Reviewer"],
      verificationMethod: "pull-request-author",
      evidenceUrl: "https://github.com/kantorcodes",
    },
  ],
  rosterTotal: 2,
  assets: [],
  sourceNotes: null,
};

// A list longer than Guard shows says how many published entries it holds and
// points at the full release, instead of the whole page failing to load.
{
  const trimmed = renderToStaticMarkup(
    createElement(ReleaseDetailPanel, { detail: { ...detail, changesTotal: 1250, rosterTotal: 1100 } }),
  );
  assert.match(trimmed, /Showing the first 2 of 1,250 change entries\./);
  // Credits merge per person, so the note counts credits, not people.
  assert.match(trimmed, /Showing the first 2 of 1,100 contributor credits\./);
  assert.match(trimmed, /href="https:\/\/hol.org\/guard\/releases\/v3.59.0"/);

  const whole = renderToStaticMarkup(createElement(ReleaseDetailPanel, { detail }));
  assert.ok(!whole.includes("Showing the first"), "a release shown in full carries no note");
}

console.log("release-trim-ui.test.tsx passed");
