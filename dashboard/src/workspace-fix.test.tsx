import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { WorkspaceFinding } from "./workspace-findings-api";
import {
  applyFix,
  fetchFixProposals,
  fixErrorMessage,
  FixRequestError,
  normalizeFixProposal,
  prepareFix,
  skippedManifestMessage,
  type FixProposal,
} from "./workspace-fix-api";
import {
  appliedNotice,
  canPrepareFix,
  DiffBlock,
  FixCell,
  FixHistory,
  FixLoadError,
  FixReview,
  type WorktreeFixes,
} from "./workspace-fix-panel";

const CODEBASE = "c".repeat(64);
const WORKTREE = "w".repeat(64);
const FINDING = "f".repeat(32);
const worktree = { codebaseKey: CODEBASE, worktreeKey: WORKTREE };
const DIFF = '--- a/package.json\n+++ b/package.json\n@@ -2 +2 @@\n-    "lodash": "^4.17.15"\n+    "lodash": "^4.17.21"\n';

function rawProposal(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    proposal_id: "p".repeat(32),
    codebase_key: CODEBASE,
    worktree_key: WORKTREE,
    finding_id: FINDING,
    package_name: "lodash",
    fix_version: "4.17.21",
    advisory_ids: ["GHSA-35jh-r3h4-6jhm", 7],
    manifest_path: "package.json",
    edits: [{ section: "dependencies", from_spec: "^4.17.15", to_spec: "^4.17.21" }, { section: "x" }],
    diff: DIFF,
    state: "prepared",
    created_at_ms: 1_700_000_000_000,
    applied_at_ms: null,
    verified_at_ms: null,
    ...overrides,
  };
}

function proposal(overrides: Record<string, unknown> = {}): FixProposal {
  const value = normalizeFixProposal(rawProposal(overrides));
  if (value === null) throw new Error("proposal fixture did not normalize");
  return value;
}

const finding: WorkspaceFinding = {
  findingId: FINDING,
  severity: "high",
  decision: "block",
  ecosystem: "npm",
  packageName: "lodash",
  packageVersion: "4.17.15",
  fixVersion: "4.17.21",
  advisoryIds: ["GHSA-35jh-r3h4-6jhm"],
  kind: "supply_chain",
  ruleIds: [],
  path: null,
  line: null,
  lines: [],
  runtime: null,
  skill: null,
  mcp: null,
  hook: null,
};

function fixes(overrides: Partial<WorktreeFixes> = {}): WorktreeFixes {
  const noop = () => undefined;
  return {
    proposals: [],
    reviewing: null,
    prepared: null,
    busy: null,
    error: null,
    loaded: true,
    loadError: null,
    applyUnsupported: false,
    notice: null,
    prepare: noop,
    review: noop,
    close: noop,
    apply: noop,
    retry: noop,
    ...overrides,
  };
}

function render(node: Parameters<typeof renderToStaticMarkup>[0]): string {
  return renderToStaticMarkup(node);
}

// Normalization keeps only well-formed edits and drops the diff once a proposal leaves review.
const prepared = proposal();
assert.deepEqual(prepared.edits, [{ section: "dependencies", fromSpec: "^4.17.15", toSpec: "^4.17.21" }]);
assert.deepEqual(prepared.advisoryIds, ["GHSA-35jh-r3h4-6jhm"]);
assert.equal(prepared.diff, DIFF);
assert.equal(proposal({ state: "applied" }).diff, null);
assert.equal(normalizeFixProposal(rawProposal({ state: "done" })), null);
assert.equal(normalizeFixProposal(rawProposal({ edits: [] })), null);
assert.equal(normalizeFixProposal(rawProposal({ proposal_id: "" })), null);

// Only a direct npm dependency with a published fix version offers Prepare.
assert.equal(canPrepareFix(finding), true);
assert.equal(canPrepareFix({ ...finding, ecosystem: "pypi" }), false);
assert.equal(canPrepareFix({ ...finding, fixVersion: null }), false);

assert.match(render(createElement(FixCell, { finding, fixes: fixes() })), /Prepare fix/);
assert.match(render(createElement(FixCell, { finding: { ...finding, fixVersion: null }, fixes: fixes() })), /Manual update/);
assert.doesNotMatch(render(createElement(FixCell, { finding: { ...finding, fixVersion: null }, fixes: fixes() })), /<button/);
assert.match(render(createElement(FixCell, { finding, fixes: fixes({ proposals: [prepared] }) })), /Review fix/);
assert.match(render(createElement(FixCell, { finding, fixes: fixes({ proposals: [proposal({ state: "applied" })] }) })), /Waiting for re-check/);
assert.match(render(createElement(FixCell, { finding, fixes: fixes({ proposals: [proposal({ state: "still_present" })] }) })), /Still found/);
assert.match(render(createElement(FixCell, { finding, fixes: fixes({ proposals: [proposal({ state: "stale" })] }) })), /Prepare again/);
// The newest proposal wins: a stale one listed after a fresh prepared one does not hide Review.
assert.match(
  render(createElement(FixCell, { finding, fixes: fixes({ proposals: [prepared, proposal({ state: "stale", proposal_id: "q".repeat(32) })] }) })),
  /Review fix/,
);
assert.match(render(createElement(FixCell, { finding, fixes: fixes({ busy: `prepare:${FINDING}` }) })), /Preparing…/);
// A sibling manifest still waiting for review keeps Review reachable whichever sibling sorts first.
assert.match(
  render(createElement(FixCell, { finding, fixes: fixes({ proposals: [proposal({ state: "applied", proposal_id: "a".repeat(32) }), prepared] }) })),
  /Review fix/,
);
// A finding listed again after a verified fix offers a new one instead of claiming it is fixed.
const relisted = render(createElement(FixCell, { finding, fixes: fixes({ proposals: [proposal({ state: "verified_fixed" })] }) }));
assert.match(relisted, /Prepare again/);
assert.doesNotMatch(relisted, />Fixed</);
// Until the proposal list loads, Prepare stays off and the failure is shown with a retry.
assert.match(render(createElement(FixCell, { finding, fixes: fixes({ loadError: "down" }) })), /<button[^>]*disabled/);
// The first load has not finished yet, so a stored proposal could still be hidden.
assert.match(render(createElement(FixCell, { finding, fixes: fixes({ loaded: false }) })), /<button[^>]*disabled/);
assert.equal(render(createElement(FixLoadError, { fixes: fixes() })), "");
const loadError = render(createElement(FixLoadError, { fixes: fixes({ loadError: "down" }) }));
assert.match(loadError, /role="alert"/);
assert.match(loadError, /Retry/);

// The review shows the exact change and one Apply per manifest; nothing renders while closed.
assert.equal(render(createElement(FixReview, { fixes: fixes({ proposals: [prepared] }), findings: [finding] })), "");
const review = render(
  createElement(FixReview, {
    findings: [finding],
    fixes: fixes({
      reviewing: FINDING,
      proposals: [prepared, proposal({ state: "verified_fixed", proposal_id: "v".repeat(32) })],
      prepared: {
        proposals: [prepared],
        skipped: [{ manifestPath: "packages/web/package.json", reason: "spec_workspace_protocol" }],
        truncated: true,
      },
    }),
  }),
);
assert.match(review, /Review fix for lodash/);
assert.match(review, /Apply to package\.json/);
assert.equal(review.match(/Apply to /g)?.length, 1);
assert.match(review, /\^4\.17\.15/);
assert.match(review, /packages\/web\/package\.json/);
assert.match(review, /another package in this workspace/);
assert.match(review, /stopped before reading every package\.json/);
assert.match(review, /Nothing is written until you apply it/);
assert.match(render(createElement(FixReview, { findings: [finding], fixes: fixes({ reviewing: FINDING, error: "boom" }) })), /role="alert"/);
// A newer check that no longer lists the finding leaves nothing to apply.
const obsolete = render(createElement(FixReview, { findings: [], fixes: fixes({ reviewing: FINDING, proposals: [prepared] }) }));
assert.doesNotMatch(obsolete, /Apply to /);
assert.match(obsolete, /no longer lists this finding/);
// Once the daemon says it cannot write fixes here, the diff stays but Apply goes away.
const unsupported = render(
  createElement(FixReview, { findings: [finding], fixes: fixes({ reviewing: FINDING, proposals: [prepared], applyUnsupported: true }) }),
);
assert.doesNotMatch(unsupported, /Apply to /);
assert.match(unsupported, /bg-emerald-50/);

const diff = render(createElement(DiffBlock, { diff: DIFF, label: "Proposed change" }));
assert.match(diff, /bg-emerald-50[^>]*>\+ {4}&quot;lodash&quot;: &quot;\^4\.17\.21&quot;/);
assert.match(diff, /bg-red-50[^>]*>- {4}&quot;lodash&quot;/);
assert.doesNotMatch(diff, /bg-red-50[^>]*>---/);

// History keeps outcomes visible after the finding leaves the list, and skips prepared or stale ones.
const history = render(
  createElement(FixHistory, {
    findings: [],
    fixes: fixes({
      proposals: [
        proposal({ state: "verified_fixed", verified_at_ms: Date.now() - 60_000 }),
        proposal({ state: "stale", proposal_id: "s".repeat(32), package_name: "left-pad" }),
        proposal({ proposal_id: "r".repeat(32), package_name: "minimist" }),
      ],
    }),
  }),
);
assert.match(history, /Fixed/);
assert.match(history, /Confirmed by a complete check/);
assert.doesNotMatch(history, /left-pad|minimist/);
assert.equal(render(createElement(FixHistory, { findings: [finding], fixes: fixes({ proposals: [proposal({ state: "applied" })] }) })), "");

// The notice only promises a re-check that was actually scheduled.
const appliedProposal = proposal({ state: "applied" });
assert.match(appliedNotice(appliedProposal, { proposal: appliedProposal, lockfiles: ["package-lock.json"], verificationQueued: true }), /Update package-lock\.json.*checks again/);
assert.match(appliedNotice(appliedProposal, { proposal: appliedProposal, lockfiles: [], verificationQueued: false }), /could not schedule a check.*Assess now/);

// Copy names the problem and the recovery, and never offers to write what the daemon refused.
assert.match(fixErrorMessage("fix_unsupported", "transitive_dependency"), /update that dependency instead/);
assert.match(fixErrorMessage("fix_unsupported", "spec_git_or_url"), /^Guard prepared no change\. It installs from a Git/);
assert.match(fixErrorMessage("fix_apply_unsupported", null), /Make the change shown above yourself/);
assert.match(fixErrorMessage("fix_proposal_stale", null), /wrote nothing/);
assert.match(fixErrorMessage("mystery", null), /retry/);
assert.match(skippedManifestMessage("unknown_reason"), /could not change this file safely/);

const storage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
Object.defineProperty(globalThis, "window", { configurable: true, value: {
  location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
  sessionStorage: storage, localStorage: storage,
} });
const previousFetch = globalThis.fetch;
try {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  let reply: { status: number; body: unknown } = { status: 200, body: {} };
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : null });
    return new Response(JSON.stringify(reply.body), { status: reply.status });
  };

  reply = { status: 200, body: { proposals: [rawProposal(), { proposal_id: "broken" }] } };
  const listed = await fetchFixProposals(worktree);
  assert.equal(listed.length, 1);
  assert.match(calls.at(-1)?.url ?? "", /workspace-fix-proposals\?codebase_key=c+&worktree_key=w+$/);

  reply = {
    status: 201,
    body: { proposals: [rawProposal()], skipped: [{ manifest_path: "a/package.json", reason: "spec_npm_alias" }, {}], truncated: true },
  };
  const result = await prepareFix(worktree, FINDING);
  assert.deepEqual(calls.at(-1)?.body, { codebase_key: CODEBASE, worktree_key: WORKTREE, finding_id: FINDING });
  assert.deepEqual(result.skipped, [{ manifestPath: "a/package.json", reason: "spec_npm_alias" }]);
  assert.equal(result.truncated, true);

  reply = { status: 200, body: { proposal: rawProposal({ state: "applied" }), lockfiles: ["package-lock.json"], verification_queued: true } };
  const applied = await applyFix("p".repeat(32));
  assert.equal(calls.at(-1)?.method, "POST");
  assert.match(calls.at(-1)?.url ?? "", /\/p{32}\/apply$/);
  assert.deepEqual(applied.lockfiles, ["package-lock.json"]);
  assert.equal(applied.proposal.state, "applied");

  reply = { status: 409, body: { error: "fix_proposal_stale", detail: "private-server-marker" } };
  await assert.rejects(applyFix("p".repeat(32)), (error: unknown) =>
    error instanceof FixRequestError && error.code === "fix_proposal_stale" && !error.message.includes("private-server-marker"));
  reply = { status: 422, body: { error: "fix_unsupported", reason: "no_fix_version" } };
  await assert.rejects(prepareFix(worktree, FINDING), /No fixed version has been published yet/);
  // A refusal keeps the files it left unchanged so the review can still list them.
  reply = {
    status: 422,
    body: { error: "fix_unsupported", reason: "spec_npm_alias", skipped: [{ manifest_path: "a/package.json", reason: "spec_npm_alias" }, { reason: 1 }], truncated: true },
  };
  await assert.rejects(prepareFix(worktree, FINDING), (error: unknown) =>
    error instanceof FixRequestError && error.skipped.length === 1 && error.skipped[0]?.manifestPath === "a/package.json" && error.truncated);
  reply = { status: 200, body: { proposal: { proposal_id: "x" } } };
  await assert.rejects(applyFix("p".repeat(32)), FixRequestError);
} finally {
  globalThis.fetch = previousFetch;
}

console.log("workspace fix tests passed");
