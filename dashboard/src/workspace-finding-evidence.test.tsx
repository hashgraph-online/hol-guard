import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";
import { EvidenceNote } from "./workspace-findings-tables";

const ids = { codebase_key: "c".repeat(64), worktree_key: "w".repeat(64) };

function finding(raw: Record<string, unknown>) {
  const state = normalizeWorkspaceFindingsState(
    { worktrees: [], runs: [] },
    { worktrees: [], assessments: [{ ...ids, run_id: "r", state: "completed", findings: [{ finding_id: "x", ...raw }] }] },
  );
  const [value] = state.assessments[0].findings;
  assert.ok(value, "fixture finding normalizes");
  return value;
}

function evidence(raw: Record<string, unknown>): string {
  return renderToStaticMarkup(createElement(EvidenceNote, { finding: finding(raw) }));
}

const affected = { package_name: "minimist", package_version: "1.2.5", decision: "block" };
assert.equal(finding({ ...affected, validation_state: "confirmed" }).validation, "confirmed");
assert.match(evidence({ ...affected, advisory_ids: ["GHSA-xvch-5gv4-984h"], validation_state: "confirmed" }), />Advisory match, confirmed</);
assert.match(
  evidence({ ...affected, decision: "ask", validation_state: "confirmed" }),
  />Package policy</,
  "a policy match is neither an advisory nor shown as confirmed",
);
assert.equal(
  finding({ ...affected, validation_state: "proven" }).validation,
  "unknown",
  "an unrecognised validation state is never shown as confirmed",
);
assert.match(
  evidence({ source_kind: "secret", detector: "secrets", rule_ids: ["github-token"], path: "a.env", validation_state: "unvalidated" }),
  />Rule match, not confirmed</,
);

console.log("workspace finding evidence tests passed");
