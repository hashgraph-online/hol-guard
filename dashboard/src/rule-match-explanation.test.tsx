import { renderToStaticMarkup } from "react-dom/server";
import { normalizeApprovalExtensionCoverage, segmentDetail } from "./approval-extension-coverage";
import type { GuardApprovalExtensionCoverage } from "./approval-extension-coverage-types";
import type { GuardApprovalRequest } from "./guard-types";
import { buildTopAlertItems } from "./review-evidence";
import { ruleMatchLines } from "./rule-match-explanation";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

const DIGEST = "d".repeat(64);
const RESET = "command.git.hard-reset";

function rule(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rule_id: RESET,
    title: "Git hard reset",
    severity: "high",
    description: "Discards uncommitted changes in the working tree.",
    safer_alternatives: ["Stash the changes first with git stash.", "Use git restore on named files."],
    ...overrides,
  };
}

function coverage(
  rules: Record<string, unknown>[],
  overrides: Record<string, unknown> = {},
): GuardApprovalExtensionCoverage | null {
  return normalizeApprovalExtensionCoverage({
    schema: "guard.approval-extension-coverage.v1",
    catalog_digest: DIGEST,
    compound: false,
    segments: [
      {
        index: 0,
        executable: "git",
        extensions: [{ extension_id: "command.git", name: "Git protection", focus_rule_id: RESET }],
        rules,
        permissions: [],
      },
    ],
    ...overrides,
  });
}

// A matched rule is worded from the catalog, with its first safer alternative.
{
  const lines = ruleMatchLines(coverage([rule()]));
  assert(lines.length === 1, "one matched rule gives one line");
  assert(
    lines[0].text === "Matched the rule “Git hard reset”. Discards uncommitted changes in the working tree.",
    `matched wording: ${lines[0].text}`,
  );
  assert(lines[0].safer === "Stash the changes first with git stash.", "the first safer alternative is shown");
  assert(lines[0].step === "git", "a one-step command names its executable only");
  assert(!lines[0].text.includes("because"), "a match is never called the cause");
}

// A rule without a title is named by its description.
{
  const normalized = coverage([rule({ title: null })]);
  assert(normalized !== null, "a title-less rule no longer drops the whole card");
  assert(
    ruleMatchLines(normalized)[0].text === "Matched a Guard rule. Discards uncommitted changes in the working tree.",
    "a title-less rule uses its description",
  );
  assert(segmentDetail(normalized!.segments[0]) === null, "the setup card skips a missing title");
  assert(!ruleMatchLines(normalized)[0].text.includes(".."), "no doubled full stop after a description");
}
// A rule with neither title nor description has nothing to say.
assert(ruleMatchLines(coverage([rule({ title: null, description: null })])).length === 0, "an empty rule is skipped");

// A compound command labels each step.
{
  const lines = ruleMatchLines(coverage([rule()], { compound: true }));
  assert(lines[0].step === "Step 1 · git", `compound step label: ${lines[0].step}`);
}

// An older daemon sends only id, title and severity, which still normalizes.
{
  const older = coverage([{ rule_id: RESET, title: "Git hard reset", severity: "high" }]);
  assert(older !== null, "an older payload normalizes");
  assert(ruleMatchLines(older)[0].text === "Matched the rule “Git hard reset”.", "title alone without description");
}

// New fields with the wrong type are not the payload the daemon builds.
assert(coverage([rule({ description: 42 })]) === null, "a non-string description drops the card");
assert(coverage([rule({ safer_alternatives: "stash" })]) === null, "non-list safer alternatives drop the card");
assert(coverage([rule({ safer_alternatives: ["ok", 7] })]) === null, "a non-string safer alternative drops the card");
assert(coverage([rule({ title: 7 })]) === null, "a non-string title drops the card");
assert(
  coverage([rule({ safer_alternatives: ["one", "two", "three"] })])!.segments[0].rules[0].safer_alternatives!.length === 2,
  "safer alternatives are capped at two",
);

// On the card, matched rules replace the category guess in "Why paused".
const REQUEST: GuardApprovalRequest = {
  request_id: "request-rule-match",
  harness: "claude-code",
  artifact_id: "claude-code:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-rule-match",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "./claude.json",
  launch_target: "git reset --hard HEAD~1",
  transport: "stdio",
  review_command: "hol-guard approvals approve request-rule-match",
  approval_url: "http://127.0.0.1:4781/approvals/request-rule-match",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-11-05T12:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
};
{
  const withRules = buildTopAlertItems({ ...REQUEST, extension_coverage: coverage([rule()])! });
  const why = withRules.find((entry) => entry.id === "why-paused");
  assert(why !== undefined, "the card has a Why paused item");
  const markup = renderToStaticMarkup(<>{why!.content}</>);
  assert(markup.includes("Matched the rule “Git hard reset”."), "Why paused shows the matched rule");
  assert(markup.includes("Safer: Stash the changes first"), "Why paused shows the safer alternative");

  const permissionOnly = coverage([]);
  const fallback = buildTopAlertItems({ ...REQUEST, extension_coverage: permissionOnly! });
  const guess = renderToStaticMarkup(<>{fallback.find((entry) => entry.id === "why-paused")?.content}</>);
  assert(!guess.includes("Matched the rule"), "without matched rules the card keeps today's wording");
  assert(ruleMatchLines(undefined).length === 0, "no coverage, no lines");
}

console.log("rule-match-explanation tests passed");
