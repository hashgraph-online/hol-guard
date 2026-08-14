import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { CommandActivityItem } from "../command-activity/command-activity-types";
import type { GuardRuntimeSnapshot } from "../guard-types";
import { CloudContinuityIndicator, ProtectionWatchingMap, RecentProtectionDecisions } from "./components/protection-landing-panels";
import { FIXED_PROTECTION_PERMISSION, PROTECTION_AUTHORITY_FIXTURES, protectionModuleFixture } from "./fixtures/protection-fixtures";
import {
  evaluateProtectionHealth,
  filterProtectionModulesByHumanQuery,
  protectionCategorySummary,
  protectionCloudContinuity,
  protectionDecisionForAction,
  rankProtectionModules,
  recentProtectionDecisions,
  searchCommandPatterns,
} from "./model/protection-landing";

function activity(overrides: Partial<CommandActivityItem> = {}): CommandActivityItem {
  return {
    activity_id: "activity-1",
    occurred_at: "2026-08-10T00:00:00Z",
    harness: "codex",
    hook_phase: "pre",
    execution_status: "prevented",
    proof_level: "pre_hook",
    policy_action: "block",
    decision_reason_code: "extension_match",
    controlling_rule_id: "command.git.hard-reset",
    parse_confidence: "exact",
    uncertainty_class: null,
    match_count: 1,
    prompted: false,
    approval_reuse_status: "not-applicable",
    receipt_link_status: "not_applicable",
    receipt_id: null,
    evaluation_latency_bucket: "lt_10ms",
    persistence_latency_bucket: "lt_10ms",
    feedback_label: null,
    schema_version: "guard.command-activity.v1",
    matches: [{
      ordinal: 0,
      extension_id: "command.git",
      extension_version: "1.0.0",
      rule_id: "command.git.hard-reset",
      rule_version: "1",
      match_class: "unsafe",
      severity: "high",
      default_floor: "review",
      safe_variant_id: null,
      effect_classes: ["destructive-or-irreversible-operation"],
      schema_version: "guard.command-match.v1",
    }],
    ...overrides,
  };
}

const git = protectionModuleFixture({ extension_id: "command.git", name: "Git", description: "Protect source control history", ecosystem_ids: ["git"], executables: ["git"] });
const npm = protectionModuleFixture({ extension_id: "command.npm", name: "npm", description: "Protect packages and dependencies", ecosystem_ids: ["npm"], executables: ["npm"], action_classes: ["package.install"], risk_classes: ["supply-chain"] });
const curl = protectionModuleFixture({ extension_id: "command.curl", name: "curl", description: "Protect downloads and network access", ecosystem_ids: ["curl"], executables: ["curl"], action_classes: ["network.read"], risk_classes: ["network-egress"] });
const secret = protectionModuleFixture({ extension_id: "command.secret-tool", name: "Secret tool", description: "Protect credentials and sensitive files", ecosystem_ids: [], executables: ["secret-tool"], action_classes: ["credential.read"], risk_classes: ["secret-access"] });
const catalog = [git, npm, curl, secret];

assert.equal(protectionDecisionForAction("allow"), "allowed");
assert.equal(protectionDecisionForAction("block"), "blocked");
assert.equal(protectionDecisionForAction("review"), "ask-first");
assert.equal(protectionDecisionForAction("warn"), "ask-first");
assert.equal(protectionDecisionForAction(null), "ask-first");

const ranked = rankProtectionModules(catalog, [activity()]);
assert.equal(ranked[0]?.extension.extension_id, "command.git");
assert.equal(ranked[0]?.section, "in-use");
assert.equal(ranked[0]?.involvementCount, 1);
assert.equal(ranked.find((item) => item.extension.extension_id === "command.npm")?.section, "recommended");
assert.equal(rankProtectionModules(catalog, []).some((item) => item.section === "in-use"), false);

assert.deepEqual(filterProtectionModulesByHumanQuery(ranked, "git").map((item) => item.extension.name), ["Git"]);
assert.deepEqual(filterProtectionModulesByHumanQuery(ranked, "packages").map((item) => item.extension.name), ["npm"]);
assert.deepEqual(filterProtectionModulesByHumanQuery(ranked, "downloads").map((item) => item.extension.name), ["curl"]);
assert.deepEqual(filterProtectionModulesByHumanQuery(ranked, "secrets").map((item) => item.extension.name), ["Secret tool"]);
assert.equal(filterProtectionModulesByHumanQuery(ranked, "/Users/private/workspace").length, 0);

const decisions = recentProtectionDecisions([
  activity({ activity_id: "older", occurred_at: "2026-08-09T23:00:00Z", policy_action: "allow", execution_status: "confirmed_success" }),
  activity({ activity_id: "newer", occurred_at: "2026-08-10T00:00:00Z", policy_action: "block" }),
], catalog, 5);
assert.deepEqual(decisions.map((item) => item.activityId), ["newer", "older"]);
assert.deepEqual(decisions.map((item) => item.result), ["blocked", "allowed"]);
assert.deepEqual(decisions[0]?.extensionNames, ["Git"]);

const localOnlyRuntime = {
  sync_configured: false,
  cloud_state: "local_only",
  cloud_state_detail: "",
  runtime_state: "ready",
} as unknown as GuardRuntimeSnapshot;
const connectedRuntime = {
  sync_configured: true,
  cloud_state: "paired_active",
  cloud_state_detail: "Connected to Guard Cloud",
  runtime_state: "ready",
} as unknown as GuardRuntimeSnapshot;
assert.equal(protectionCloudContinuity(localOnlyRuntime).state, "not-connected");
assert.match(protectionCloudContinuity(localOnlyRuntime).detail, /Local protection continues/);
assert.equal(protectionCloudContinuity(connectedRuntime).state, "connected");
assert.equal(protectionCloudContinuity(null, true).state, "unavailable");
assert.match(protectionCloudContinuity(null, true).detail, /Local protection continues/);

const healthy = evaluateProtectionHealth("a".repeat(64), PROTECTION_AUTHORITY_FIXTURES.protected, connectedRuntime);
assert.equal(healthy.status, "healthy");
const needsAttention = evaluateProtectionHealth("b".repeat(64), PROTECTION_AUTHORITY_FIXTURES.tampered, null);
assert.equal(needsAttention.status, "needs-attention");
assert.equal(needsAttention.checks.filter((check) => !check.passed).length, 3);

const cloudMarkup = renderToStaticMarkup(createElement(CloudContinuityIndicator, { continuity: protectionCloudContinuity(null, true) }));
assert.match(cloudMarkup, /Cloud continuity unavailable/);
assert.match(cloudMarkup, /Local protection continues/);
assert.doesNotMatch(cloudMarkup, /unprotected|protection stopped/i);

const decisionMarkup = renderToStaticMarkup(createElement(RecentProtectionDecisions, { decisions }));
assert.match(decisionMarkup, /Recent decisions/);
assert.match(decisionMarkup, /Blocked/);
assert.match(decisionMarkup, /Allowed/);
assert.match(decisionMarkup, /Why\?/);
assert.doesNotMatch(decisionMarkup, /Users\/private|workspace\/secret|\.env\/private/i);

const watching = renderToStaticMarkup(createElement(ProtectionWatchingMap, {
  modules: ranked,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  onOpen: () => undefined,
}));
assert.match(watching, /Guard is watching the tools your agent uses/);
assert.match(watching, /Git/);
assert.match(watching, /guard-extensions-row/);
assert.doesNotMatch(watching, /guard-extensions-chip/);
assert.doesNotMatch(watching, /divide-y/);
assert.doesNotMatch(watching, /Source control/);
assert.doesNotMatch(watching, /What HOL Guard protects/);

const areas = protectionCategorySummary(catalog, PROTECTION_AUTHORITY_FIXTURES.protected, new Set(["command.git"]));
assert.equal(areas[0]?.id, "source-control");
assert.equal(areas[0]?.inUse, 1);


// Pattern search: query matches labels, examples, flags, and IDs across tools.
{
  const git = protectionModuleFixture({
    extension_id: "command.git",
    name: "Git",
    executables: ["git"],
    permissions: [],
  }) as import("../extension-controls-api").ExtensionCatalogItem;
  const github = protectionModuleFixture({
    extension_id: "command.github",
    name: "GitHub",
    executables: ["gh"],
    permissions: [],
  }) as import("../extension-controls-api").ExtensionCatalogItem;
  const permission = (extensionId: string, suffix: string, label: string, example: string | null) => ({
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: `${extensionId}.permission.${suffix}`,
    extension_id: extensionId,
    label,
    configurable: true,
    fixed_reason: null,
    example_command: example,
  });
  const catalog = [
    { ...git, permissions: [permission("command.git", "force-push", "Forced Git push", "git push --force")] },
    { ...github, permissions: [
      permission("command.github", "merge-remote", "GitHub pull-request merge", "gh pr merge 123 --merge"),
      permission("command.github", "merge-admin", "GitHub admin merge", "gh pr merge 123 --admin"),
      permission("command.github", "read-remote", "GitHub read", "gh pr view 123"),
    ] },
  ];

  const squash = searchCommandPatterns(catalog, "merge --squash");
  assert.equal(squash.length, 0, "no permission carries a squash example in this fixture");

  const merges = searchCommandPatterns(catalog, "pr merge");
  assert.equal(merges.length, 2, "example text matches the two merge variants");
  assert.ok(merges.every((match) => match.extension.extension_id === "command.github"));

  const flag = searchCommandPatterns(catalog, "--force");
  assert.equal(flag.length, 1);
  assert.equal(flag[0]!.permission.permission_id, "command.git.permission.force-push");

  const byLabel = searchCommandPatterns(catalog, "admin merge");
  assert.equal(byLabel.length, 1);
  assert.equal(byLabel[0]!.permission.label, "GitHub admin merge");

  assert.deepEqual(searchCommandPatterns(catalog, ""), []);
  assert.deepEqual(searchCommandPatterns(catalog, "   "), []);
}

console.log("protection-landing.test.tsx: all assertions passed");
