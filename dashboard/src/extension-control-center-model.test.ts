import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

import type { EffectiveExtensionControls, ExtensionCatalogItem, ExtensionPermission, ExtensionRule } from "./extension-controls-api";
import {
  canonicalExtensionId,
  groupPermissionsByFamily,
  DEFAULT_EXTENSION_DETAIL_URL_STATE,
  extensionDetailHref,
  extensionDetailSearch,
  extensionDisplayName,
  extensionStateLabel,
  filterDetailPermissions,
  filterDetailRules,
  parseExtensionRoute,
  permissionStateLabel,
  readExtensionDetailUrlState,
} from "./extension-control-center-model";

const digest = "a".repeat(64);

function permission(index: number, risk: "low" | "medium" | "high" | "critical" = "high"): ExtensionPermission {
  return {
    permission_id: `command.git.permission.rule-${index}`,
    schema_version: 1,
    extension_id: "command.git",
    implementation_version: "1.2.3",
    label: `Permission ${index}`,
    description: `Permission description ${index}`,
    risk_tier: risk,
    baseline_floor: risk === "critical" ? "block" : "review",
    default_enabled: true,
    configurable: index % 3 !== 0,
    fixed_reason: index % 3 === 0 ? "Fixed by Guard" : null,
    typed_capabilities: [`git.capability.${index}`],
    action_classes: [`git.action.${index}`],
    rule_ids: [`command.git.rule-${index}`],
    dependencies: [],
    conflicts: [],
    implied_permissions: [],
    introduced_version: "1.0.0",
    deprecated: index % 17 === 0,
    replacement_permission_id: null,
    example_command: null,
    family: null,
    safer_guidance: [],
  };
}

function rule(index: number, risk: "low" | "medium" | "high" | "critical" = "high"): ExtensionRule {
  return {
    rule_id: `command.git.rule-${index}`,
    rule_version: 1,
    title: `Rule ${String(index).padStart(3, "0")}`,
    description: `Rule description ${index}`,
    severity: risk,
    risk_classes: [`risk-${index}`],
    action_classes: [`git.action.${index}`],
    safer_alternatives: [],
    default_mode: "review",
    matcher_kind: "ExecutableMatcher",
    safe_variants: [],
    compatibility_fallback: false,
  };
}

const risks = ["low", "medium", "high", "critical"] as const;
const permissions = Array.from({ length: 500 }, (_, index) => permission(index, risks[index % risks.length]!));
const rules = Array.from({ length: 500 }, (_, index) => rule(index, risks[index % risks.length]!));
const extension: ExtensionCatalogItem = {
  schema_version: 2,
  extension_id: "command.git",
  name: "Git",
  description: "Protects Git commands.",
  enabled: true,
  required: false,
  source: "built-in",
  version: "1.2.3",
  aliases: ["command.scm"],
  dependencies: [], conflicts: [], delegated_protection: null,
  ecosystem_ids: ["git"], executables: ["git"], project_markers: [".git"], reference_urls: [],
  action_classes: rules.map((item) => item.action_classes[0]!), risk_classes: ["destructive_shell"], safer_alternatives: [],
  rule_count: rules.length, rules, permission_count: permissions.length, permissions,
};
const effective: EffectiveExtensionControls = {
  schema_version: "1.0.0", health: "protected", revision: 1, catalog_digest: digest,
  global_lockdown: false, controls: [], layers: [], failures: [],
};

assert.deepEqual(parseExtensionRoute("/extensions"), { kind: "overview" });
assert.deepEqual(parseExtensionRoute("/extensions/command.git"), { kind: "detail", extensionId: "command.git" });
assert.deepEqual(parseExtensionRoute("/extensions/COMMAND.GIT"), { kind: "detail", extensionId: "command.git" });
assert.deepEqual(parseExtensionRoute("/extensions/command.git/nested"), { kind: "invalid" });
assert.deepEqual(parseExtensionRoute("/extensions/%2Fetc%2Fpasswd"), { kind: "invalid" });
assert.deepEqual(parseExtensionRoute("/extensions/%ZZ"), { kind: "invalid" });
assert.equal(canonicalExtensionId([extension], "command.scm"), "command.git");
assert.equal(canonicalExtensionId([extension], "command.unknown"), null);

const safeState = readExtensionDetailUrlState("?tab=commands&q=hard%20reset&risk=high&state=blocked&sort=risk&rule=command.git.rule-1&guard-token=secret#fragment");
assert.equal(safeState.tab, "commands");
assert.equal(safeState.query, "hard reset");
assert.equal(safeState.risk, "high");
assert.equal(safeState.ruleId, "command.git.rule-1");
const safeSearch = extensionDetailSearch(safeState);
assert.match(safeSearch, /tab=commands/);
assert.doesNotMatch(safeSearch, /guard-token|secret|#/);
assert.equal(extensionDetailHref("command.git", safeState), `/extensions/command.git${safeSearch}`);
assert.doesNotMatch(extensionDetailHref("command.git", safeState), /#/);
assert.equal(readExtensionDetailUrlState("?tab=evil&risk=maximum&sort=random&rule=%2Ftmp%2Fx").tab, "overview");
assert.equal(readExtensionDetailUrlState("?tab=evil&risk=maximum&sort=random&rule=%2Ftmp%2Fx").ruleId, null);
assert.equal(readExtensionDetailUrlState(`?q=${"x".repeat(300)}`).query.length, 160);

assert.equal(extensionStateLabel(effective, extension), "Allowed");
assert.equal(permissionStateLabel(effective, extension, permissions[1]!), "Inherited");
assert.equal(extensionStateLabel({ ...effective, global_lockdown: true }, extension), "Lockdown");
assert.equal(extensionStateLabel({ ...effective, health: "tampered" }, extension), "Unavailable");
const required = { ...extension, required: true };
assert.equal(extensionStateLabel(effective, required), "Required");
const blockedParent: EffectiveExtensionControls = {
  ...effective,
  controls: [{ target: { kind: "extension", target_id: "command.git" }, state: "disabled" }],
  layers: [{ schema_version: "1.0.0", kind: "local-admin", catalog_digest: digest, global_lockdown: false, controls: [{ target_kind: "extension", target_id: "command.git", state: "disabled" }] }],
};
assert.equal(extensionStateLabel(blockedParent, extension), "Blocked");
assert.equal(permissionStateLabel(blockedParent, extension, permissions[1]!), "Blocked");
const blockedParentWithManagedPermission: EffectiveExtensionControls = {
  ...blockedParent,
  projection: {
    schema_version: "guard.daemon.extension-control-projection.v1",
    revision: 1,
    catalog_digest: digest,
    health: "protected",
    extensions: [{
      extension_id: extension.extension_id,
      effective_state: "blocked",
      local_state: "disabled",
      managed_state: "inherited",
      required: false,
      reason_codes: ["control.extension-disabled"],
    }],
    permissions: [{
      permission_id: permissions[1]!.permission_id,
      extension_id: extension.extension_id,
      effective_state: "blocked",
      local_state: "inherited",
      managed_state: "enabled",
      configurable: true,
      fixed_reason: null,
      reason_codes: ["control.extension-disabled"],
    }],
  },
};
assert.equal(permissionStateLabel(blockedParentWithManagedPermission, extension, permissions[1]!), "Blocked");
const managed: EffectiveExtensionControls = {
  ...effective,
  layers: [{ schema_version: "1.0.0", kind: "signed-cloud", catalog_digest: digest, global_lockdown: false, controls: [{ target_kind: "extension", target_id: "command.git", state: "disabled" }] }],
  controls: [{ target: { kind: "extension", target_id: "command.git" }, state: "disabled" }],
};
assert.equal(extensionStateLabel(managed, extension), "Managed");

const sharedRuleExtension: ExtensionCatalogItem = {
  ...extension,
  rules: [rules[0]!],
  rule_count: 1,
  permissions: [
    permissions[0]!,
    { ...permissions[1]!, rule_ids: [rules[0]!.rule_id] },
  ],
  permission_count: 2,
};
assert.equal(filterDetailRules(sharedRuleExtension, effective, {
  ...DEFAULT_EXTENSION_DETAIL_URL_STATE,
  tab: "commands",
  query: "Permission 0",
}).length, 1);
assert.equal(filterDetailRules(sharedRuleExtension, effective, {
  ...DEFAULT_EXTENSION_DETAIL_URL_STATE,
  tab: "commands",
  query: "Permission 1",
}).length, 0);

const rulePerformanceState = {
  ...DEFAULT_EXTENSION_DETAIL_URL_STATE,
  tab: "commands" as const,
  risk: "critical" as const,
  sort: "risk" as const,
};
const permissionPerformanceState = {
  ...DEFAULT_EXTENSION_DETAIL_URL_STATE,
  tab: "commands" as const,
  query: "Permission 49",
};
filterDetailRules(extension, effective, rulePerformanceState);
filterDetailPermissions(extension, effective, permissionPerformanceState);
const start = performance.now();
const filteredRules = filterDetailRules(extension, effective, rulePerformanceState);
const filteredPermissions = filterDetailPermissions(extension, effective, permissionPerformanceState);
const duration = performance.now() - start;
assert.equal(filteredRules.length, 125);
assert.ok(filteredPermissions.length > 0);
assert.ok(duration < 100, `500-rule filter pass took ${duration.toFixed(2)}ms`);
assert.equal(filteredRules[0]?.severity, "critical");

const sortedById = filterDetailRules(extension, effective, { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "commands", sort: "id" });
assert.equal(sortedById[0]?.rule_id, "command.git.rule-0");
assert.equal(sortedById.at(-1)?.rule_id, "command.git.rule-99");

// Family grouping: shared-command heading, stable ordering, ungrouped passthrough.
{
  const variant = (index: number, family: string | null, example: string | null): ExtensionPermission => ({
    ...permission(index),
    family,
    example_command: example,
  });
  const mergeSquash = variant(0, "gh-pr-merge", "gh pr merge 123 --squash");
  const mergePlain = variant(1, "gh-pr-merge", "gh pr merge 123 --merge");
  const mergeAdmin = variant(2, "gh-pr-merge", "gh pr merge 123 --admin");
  const readRemote = variant(3, null, "gh pr view 123");
  const grouped = groupPermissionsByFamily([readRemote, mergeAdmin, mergeSquash, mergePlain]);
  assert.deepEqual(grouped.ungrouped.map((item) => item.permission_id), [readRemote.permission_id]);
  assert.equal(grouped.families.length, 1);
  assert.equal(grouped.families[0]!.family, "gh-pr-merge");
  assert.equal(grouped.families[0]!.heading, "gh pr merge 123");
  assert.equal(grouped.families[0]!.permissions.length, 3);
  const noExamples = groupPermissionsByFamily([variant(4, "git-destructive", null)]);
  assert.equal(noExamples.families[0]!.heading, noExamples.families[0]!.permissions[0]!.label);
}

// Row display names strip the uniform catalog suffix where it is pure noise.
{
  assert.equal(extensionDisplayName("AWS command protection"), "AWS");
  assert.equal(extensionDisplayName("Git protection"), "Git");
  assert.equal(extensionDisplayName("Shell, Git, and filesystem protection"), "Shell, Git, and filesystem");
  assert.equal(extensionDisplayName("Command data protection"), "Command data");
  // "Guard self-protection" must not collapse to a dangling "Guard self-".
  assert.equal(extensionDisplayName("Guard self-protection"), "Guard self-protection");
  assert.equal(extensionDisplayName("kubectl"), "kubectl");
  assert.equal(extensionDisplayName("protection"), "protection");
}

console.log("extension-control-center-model.test.ts: all assertions passed");
