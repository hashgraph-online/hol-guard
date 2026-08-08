import assert from "node:assert/strict";

import type { EffectiveExtensionControls, ExtensionCatalogItem } from "./extension-controls-api";
import {
  classifyDomain,
  countByRiskClass,
  EMPTY_EXTENSION_FILTERS,
  filterExtensions,
  hasActiveFilters,
  isExtensionEnabled,
  matchExtensionQuery,
} from "./extensions-filters";

function makeExtension(overrides: Partial<ExtensionCatalogItem> = {}): ExtensionCatalogItem {
  return {
    extension_id: "command.filesystem",
    name: "Filesystem protection",
    description: "Reviews recursive deletion and access-control changes.",
    required: false,
    source: "built-in",
    version: "1.0.0",
    action_classes: ["filesystem destructive command"],
    risk_classes: ["destructive_shell"],
    ...overrides,
  };
}

const effective: EffectiveExtensionControls = {
  schema_version: "1.0.0",
  health: "protected",
  revision: 1,
  catalog_digest: "a".repeat(64),
  global_lockdown: false,
  controls: [
    { target: { kind: "extension", target_id: "command.disabled-one" }, state: "disabled" },
  ],
  layers: [],
  failures: [],
};

// classifyDomain

assert.equal(classifyDomain("command.filesystem"), "core");
assert.equal(classifyDomain("command.git"), "core");
assert.equal(classifyDomain("command.guard-self-protection"), "core");
assert.equal(classifyDomain("command.package.node"), "package");
assert.equal(classifyDomain("command.package.python"), "package");
assert.equal(classifyDomain("command.cloud.aws"), "cloud");
assert.equal(classifyDomain("command.aws"), "cloud");
assert.equal(classifyDomain("command.database.postgres"), "database");
assert.equal(classifyDomain("command.storage.s3"), "storage");
assert.equal(classifyDomain("command.backup.rsync"), "backup");
assert.equal(classifyDomain("command.remote.ssh"), "remote");
assert.equal(classifyDomain("command.cicd.circleci"), "cicd");
assert.equal(classifyDomain("command.platform.docker"), "platform");
assert.equal(classifyDomain("command.managed-service.dns"), "managed-service");
assert.equal(classifyDomain("command.search-messaging.email"), "search-messaging");
assert.equal(classifyDomain("command.github"), "source-control");
// Uppercase tolerance
assert.equal(classifyDomain("COMMAND.PACKAGE.NODE"), "package");
console.log("✓ classifyDomain maps extension ids to functional domains");

// isExtensionEnabled

assert.equal(
  isExtensionEnabled(effective, makeExtension({ extension_id: "command.optional-on" })),
  true,
  "optional extension without a control defaults to enabled",
);
assert.equal(
  isExtensionEnabled(effective, makeExtension({ extension_id: "command.disabled-one" })),
  false,
  "optional extension with an explicit disabled control is disabled",
);
assert.equal(
  isExtensionEnabled(effective, makeExtension({ required: true })),
  true,
  "required extension is always enabled regardless of controls",
);
console.log("✓ isExtensionEnabled resolves authority state correctly");

// matchExtensionQuery

const aws = makeExtension({
  extension_id: "command.cloud.aws",
  name: "AWS protection",
  description: "Reviews destructive AWS CLI commands.",
  action_classes: ["AWS destructive command"],
  risk_classes: ["destructive_shell", "network_egress"],
});
assert.equal(matchExtensionQuery(aws, ""), true, "empty query matches everything");
assert.equal(matchExtensionQuery(aws, "aws"), true);
assert.equal(matchExtensionQuery(aws, "AWS"), true, "search is case-insensitive");
assert.equal(matchExtensionQuery(aws, "destructive"), true, "matches description words");
assert.equal(matchExtensionQuery(aws, "network_egress"), true, "matches risk class");
assert.equal(matchExtensionQuery(aws, "command.cloud.aws"), true, "matches extension id");
assert.equal(matchExtensionQuery(aws, "cloud"), true, "matches the derived domain token");
assert.equal(matchExtensionQuery(aws, "postgres"), false, "non-matching token excluded");
assert.equal(matchExtensionQuery(aws, "aws destructive"), true, "multi-token AND search matches");
assert.equal(matchExtensionQuery(aws, "aws postgres"), false, "multi-token AND search excludes when one token misses");
assert.equal(matchExtensionQuery(aws, "  aws  "), true, "whitespace is trimmed");
console.log("✓ matchExtensionQuery handles single and multi-token search");

// hasActiveFilters

assert.equal(hasActiveFilters(EMPTY_EXTENSION_FILTERS), false);
assert.equal(hasActiveFilters({ ...EMPTY_EXTENSION_FILTERS, query: "aws" }), true);
assert.equal(hasActiveFilters({ ...EMPTY_EXTENSION_FILTERS, risk: "supply_chain" }), true);
assert.equal(hasActiveFilters({ ...EMPTY_EXTENSION_FILTERS, domain: "package" }), true);
assert.equal(hasActiveFilters({ ...EMPTY_EXTENSION_FILTERS, state: "disabled" }), true);
assert.equal(hasActiveFilters({ ...EMPTY_EXTENSION_FILTERS, required: "optional" }), true);
assert.equal(hasActiveFilters({ ...EMPTY_EXTENSION_FILTERS, query: "   " }), false, "whitespace-only query is inactive");
console.log("✓ hasActiveFilters reports active state across all dimensions");

// filterExtensions

const catalog: ExtensionCatalogItem[] = [
  makeExtension({
    extension_id: "command.filesystem",
    name: "Filesystem protection",
    risk_classes: ["destructive_shell"],
    required: true,
  }),
  makeExtension({
    extension_id: "command.package.node",
    name: "Node package protection",
    description: "Reviews npm install commands.",
    risk_classes: ["supply_chain"],
    action_classes: ["Node package install command"],
  }),
  makeExtension({
    extension_id: "command.cloud.aws",
    name: "AWS protection",
    description: "Reviews destructive AWS commands.",
    risk_classes: ["destructive_shell", "network_egress"],
    action_classes: ["AWS destructive command"],
  }),
  makeExtension({
    extension_id: "command.disabled-one",
    name: "Disabled demo",
    risk_classes: ["execution"],
  }),
];

const all = filterExtensions(catalog, effective, EMPTY_EXTENSION_FILTERS);
assert.equal(all.length, 4, "no filters returns everything, alphabetically sorted");
assert.deepEqual(
  all.map((e) => e.extension_id),
  ["command.cloud.aws", "command.disabled-one", "command.filesystem", "command.package.node"],
  "results are sorted by display name",
);

const supplyChain = filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, risk: "supply_chain" });
assert.deepEqual(
  supplyChain.map((e) => e.extension_id),
  ["command.package.node"],
  "risk filter narrows to matching extensions only",
);

const packageDomain = filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, domain: "package" });
assert.deepEqual(
  packageDomain.map((e) => e.extension_id),
  ["command.package.node"],
  "domain filter narrows by derived domain",
);

const requiredOnly = filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, required: "required" });
assert.deepEqual(
  requiredOnly.map((e) => e.extension_id),
  ["command.filesystem"],
  "required filter shows required extensions only",
);

const optionalOnly = filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, required: "optional" });
assert.equal(optionalOnly.length, 3, "optional filter excludes required extensions");

const disabledOnly = filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, state: "disabled" });
assert.deepEqual(
  disabledOnly.map((e) => e.extension_id),
  ["command.disabled-one"],
  "state filter respects the resolved enabled state",
);

const enabledOnly = filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, state: "enabled" });
assert.equal(enabledOnly.length, 3, "enabled filter includes required and optional-on extensions");

const combined = filterExtensions(catalog, effective, {
  ...EMPTY_EXTENSION_FILTERS,
  risk: "destructive_shell",
  required: "optional",
});
assert.deepEqual(
  combined.map((e) => e.extension_id),
  ["command.cloud.aws"],
  "combined risk + required filters intersect correctly",
);

const noMatches = filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, query: "kafka" });
assert.equal(noMatches.length, 0, "non-matching query returns empty");
console.log("✓ filterExtensions applies query, risk, domain, state, required, and combinations");

// Immutability: the source array and its items must not be mutated.
const catalogBefore = JSON.stringify(catalog);
filterExtensions(catalog, effective, { ...EMPTY_EXTENSION_FILTERS, query: "aws" });
assert.equal(JSON.stringify(catalog), catalogBefore, "filterExtensions must not mutate the input array");
console.log("✓ filterExtensions does not mutate inputs");

// countByRiskClass

const counts = countByRiskClass(catalog);
assert.equal(counts.get("destructive_shell"), 2);
assert.equal(counts.get("supply_chain"), 1);
assert.equal(counts.get("network_egress"), 1);
assert.equal(counts.get("execution"), 1);
assert.equal(counts.get("encoded_execution"), 0, "absent risks report zero");
console.log("✓ countByRiskClass tallies extensions per risk class");

console.log("\nAll extension filter tests passed.");
