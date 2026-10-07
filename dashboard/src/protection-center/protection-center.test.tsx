import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { assertSimpleCopySafe, localSettingChoiceLabel, PROTECTION_TERMS, protectionCenterLoadError, simpleCopyViolations } from "./copy/protection-copy";
import { CatalogFilterBar, CatalogFilterTrigger } from "./components/catalog-filter-bar";
import { ProtectionModuleRow, ProtectionStatusHero, TechnicalDetails } from "./components/protection-primitives";
import {
  CLOUD_CONNECTED_FIXTURE,
  CLOUD_OFFLINE_FIXTURE,
  FIXED_PROTECTION_MODULE,
  MALFORMED_PROTECTION_STATE_FIXTURE,
  NO_PROTECTION_DECISIONS,
  PROTECTION_AUTHORITY_FIXTURES,
  STALE_POLICY_DRAFT_FIXTURE,
  SYNTHETIC_PROTECTION_DECISIONS,
  largeDeveloperModuleFixture,
  protectionModuleFixture,
} from "./fixtures/protection-fixtures";
import { EMPTY_CATALOG_FILTERS } from "./model/catalog-filters";
import { groupProtectionModules, protectionCategoryIdForExtension } from "./model/protection-categories";
import { deriveProtectionStatus } from "./model/protection-presentation";
import { CustomExtensionsSection } from "./custom-extensions-section";
import type { LocalCliItem } from "../local-cli-api";
import { LocalCliDetail } from "./local-clis-panel";

assert.equal(PROTECTION_TERMS.navigation, "Extensions");
assert.equal(PROTECTION_TERMS.pageTitle, "Extensions");
assert.equal(localSettingChoiceLabel("inherit"), "Recommended");
assert.equal(localSettingChoiceLabel("allow"), "Permit when Guard considers it safe");
assert.equal(localSettingChoiceLabel("block"), "Always block matching actions");

assert.deepEqual(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.protected), {
  status: "protected",
  title: "Protected",
  summary: "Guard is actively applying the trusted protection settings on this device.",
  tone: "safe",
  primaryAction: "none",
  primaryActionLabel: null,
});
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.unenrolled).primaryAction, "finish-setup");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.unenrolled).primaryActionLabel, "Show setup steps");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.tampered).primaryAction, "repair");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.recoveryRequired).primaryAction, "repair");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.degradedUnacknowledged).status, "limited");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.degradedAcknowledged).primaryAction, "retry-repair");
assert.equal(deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.lockdown).status, "lockdown");
assert.equal(PROTECTION_AUTHORITY_FIXTURES.managedBlock.layers[0]?.kind, "signed-cloud");
assert.equal(PROTECTION_AUTHORITY_FIXTURES.localStricterBlock.layers[0]?.kind, "local-admin");
assert.equal(FIXED_PROTECTION_MODULE.permissions[0]?.configurable, false);
assert.equal(STALE_POLICY_DRAFT_FIXTURE.currentRevision > STALE_POLICY_DRAFT_FIXTURE.baseRevision, true);
assert.equal(CLOUD_OFFLINE_FIXTURE.syncConfigured, false);
assert.equal(CLOUD_CONNECTED_FIXTURE.syncConfigured, true);
assert.equal(NO_PROTECTION_DECISIONS.length, 0);
assert.equal(SYNTHETIC_PROTECTION_DECISIONS.length, 3);
assert.equal(typeof MALFORMED_PROTECTION_STATE_FIXTURE, "object");
const largeFixture = largeDeveloperModuleFixture();
assert.equal(largeFixture.rules.length, 500);
assert.equal(largeFixture.rule_count, 500);
assert.throws(() => largeDeveloperModuleFixture(501), /Invalid fixture rule count/);

const categoryFixtures = [
  ["command.git", "source-control"],
  ["command.npm", "packages"],
  ["command.aws", "cloud-infrastructure"],
  ["command.postgres", "data-databases"],
  ["command.curl", "network-downloads"],
  ["command.github-actions", "source-control"],
  ["command.slack", "messaging-collaboration"],
  ["command.mcp", "ai-workflows"],
  ["command.unknown-shell", "system-shell"],
] as const;
for (const [id, category] of categoryFixtures) {
  assert.equal(protectionCategoryIdForExtension(protectionModuleFixture({
    extension_id: id,
    name: id,
    description: id,
    ecosystem_ids: [],
    executables: [],
    action_classes: [],
    risk_classes: [],
  })), category);
}
const grouped = groupProtectionModules([
  protectionModuleFixture({ extension_id: "command.git", name: "Git" }),
  protectionModuleFixture({ extension_id: "command.npm", name: "npm", description: "Package manager", ecosystem_ids: ["npm"], executables: ["npm"], action_classes: ["package.install"], risk_classes: ["supply-chain"] }),
]);
assert.equal(grouped.get("source-control")?.length, 1);
assert.equal(grouped.get("packages")?.length, 1);

assert.deepEqual(simpleCopyViolations("Protection is active on this device."), []);
assert.deepEqual(simpleCopyViolations("Catalog digest is hidden here."), ["catalog digest"]);
assert.doesNotThrow(() => assertSimpleCopySafe("Guard is protecting source control on this device."));
assert.throws(() => assertSimpleCopySafe("The semantic blast radius changed."), /semantic blast radius/);

assert.equal(protectionCenterLoadError("unauthorized").title, "This view needs a signed local session");
assert.match(protectionCenterLoadError("unauthorized").detail, /Local protection is still running/);
assert.doesNotMatch(protectionCenterLoadError("unauthorized").detail, /^unauthorized$/);
assert.equal(protectionCenterLoadError("HTTP 401").title, "This view needs a signed local session");
assert.equal(protectionCenterLoadError("catalog 1401 mismatch").title, "Extensions unavailable");
assert.match(protectionCenterLoadError("catalog mismatch").detail, /catalog mismatch/);

const hero = renderToStaticMarkup(createElement(ProtectionStatusHero, { status: deriveProtectionStatus(PROTECTION_AUTHORITY_FIXTURES.protected) }));
assert.match(hero, /Local protection/);
assert.match(hero, /Protected/);
assert.match(hero, /No action required/);
assert.doesNotMatch(hero, /revision|catalog digest|authority/);

const moduleRow = renderToStaticMarkup(createElement(ProtectionModuleRow, {
  extensionId: "command.git",
  name: "Git",
  description: "Protects source-control history.",
  behavior: "Ask once",
  executables: ["git"],
  ecosystemIds: ["git"],
  onOpen: () => undefined,
}));
assert.match(moduleRow, /Git/);
assert.match(moduleRow, /Ask once/);
assert.match(moduleRow, /guard-extensions-row/);
assert.match(moduleRow, /data-extension-brand="git"/);
assert.match(moduleRow, /guard-extension-mark/);
assert.doesNotMatch(moduleRow, />[^<]*(?:permission|rule|version)[^<]*</i);

const awsRow = renderToStaticMarkup(createElement(ProtectionModuleRow, {
  extensionId: "command.cloud.aws",
  name: "AWS command protection",
  description: "Reviews AWS CLI deletions.",
  behavior: "Ask once",
  onOpen: () => undefined,
}));
assert.match(awsRow, /data-extension-brand="aws"/);

const cloudCluster = renderToStaticMarkup(createElement(ProtectionModuleRow, {
  extensionId: "command.cdn",
  name: "CDN command protection",
  description: "Reviews distribution deletion.",
  behavior: "Ask once",
  onOpen: () => undefined,
}));
assert.match(cloudCluster, /data-extension-brand="aws gcp azure"/);

const customRow = renderToStaticMarkup(createElement(ProtectionModuleRow, {
  extensionId: "local-cli.kubectl-abcdef12",
  name: "kubectl",
  description: "kubectl",
  behavior: "Custom extension. Matching commands are allowed on this device.",
  custom: true,
  executables: ["kubectl"],
  onOpen: () => undefined,
}));
assert.match(customRow, />Custom</);
assert.match(customRow, /data-extension-brand="kubernetes"/);

const mcpRow = renderToStaticMarkup(createElement(ProtectionModuleRow, {
  extensionId: "command.mcp-filesystem",
  name: "Filesystem MCP",
  description: "Reviews official filesystem MCP tools.",
  behavior: "Off until you turn it on",
  mcp: true,
  external: true,
  executables: ["npx"],
  onOpen: () => undefined,
}));
assert.match(mcpRow, />MCP</);
assert.match(mcpRow, />External</);
assert.match(mcpRow, /Off until you turn it on/);

const filterCatalog = [
  protectionModuleFixture({ extension_id: "command.git", name: "Git" }),
  protectionModuleFixture({
    extension_id: "command.mcp-filesystem",
    name: "Filesystem MCP",
    trust_class: "external",
    surface: "mcp",
    description: "Reviews official filesystem MCP tools.",
  }),
];
const filterBar = renderToStaticMarkup(createElement("div", { "data-testid": "catalog-filters" },
  createElement(CatalogFilterTrigger, {
    open: false,
    activeCount: 0,
    panelId: "catalog-filter-panel-test",
    buttonRef: { current: null },
    onToggle: () => undefined,
  }),
  createElement(CatalogFilterBar, {
    catalog: filterCatalog,
    filters: EMPTY_CATALOG_FILTERS,
    onChange: () => undefined,
    open: false,
    onOpenChange: () => undefined,
    panelId: "catalog-filter-panel-test",
  }),
));
assert.match(filterBar, /data-testid="catalog-filters"/);
assert.match(filterBar, /aria-expanded="false"/);
assert.match(filterBar, /aria-controls="catalog-filter-panel-test"/);
assert.match(filterBar, /id="catalog-filter-panel-test"/);
assert.match(filterBar, /hidden/);
assert.match(filterBar, /<legend[^>]*>Trust<\/legend>/);
assert.match(filterBar, /<legend[^>]*>Kind<\/legend>/);
assert.match(filterBar, /<legend[^>]*>Area<\/legend>/);
assert.match(filterBar, />Built in</);
assert.match(filterBar, />External</);
assert.match(filterBar, /aria-label="External, 1 tool"/);
assert.match(filterBar, />MCP</);
assert.match(filterBar, />Commands</);
assert.match(filterBar, />Source control</);
assert.match(filterBar, /aria-pressed="false"/);
assert.match(filterBar, /data-testid="catalog-filter-count"/);
assert.doesNotMatch(filterBar, /Clear filters/);

const filteringBar = renderToStaticMarkup(createElement(CatalogFilterBar, {
  catalog: filterCatalog,
  filters: { trusts: ["external"], kinds: [], areas: [] },
  onChange: () => undefined,
  open: true,
  onOpenChange: () => undefined,
  panelId: "catalog-filter-panel-open",
}));
assert.match(filteringBar, /data-testid="catalog-filter-tokens"/);
assert.match(filteringBar, /Remove External trust filter/);
assert.match(filteringBar, />Clear filters</);
assert.match(filteringBar, />Clear all 1 filter</);
assert.match(filteringBar, /1 of 2 tools/);
assert.doesNotMatch(filteringBar, /<div id="catalog-filter-panel-open"[^>]*hidden/);

const technical = renderToStaticMarkup(createElement(TechnicalDetails, { children: createElement("code", null, "command.git") }));
assert.match(technical, /<details/);
assert.doesNotMatch(technical, / open/);

const baseCustomExtension: LocalCliItem = {
  cli_id: "local-cli.fixture-abcdef12",
  name: "Fixture connector",
  kind: "executable",
  identity_hash: "a".repeat(64),
  example_label: "fixture --help",
  interpreter_name: null,
  observed_count: 1,
  last_seen_at: "2026-09-29T00:00:00Z",
  source_path: null,
  help_status: "ok",
  surface: "mcp",
  server_identity_hash: null,
  source_label: "ZCode",
  state: "unset",
  stale: false,
  grant_revision: null,
  authority_revision: 1,
  suggestable: true,
  suggestion_score: 1,
  commands: [],
};

const customEmpty = renderToStaticMarkup(createElement(CustomExtensionsSection, {
  items: [], onOpen: () => undefined, onAdd: () => undefined,
}));
assert.match(customEmpty, /data-testid="custom-extensions-empty"/);
assert.match(customEmpty, /No custom extensions yet\./);
assert.match(customEmpty, />Add custom extension</);
assert.match(customEmpty, /custom-extensions-heading/);
assert.doesNotMatch(customEmpty, /Search custom extensions/);
assert.doesNotMatch(customEmpty, /Show all/);

const customDiscovered = renderToStaticMarkup(createElement(CustomExtensionsSection, {
  items: [], onOpen: () => undefined, onAdd: () => undefined, discovering: true,
}));
assert.match(customDiscovered, /Checking host configuration for connectors…/);

const customMixed = renderToStaticMarkup(createElement(CustomExtensionsSection, {
  items: [
    { ...baseCustomExtension, cli_id: "local-cli.enrolled", name: "Enrolled tool", state: "allowed" },
    { ...baseCustomExtension, cli_id: "local-cli.observed", name: "Observed tool", state: "unset" },
  ],
  onOpen: () => undefined, onAdd: () => undefined,
}));
assert.match(customMixed, /Needs review · 1/);
assert.match(customMixed, /Reviewed · 1/);
assert.doesNotMatch(customMixed, /custom-extensions-empty/);

// When the section search is visible it must render in its own row below the
// header: the Add action closes the header row and a bounded search label
// opens the row that follows it — never inside the header's flex container,
// where a long description squeezes it into a floating box above the heading.
const customSearched = renderToStaticMarkup(createElement(CustomExtensionsSection, {
  items: Array.from({ length: 12 }, (_, index) => ({
    ...baseCustomExtension,
    cli_id: `local-cli.seeded-${index}`,
    name: `Seeded tool ${index}`,
  })),
  onOpen: () => undefined, onAdd: () => undefined,
}));
assert.match(customSearched, /Search custom extensions/);
const headerClose = customSearched.indexOf(">Add custom extension</button></div>");
const searchRow = customSearched.indexOf('<div class="mt-4"><label class="relative block w-full max-w-sm">');
assert.ok(headerClose !== -1, "the Add action must be the header row's last element");
assert.ok(searchRow > headerClose && searchRow - headerClose < 40,
  "the search label must open its own row immediately after the header closes");

const customFiltered = renderToStaticMarkup(createElement(CustomExtensionsSection, {
  items: [], onOpen: () => undefined, onAdd: () => undefined, filteredOut: true,
  onClearFilters: () => undefined,
}));
assert.match(customFiltered, /data-testid="custom-extensions-filter-empty"/);
assert.match(customFiltered, /No custom extensions match these filters\./);
assert.match(customFiltered, /Clear filters/);
assert.doesNotMatch(customFiltered, /No custom extensions yet\./);

for (const state of ["unset", "allowed", "blocked"] as const) {
  const detail = renderToStaticMarkup(createElement(LocalCliDetail, {
    item: { ...baseCustomExtension, surface: "mcp", state, name: "Synthetic MCP connector" },
    revision: 0,
    continuity: { sync_local_only: true, continuity_enabled: false, summary: "Local fixture" },
    onBack: () => undefined,
    onRefresh: async () => undefined,
  }));
  assert.match(detail, /data-testid="local-cli-detail"/);
  assert.match(detail, /Synthetic MCP connector/);
  assert.match(detail, /Refresh inventory/);
}

console.log("protection-center.test.tsx: all assertions passed");
