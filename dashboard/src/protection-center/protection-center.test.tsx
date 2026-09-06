import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { assertSimpleCopySafe, localSettingChoiceLabel, PROTECTION_TERMS, protectionCenterLoadError, simpleCopyViolations } from "./copy/protection-copy";
import { CatalogFilterBar } from "./components/catalog-filter-bar";
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
  extensionId: "command.dns",
  name: "DNS command protection",
  description: "Reviews hosted-zone deletion.",
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

const filterBar = renderToStaticMarkup(createElement(CatalogFilterBar, {
  catalog: [
    protectionModuleFixture({ extension_id: "command.git", name: "Git" }),
    protectionModuleFixture({
      extension_id: "command.mcp-filesystem",
      name: "Filesystem MCP",
      trust_class: "external",
      surface: "mcp",
      description: "Reviews official filesystem MCP tools.",
    }),
  ],
  filters: EMPTY_CATALOG_FILTERS,
  onChange: () => undefined,
}));
assert.match(filterBar, /data-testid="catalog-filters"/);
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
assert.doesNotMatch(filterBar, /Clear filters/);

const technical = renderToStaticMarkup(createElement(TechnicalDetails, { children: createElement("code", null, "command.git") }));
assert.match(technical, /<details/);
assert.doesNotMatch(technical, / open/);

console.log("protection-center.test.tsx: all assertions passed");
