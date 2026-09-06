import assert from "node:assert/strict";

import { protectionModuleFixture } from "../fixtures/protection-fixtures";
import {
  CATALOG_KIND_FILTERS,
  CATALOG_TRUST_FILTERS,
  catalogFilterChipAriaLabel,
  catalogFilterChipCount,
  catalogFilterCountCopy,
  catalogFiltersActive,
  catalogItemMatchesFilters,
  catalogKindLabel,
  catalogTrustLabel,
  catalogFiltersEqual,
  customItemMatchesFilters,
  customItemMatchesKind,
  EMPTY_CATALOG_FILTERS,
  filterCatalogExtensions,
  populatedCatalogAreaOptions,
  populatedCatalogAreas,
  pruneCatalogFilters,
  toggleCatalogFilterValue,
} from "./catalog-filters";

const git = protectionModuleFixture({
  extension_id: "command.git",
  name: "Git",
  trust_class: "first-party",
  executables: ["git"],
  ecosystem_ids: ["git"],
});
const aws = protectionModuleFixture({
  extension_id: "command.cloud.aws",
  name: "AWS",
  description: "Reviews AWS CLI deletions.",
  trust_class: "first-party",
  executables: ["aws"],
  ecosystem_ids: ["aws"],
  action_classes: ["cloud.delete"],
});
const filesystemMcp = protectionModuleFixture({
  extension_id: "command.mcp-filesystem",
  name: "Filesystem MCP",
  description: "Reviews official filesystem MCP tools.",
  trust_class: "external",
  surface: "mcp",
  executables: ["npx"],
  ecosystem_ids: [],
  action_classes: ["mcp filesystem tool"],
});
const trustedLib = protectionModuleFixture({
  extension_id: "command.package.node",
  name: "Node package",
  description: "Protects npm installs and supply-chain changes.",
  trust_class: "trusted-library",
  executables: ["npm"],
  ecosystem_ids: ["npm"],
  action_classes: ["package.install"],
  risk_classes: ["supply-chain"],
});
const catalog = [git, aws, filesystemMcp, trustedLib];

assert.equal(catalogFiltersActive(EMPTY_CATALOG_FILTERS), false);
assert.equal(catalogFiltersActive({ ...EMPTY_CATALOG_FILTERS, trusts: ["external"] }), true);
assert.equal(catalogTrustLabel("first-party"), "Built in");
assert.equal(catalogTrustLabel("trusted-library"), "Trusted");
assert.equal(catalogTrustLabel("external"), "External");
assert.equal(catalogKindLabel("commands"), "Commands");
assert.equal(catalogKindLabel("mcp"), "MCP");
assert.deepEqual(CATALOG_TRUST_FILTERS, ["first-party", "trusted-library", "external"]);
assert.deepEqual(CATALOG_KIND_FILTERS, ["commands", "mcp"]);

assert.deepEqual(toggleCatalogFilterValue([], "external"), ["external"]);
assert.deepEqual(toggleCatalogFilterValue(["external"], "external"), []);
assert.deepEqual(toggleCatalogFilterValue(["external"], "first-party"), ["external", "first-party"]);

assert.equal(catalogItemMatchesFilters(filesystemMcp, EMPTY_CATALOG_FILTERS), true);
assert.equal(catalogItemMatchesFilters(filesystemMcp, { ...EMPTY_CATALOG_FILTERS, trusts: ["external"] }), true);
assert.equal(catalogItemMatchesFilters(git, { ...EMPTY_CATALOG_FILTERS, trusts: ["external"] }), false);
assert.equal(catalogItemMatchesFilters(filesystemMcp, { ...EMPTY_CATALOG_FILTERS, kinds: ["mcp"] }), true);
assert.equal(catalogItemMatchesFilters(git, { ...EMPTY_CATALOG_FILTERS, kinds: ["mcp"] }), false);
assert.equal(catalogItemMatchesFilters(aws, { ...EMPTY_CATALOG_FILTERS, areas: ["cloud-infrastructure"] }), true);
assert.equal(catalogItemMatchesFilters(git, { ...EMPTY_CATALOG_FILTERS, areas: ["cloud-infrastructure"] }), false);

const externalOnly = filterCatalogExtensions(catalog, { ...EMPTY_CATALOG_FILTERS, trusts: ["external"] });
assert.deepEqual(externalOnly.map((item) => item.extension_id), ["command.mcp-filesystem"]);

const mcpAndCommands = filterCatalogExtensions(catalog, {
  ...EMPTY_CATALOG_FILTERS,
  kinds: ["mcp", "commands"],
});
assert.equal(mcpAndCommands.length, 4);

const cloudExternal = filterCatalogExtensions(catalog, {
  trusts: ["external"],
  kinds: [],
  areas: ["cloud-infrastructure"],
});
assert.equal(cloudExternal.length, 0, "AND across groups yields no cloud+external tools in this fixture");

assert.equal(customItemMatchesKind({ surface: "mcp" }, []), true);
assert.equal(customItemMatchesKind({ surface: "mcp" }, ["mcp"]), true);
assert.equal(customItemMatchesKind({ surface: "cli" }, ["mcp"]), false);
assert.equal(customItemMatchesKind({ surface: "package-scripts" }, ["commands"]), true);
assert.equal(customItemMatchesFilters({ surface: "mcp" }, EMPTY_CATALOG_FILTERS), true);
assert.equal(customItemMatchesFilters({ surface: "mcp" }, { ...EMPTY_CATALOG_FILTERS, kinds: ["mcp"] }), true);
assert.equal(customItemMatchesFilters({ surface: "cli" }, { ...EMPTY_CATALOG_FILTERS, kinds: ["mcp"] }), false);
assert.equal(customItemMatchesFilters({ surface: "mcp" }, { ...EMPTY_CATALOG_FILTERS, trusts: ["external"] }), false);
assert.equal(customItemMatchesFilters({ surface: "cli" }, { ...EMPTY_CATALOG_FILTERS, areas: ["cloud-infrastructure"] }), false);

const stale = {
  trusts: ["external", "first-party"] as const,
  kinds: ["mcp", "commands"] as const,
  areas: ["cloud-infrastructure", "ai-workflows"] as const,
};
const pruned = pruneCatalogFilters({
  trusts: [...stale.trusts],
  kinds: [...stale.kinds],
  areas: [...stale.areas],
}, [git, aws]);
assert.deepEqual(pruned.trusts, ["first-party"]);
assert.deepEqual(pruned.kinds, ["commands"]);
assert.deepEqual(pruned.areas, ["cloud-infrastructure"]);
assert.equal(catalogFiltersEqual(pruned, pruned), true);
assert.equal(catalogFiltersEqual(pruned, EMPTY_CATALOG_FILTERS), false);

assert.equal(catalogFilterCountCopy(66, 66, false), "66 tools");
assert.equal(catalogFilterCountCopy(1, 1, false), "1 tool");
assert.equal(catalogFilterCountCopy(3, 66, true), "3 of 66 tools");
assert.equal(catalogFilterCountCopy(0, 66, true), "0 of 66 tools");
assert.equal(catalogFilterChipAriaLabel("MCP", 1), "MCP, 1 tool");
assert.equal(catalogFilterChipAriaLabel("External", 7), "External, 7 tools");

assert.ok(populatedCatalogAreas(catalog).includes("source-control"));
assert.ok(populatedCatalogAreas(catalog).includes("cloud-infrastructure"));
assert.ok(populatedCatalogAreas(catalog).includes("files-secrets"));
assert.ok(populatedCatalogAreaOptions(catalog).some((area) => area.id === "cloud-infrastructure" && area.label === "Cloud and infrastructure"));
assert.equal(
  catalogFilterChipCount(catalog, EMPTY_CATALOG_FILTERS, { trusts: ["external"] }),
  1,
);
assert.equal(
  catalogFilterChipCount(catalog, { ...EMPTY_CATALOG_FILTERS, kinds: ["commands"] }, { trusts: ["external"] }),
  0,
);

console.log("catalog-filters.test.ts: all assertions passed");
