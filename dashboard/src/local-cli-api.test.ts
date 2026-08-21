import assert from "node:assert/strict";

import {
  addedCustomExtensions,
  filterExtensionSuggestions,
  isLocalCliId,
  normalizeLocalCliItem,
  normalizeLocalCliList,
  seenSuggestionMeta,
  suggestedCustomExtensions,
  looksLikePackageScriptPaste,
  suggestedHarnessExtensions,
  suggestedPackageScriptExtensions,
  suggestedSeenExtensions,
} from "./local-cli-api";
import { parseProtectionRoute, localCliHref } from "./local-cli-links";

assert.equal(isLocalCliId("local-cli.cwv-py-abcdef12"), true);
assert.equal(isLocalCliId("command.git"), false);

const item = normalizeLocalCliItem({
  cli_id: "local-cli.cwv-py-abcdef12",
  name: "cwv.py",
  kind: "script",
  identity_hash: "a".repeat(64),
  example_label: "python3 cwv.py",
  interpreter_name: "python3",
  observed_count: 3,
  last_seen_at: "2026-08-16T00:00:00Z",
  state: "allowed",
  stale: false,
  grant_revision: 1,
  authority_revision: 1,
  suggestable: true,
  commands: [
    {
      command_id: "root",
      name: "cwv.py",
      usage: "cwv.py",
      description: "Run cwv.py without a subcommand.",
      parent_id: null,
      state: "inherit",
    },
  ],
});
assert.equal(item.name, "cwv.py");
assert.equal(item.state, "allowed");
assert.equal(item.surface, "cli");
assert.equal(item.server_identity_hash, null);
assert.equal(item.source_label, null);
assert.equal(item.commands[0]?.command_id, "root");

const mcpItem = normalizeLocalCliItem({
  ...item,
  cli_id: "local-cli.mcp-abcdef12",
  name: "@modelcontextprotocol/server-github",
  kind: "executable",
  example_label: "npx -y @modelcontextprotocol/server-github",
  interpreter_name: null,
  surface: "mcp",
  server_identity_hash: "b".repeat(64),
  commands: [
    {
      command_id: "read-file",
      name: "read_file",
      usage: "read_file",
      description: "Read a file",
      parent_id: null,
      state: "allow",
    },
  ],
});
assert.equal(mcpItem.surface, "mcp");
assert.equal(mcpItem.server_identity_hash, "b".repeat(64));
assert.equal(
  normalizeLocalCliItem({ ...mcpItem, source_label: "Codex, Claude Code" }).source_label,
  "Codex, Claude Code",
);
assert.equal(isLocalCliId(mcpItem.cli_id), true);
assert.equal(
  normalizeLocalCliItem({ ...mcpItem, server_identity_hash: "not-a-hash" }).server_identity_hash,
  null,
);

const list = normalizeLocalCliList({
  schema_version: "guard.daemon.local-clis.v1",
  revision: 1,
  items: [item],
  cloud: { sync_local_only: true, summary: "This device only." },
});
assert.equal(list.items.length, 1);
assert.equal(list.cloud.sync_local_only, true);

assert.deepEqual(parseProtectionRoute("/extensions/local-cli/local-cli.cwv-py-abcdef12"), {
  kind: "local-cli",
  cliId: "local-cli.cwv-py-abcdef12",
});
assert.equal(parseProtectionRoute("/extensions/command.git").kind, "detail");
assert.equal(localCliHref("local-cli.cwv-py-abcdef12"), "/extensions/local-cli/local-cli.cwv-py-abcdef12");
assert.equal(addedCustomExtensions(list.items).length, 1);
assert.equal(suggestedCustomExtensions(list.items).length, 0);

const blockedItem = normalizeLocalCliItem({
  ...item,
  cli_id: "local-cli.blocked-tool-abcdef12",
  name: "blocked-tool",
  state: "blocked",
});
const unsetItem = normalizeLocalCliItem({
  ...item,
  cli_id: "local-cli.unset-tool-abcdef12",
  name: "unset-tool",
  state: "unset",
  grant_revision: null,
  suggestable: true,
});
const grepItem = normalizeLocalCliItem({
  ...item,
  cli_id: "local-cli.grep-abcdef12",
  name: "grep",
  kind: "executable",
  example_label: "grep",
  state: "unset",
  grant_revision: null,
  suggestable: false,
});
const mixed = [item, blockedItem, unsetItem, grepItem];
assert.deepEqual(addedCustomExtensions(mixed).map((entry) => entry.state), ["allowed", "blocked"]);
assert.deepEqual(suggestedCustomExtensions(mixed).map((entry) => entry.name), ["unset-tool"]);
const harnessUnset = normalizeLocalCliItem({
  ...unsetItem,
  cli_id: "local-cli.mcp-abcdef12",
  name: "github",
  surface: "mcp",
  source_label: "Codex",
});
assert.deepEqual(suggestedHarnessExtensions([unsetItem, harnessUnset]).map((entry) => entry.name), ["github"]);
assert.deepEqual(suggestedSeenExtensions([unsetItem, harnessUnset]).map((entry) => entry.name), ["unset-tool"]);
const packageScripts = normalizeLocalCliItem({
  ...unsetItem,
  cli_id: "local-cli.pkg-demo-abcdef12",
  name: "demo-app",
  example_label: "pnpm run",
  surface: "package-scripts",
  suggestable: true,
});
assert.equal(packageScripts.surface, "package-scripts");
assert.deepEqual(suggestedPackageScriptExtensions([unsetItem, packageScripts]).map((entry) => entry.name), ["demo-app"]);
assert.deepEqual(suggestedSeenExtensions([unsetItem, packageScripts]).map((entry) => entry.name), ["unset-tool"]);
assert.equal(looksLikePackageScriptPaste("npm run guard:audit"), true);
assert.equal(looksLikePackageScriptPaste("pnpm run"), true);
assert.equal(looksLikePackageScriptPaste("npx -y server"), false);
assert.equal(looksLikePackageScriptPaste("npm"), false);

const recentJunk = normalizeLocalCliItem({
  ...unsetItem,
  cli_id: "local-cli.rg-abcdef12",
  name: "rg",
  kind: "executable",
  example_label: "rg",
  observed_count: 9,
  last_seen_at: "2026-08-18T12:00:00Z",
  suggestable: false,
});
const frequentTool = normalizeLocalCliItem({
  ...unsetItem,
  cli_id: "local-cli.cwv-py-bbbbbb12",
  name: "cwv.py",
  example_label: "python3 cwv.py",
  observed_count: 4,
  last_seen_at: "2026-08-18T11:00:00Z",
  suggestable: true,
  suggestion_score: 40,
});
const rareTool = normalizeLocalCliItem({
  ...unsetItem,
  cli_id: "local-cli.ship-it-cccccccc",
  name: "ship-it",
  example_label: "ship-it",
  observed_count: 1,
  last_seen_at: "2026-08-18T12:30:00Z",
  suggestable: true,
  suggestion_score: 30,
});
const frequentGeneric = normalizeLocalCliItem({
  ...unsetItem,
  cli_id: "local-cli.foo-dddddddd",
  name: "foo",
  example_label: "foo",
  observed_count: 12,
  last_seen_at: "2026-08-18T13:00:00Z",
  suggestable: true,
  suggestion_score: 20,
});
assert.deepEqual(
  suggestedSeenExtensions([recentJunk, frequentGeneric, rareTool, frequentTool, harnessUnset]).map((entry) => entry.name),
  ["cwv.py", "ship-it", "foo"],
);
assert.deepEqual(
  filterExtensionSuggestions(suggestedSeenExtensions([frequentTool, rareTool]), "cwv").map((entry) => entry.name),
  ["cwv.py"],
);
assert.deepEqual(
  filterExtensionSuggestions([recentJunk], "rg").map((entry) => entry.name),
  ["rg"],
);
assert.equal(seenSuggestionMeta(frequentTool), "Seen 4 times");
assert.equal(seenSuggestionMeta(rareTool), "Seen once");

const fallbackCloud = normalizeLocalCliList({
  schema_version: "guard.daemon.local-clis.v1",
  revision: 1,
  items: [],
});
assert.equal(
  fallbackCloud.cloud.summary,
  "Custom extensions stay on this device. Guard Cloud can keep the same extension on your other machines.",
);
