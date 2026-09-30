import assert from "node:assert/strict";

import type { LocalCliCommand, LocalCliItem } from "../local-cli-api";
import { normalizeLocalCliItem } from "../local-cli-api";
import { commandPermissionChanges, mcpCatalogCopy, mcpToolCanReceiveDirectAllow, rebaseCommandDraft } from "./mcp-catalog-state";
import { commandNestingDepth, commandRowUsage, commandStatesPayload, withCommandState } from "./custom-extension-commands";
import { customExtensionStateLabel } from "./local-clis-panel";

{
  const catalog = {
    complete: true, stale: false, reason: null, pages: 1, listed_count: 2, known_count: 2,
    protocol_version: "2026-07-28", revision: 1,
    updated_at: "2026-09-27T12:00:00Z", last_complete_at: "2026-09-27T12:00:00Z",
  };
  function item(metadata: unknown = catalog) {
    return normalizeLocalCliItem({
      cli_id: "local-cli.mcp-fixture", name: "Fixture connector", kind: "executable",
      identity_hash: "a".repeat(64), example_label: "fixture-mcp", observed_count: 1,
      state: "allowed", grant_revision: 1, authority_revision: 7, surface: "mcp", commands: [],
      mcp_catalog: metadata,
    });
  }
  assert.equal(mcpCatalogCopy(item())?.title, "2 tools listed");
  const expired = item({ ...catalog, fresh_until: "2020-01-01T00:00:00Z", cache_scope: "private" });
  assert.equal(mcpCatalogCopy(expired)?.title, "2 tools cached · Refresh available");
  assert.equal(expired.state, "allowed");
  assert.equal(expired.authority_revision, 7);
  assert.equal(expired.grant_revision, 1);
  assert.equal(mcpCatalogCopy(item({
    ...catalog, complete: false, reason: "catalog_changed",
  }))?.title, "Inventory changed during discovery");
  const partial = item({ ...catalog, complete: false, stale: true, reason: "list_failed", listed_count: 1, known_count: 3 });
  assert.equal(mcpCatalogCopy(partial)?.title, "3 tools cached · Refresh failed");
  assert.equal(partial.authority_revision, 7);
  assert.equal(partial.grant_revision, 1);
  const changes = { added: ["search", "search"], changed: ["read"], removed: ["delete"], stale: [] };
  assert.deepEqual(item({ ...catalog, changes }).mcp_catalog?.changes, {
    ...changes, added: ["search"],
  });
  for (const invalidChanges of [
    { ...changes, removed: "delete" }, { ...changes, added: [null] },
    { ...changes, changed: [" read "] }, { ...changes, stale: ["x".repeat(257)] },
  ]) {
    assert.equal(item({ ...catalog, changes: invalidChanges }).mcp_catalog?.changes, undefined);
  }
  assert.equal(mcpCatalogCopy(item(null))?.title, "Inventory not checked");
  assert.equal(mcpCatalogCopy({ ...item(), surface: "cli" }), null);
  for (const invalid of [
    { ...catalog, known_count: -1 }, { ...catalog, known_count: 10_001 },
    { ...catalog, listed_count: 3 }, { ...catalog, revision: 0 },
    { ...catalog, updated_at: "not-a-date" }, { ...catalog, reason: "list_failed" },
  ]) {
    const normalized = item(invalid);
    assert.equal(normalized.mcp_catalog, undefined);
    assert.equal(normalized.cli_id, "local-cli.mcp-fixture");
  }
  function command(id: string, state: LocalCliCommand["state"] = "inherit"): LocalCliCommand {
    return { command_id: id, name: id, usage: id, description: "Fixture tool", parent_id: null, state };
  }
  const previous = [command("read"), command("delete", "block")];
  assert.equal(mcpToolCanReceiveDirectAllow(command("read")), true);
  assert.equal(mcpToolCanReceiveDirectAllow(command("other")), false);
  for (const name of ["composio_multi_execute_tool", "composio_remote_workbench", "composio_remote_bash_tool"]) {
    assert.equal(mcpToolCanReceiveDirectAllow({ ...command(name), usage: `mcp__codex_apps__composio__${name}` }), false);
  }
  assert.equal(commandStatesPayload([command("read", "review")])[0].state, "review");
  const current = [command("read", "allow"), command("delete", "block")];
  const next = [command("delete", "block"), command("search"), { ...command("read"), description: "New metadata" }];
  assert.deepEqual(rebaseCommandDraft(current, previous, next).map(({ command_id, state }) => [command_id, state]), [
    ["delete", "block"], ["search", "inherit"], ["read", "allow"],
  ]);
  assert.equal(rebaseCommandDraft(current, previous, next)[2].description, "New metadata");
  assert.deepEqual(rebaseCommandDraft(previous, previous, [command("read", "block")]), [command("read", "block")]);
  assert.deepEqual(rebaseCommandDraft(current, previous, [command("search")]), [command("search")]);
  assert.equal(rebaseCommandDraft(current, previous, next, ["read"])[2].state, "inherit");
  const deniedDraft = [command("read", "block"), command("delete", "block")];
  assert.equal(rebaseCommandDraft(deniedDraft, previous, next, ["read"])[2].state, "block");
  assert.deepEqual(commandPermissionChanges(previous, [previous[1], previous[0]]), []);
  assert.deepEqual(commandPermissionChanges(previous, current), [
    { commandId: "read", name: "read", before: "inherit", after: "allow" },
  ]);
}

const commands: LocalCliCommand[] = [
  {
    command_id: "deploy",
    name: "deploy",
    usage: "deploy",
    description: "Deploy the worker",
    parent_id: null,
    state: "inherit",
  },
  {
    command_id: "other",
    name: "Other commands",
    usage: "tool …",
    description: "Anything else",
    parent_id: null,
    state: "inherit",
  },
];

const updated = withCommandState(commands, "deploy", "allow");
assert.equal(updated[0]?.state, "allow");
assert.equal(updated[1]?.state, "inherit");
assert.deepEqual(commandStatesPayload(updated), [
  { command_id: "deploy", state: "allow" },
  { command_id: "other", state: "inherit" },
]);

const legacyAllowed: LocalCliItem = {
  cli_id: "local-cli.ship-abcdef12",
  name: "ship",
  kind: "executable",
  identity_hash: "b".repeat(64),
  example_label: "ship",
  interpreter_name: null,
  observed_count: 1,
  last_seen_at: null,
  source_path: null,
  help_status: null,
  surface: "cli",
  server_identity_hash: null,
  source_label: null,
  state: "allowed",
  stale: false,
  grant_revision: 1,
  authority_revision: 1,
  suggestable: true,
  commands: [],
};
assert.equal(customExtensionStateLabel(legacyAllowed), "Matching commands from this file are allowed.");
assert.match(
  customExtensionStateLabel({
    ...legacyAllowed,
    commands: [{ ...commands[0]!, state: "inherit" }],
  }),
  /Recommended/,
);
assert.equal(
  customExtensionStateLabel({
    ...legacyAllowed,
    surface: "mcp",
    state: "blocked",
  }),
  "Every tool from this server is blocked.",
);

assert.equal(
  commandNestingDepth({
    command_id: "guard.reddit-targeting.audit",
    name: "guard:reddit-targeting:audit",
    usage: "pnpm run guard:reddit-targeting:audit",
    description: "audit",
    parent_id: "guard.reddit-targeting",
    state: "inherit",
  }),
  2,
);

assert.equal(commandRowUsage("click", "click"), null);
assert.equal(commandRowUsage("deploy", "pnpm run deploy"), "pnpm run deploy");

console.log("custom-extension-commands.test.ts: all assertions passed");
