import assert from "node:assert/strict";

import {
  addedCustomExtensions,
  isLocalCliId,
  normalizeLocalCliItem,
  normalizeLocalCliList,
  suggestedCustomExtensions,
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
});
assert.equal(item.name, "cwv.py");
assert.equal(item.state, "allowed");

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

const fallbackCloud = normalizeLocalCliList({
  schema_version: "guard.daemon.local-clis.v1",
  revision: 1,
  items: [],
});
assert.equal(
  fallbackCloud.cloud.summary,
  "Custom extensions stay on this device. Guard Cloud can keep the same extension on your other machines.",
);
