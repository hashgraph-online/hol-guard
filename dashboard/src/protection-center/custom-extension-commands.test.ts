import assert from "node:assert/strict";

import type { LocalCliCommand, LocalCliItem } from "../local-cli-api";
import { commandNestingDepth, commandStatesPayload, withCommandState } from "./custom-extension-commands";
import { customExtensionStateLabel } from "./local-clis-panel";

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

console.log("custom-extension-commands.test.ts: all assertions passed");
