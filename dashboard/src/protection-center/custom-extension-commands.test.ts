import assert from "node:assert/strict";

import { commandStatesPayload, withCommandState } from "./custom-extension-commands";
import type { LocalCliCommand } from "../local-cli-api";

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

console.log("custom-extension-commands.test.ts: all assertions passed");
