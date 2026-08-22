import assert from "node:assert/strict";

import type { LocalCliItem } from "../local-cli-api";
import {
  addDialogSubmitLabel,
  dialogIntro,
  filterCountCopy,
  suggestionSummary,
} from "./add-custom-extension-support";

const packageItem: LocalCliItem = {
  cli_id: "local-cli.pkg-demo-abcdef12",
  name: "demo-app",
  kind: "script",
  identity_hash: "a".repeat(64),
  example_label: "pnpm run",
  interpreter_name: "pnpm",
  observed_count: 2,
  last_seen_at: "2026-08-21T00:00:00Z",
  source_path: "user-tool",
  help_status: "ok",
  surface: "package-scripts",
  server_identity_hash: null,
  source_label: "ads-app",
  state: "unset",
  stale: false,
  grant_revision: null,
  authority_revision: 1,
  suggestable: true,
  suggestion_score: 100,
  commands: [
    {
      command_id: "guard.audit",
      name: "guard:audit",
      usage: "pnpm run guard:audit",
      description: "audit",
      parent_id: "guard",
      state: "inherit",
    },
  ],
};

assert.equal(
  dialogIntro(true, true),
  "Confirm these project scripts, or type a nested name to find one fast.",
);
assert.match(filterCountCopy(1, 8), /Showing 1 of 8/);
assert.match(suggestionSummary(packageItem), /Ready to enroll 1 script from ads-app/);
assert.equal(
  addDialogSubmitLabel({ recognized: packageItem, busy: false, pending: "allowed" }),
  "Allow these scripts",
);

console.log("add-custom-extension-support.test.ts: all assertions passed");
