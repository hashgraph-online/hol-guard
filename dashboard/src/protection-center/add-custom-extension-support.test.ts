import assert from "node:assert/strict";

import type { LocalCliItem } from "../local-cli-api";
import {
  addDialogSubmitLabel,
  dialogIntro,
  enrollConfirmCopy,
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

assert.match(dialogIntro(true, "package-scripts"), /Allow these scripts/);
assert.match(dialogIntro(false, "mcp"), /Allow all/);
assert.match(dialogIntro(false, null, true), /Looking for project scripts/);
assert.match(filterCountCopy(1, 8), /1 of 8 scripts match/);
assert.match(suggestionSummary(packageItem), /1 script from ads-app/);
assert.equal(
  addDialogSubmitLabel({ recognized: packageItem, busy: false, pending: "allowed" }),
  "Continue",
);
assert.equal(
  addDialogSubmitLabel({ recognized: packageItem, busy: false, pending: "allowed", step: "confirm" }),
  "Allow these scripts",
);
assert.match(enrollConfirmCopy("mcp", true, true), /Recently confirmed/);
assert.match(enrollConfirmCopy("mcp", false, true), /authenticator code/);
assert.match(enrollConfirmCopy("mcp", false, false), /approval password/);

console.log("add-custom-extension-support.test.ts: all assertions passed");
