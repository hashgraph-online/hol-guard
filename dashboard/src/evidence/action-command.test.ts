import assert from "node:assert/strict";
import type { GuardActionEnvelope, GuardReceipt } from "../guard-types";
import { resolveActionCommand, resolveActionDetail, resolveActionSubtitle, resolveActionTitle } from "./plain-english";

const receipt: GuardReceipt = {
  receipt_id: "example", harness: "bun", artifact_id: "example", artifact_hash: "example",
  policy_decision: "allow", capabilities_summary: "bun custom", changed_capabilities: [],
  provenance_summary: "bun test example.test.ts", artifact_name: "bun", user_override: null,
  source_scope: null, timestamp: "2026-09-10T12:00:00Z",
};
assert.equal(resolveActionCommand(receipt), "bun test example.test.ts");
assert.equal(resolveActionTitle(receipt), "bun test example.test.ts");
assert.equal(resolveActionCommand({ ...receipt, provenance_summary: "hook event for bun" }), null);
assert.equal(resolveActionCommand({ ...receipt, decision_contract_error: "invalid" }), null);
assert.equal(resolveActionCommand({ ...receipt, provenance_summary: "Command details are redacted" }), null);

const shellEnvelope = (command: string): GuardActionEnvelope =>
  ({ action_type: "shell_command", command } as unknown as GuardActionEnvelope);

const credentialCommand =
  "bun run deploy --password synthetic-password-value --credential='synthetic credential value' PASSWORD=synthetic-env-value";
const credentialReceipt: GuardReceipt = {
  ...receipt,
  action_envelope_json: shellEnvelope(credentialCommand),
};
const safeCredentialCommand = resolveActionCommand(credentialReceipt);
assert.ok(safeCredentialCommand);
assert.ok(safeCredentialCommand.includes("bun run deploy"), "credential-bearing commands retain their safe command shape");
assert.ok(safeCredentialCommand.includes("[redacted]"), "credential-bearing command values are replaced");
for (const marker of ["synthetic-password-value", "synthetic credential value", "synthetic-env-value"]) {
  assert.ok(!safeCredentialCommand.includes(marker), `command display must not expose ${marker}`);
  assert.ok(!resolveActionTitle(credentialReceipt).includes(marker), `title must not expose ${marker}`);
  assert.ok(!resolveActionDetail(credentialReceipt)?.includes(marker), `detail must not expose ${marker}`);
}

const legacyCredentialReceipt: GuardReceipt = {
  ...receipt,
  capabilities_summary: "",
  provenance_summary: "bun --password synthetic-legacy-password 'PASSWORD=synthetic-legacy-env-value'",
  action_envelope_json: null,
};
const safeLegacyCommand = resolveActionCommand(legacyCredentialReceipt);
assert.ok(safeLegacyCommand);
assert.ok(safeLegacyCommand.includes("bun --password [redacted]"), "legacy provenance retains the command prefix");
for (const marker of ["synthetic-legacy-password", "synthetic-legacy-env-value"]) {
  assert.ok(!safeLegacyCommand.includes(marker), `legacy command display must not expose ${marker}`);
  assert.ok(!resolveActionTitle(legacyCredentialReceipt).includes(marker), `legacy title must not expose ${marker}`);
  assert.ok(!resolveActionSubtitle(legacyCredentialReceipt)?.includes(marker), `legacy subtitle must not expose ${marker}`);
}
