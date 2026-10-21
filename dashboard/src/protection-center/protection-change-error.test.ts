import assert from "node:assert/strict";

import { ExtensionControlApiError } from "../extension-controls-api";
import { isRetryableProtectionChangeError, protectionChangeErrorMessage } from "./protection-change-error";

// Every code the daemon's extension-control API can answer a mutation with.
const CODES = [
  "approval_required",
  "authority_apply_failed",
  "authority_conflict",
  "authority_history_unavailable",
  "authority_not_degraded",
  "authority_not_recoverable",
  "authority_recovery_failed",
  "authority_recovery_incomplete",
  "authority_unavailable",
  "authority_unread",
  "catalog_conflict",
  "catalog_payload_limit_exceeded",
  "control_limit_exceeded",
  "duplicate_control_target",
  "extension_control_stopped",
  "immutable_extension",
  "immutable_permission",
  "invalid_extension",
  "invalid_inspection_command",
  "invalid_layers",
  "invalid_mutation",
  "invalid_previous_revision",
  "invalid_test_command",
  "layer_control_limit_exceeded",
  "layer_limit_exceeded",
  "managed_layer_conflict",
  "managed_layer_mutation",
  "pack_preparation_unavailable",
  "prepared_preview_expired",
  "proof_invalid",
  "proof_mismatch",
  "proof_not_found",
  "revision_conflict",
  "unknown_extension",
  "unknown_permission",
  "a_code_this_build_has_never_seen",
];

// Every cause `classify` in the daemon can attach, plus one this build has
// never seen.
const CAUSES = [
  undefined,
  "installed_runtime_incomplete",
  "installed_runtime_unresponsive",
  "internal",
  "local_storage",
  "offline",
  "pack_authority_unavailable",
  "pack_revoked",
  "release_unavailable",
  "surprise",
];

function apiError(code: string, cause?: string): ExtensionControlApiError {
  return new ExtensionControlApiError(code, 503, code, "retry_pack_preparation", cause);
}

// No protocol token and no recovery token ever reaches the screen, whatever the
// daemon answered with.
for (const code of CODES) {
  const message = protectionChangeErrorMessage(apiError(code));
  assert.ok(!message.includes(code), `raw code leaked for ${code}`);
  assert.ok(!/\b[a-z]+(_[a-z]+){2,}\b/.test(message), `snake_case token leaked for ${code}: ${message}`);
  assert.ok(message.endsWith("."), `message for ${code} is not a sentence: ${message}`);
}

// Preparation runs before the daemon commits anything, so every one of its
// causes can say the existing protection survived, and each says what to do.
for (const cause of CAUSES) {
  const message = protectionChangeErrorMessage(apiError("pack_preparation_unavailable", cause));
  assert.match(message, /current protection is unchanged/);
  assert.match(message, /try again/i);
}

assert.match(
  protectionChangeErrorMessage(apiError("pack_preparation_unavailable", "offline")),
  /could not reach the protection release service/,
);
assert.match(
  protectionChangeErrorMessage(apiError("pack_preparation_unavailable", "release_unavailable")),
  /not available yet/,
);
assert.match(
  protectionChangeErrorMessage(apiError("pack_preparation_unavailable", "pack_revoked")),
  /was withdrawn/,
);
assert.match(
  protectionChangeErrorMessage(apiError("pack_preparation_unavailable", "installed_runtime_incomplete")),
  /Reinstall or update Guard/,
);
// A compiler that would not start or ran out of time is not a broken install,
// so it must not ask for a reinstall.
const unresponsive = protectionChangeErrorMessage(
  apiError("pack_preparation_unavailable", "installed_runtime_unresponsive"),
);
assert.match(unresponsive, /did not answer in time/);
assert.ok(!/Reinstall/.test(unresponsive));
assert.match(
  protectionChangeErrorMessage(apiError("pack_preparation_unavailable", "local_storage")),
  /local protection cache/,
);

// The authority recovery command and its shell come from the daemon.
const authority = protectionChangeErrorMessage(
  apiError("authority_unavailable"),
  "hol-guard command controls recover-authority --home C:\\Guard",
  "powershell",
);
assert.match(authority, /hol-guard command controls recover-authority --home C:\\Guard/);
assert.match(authority, /in PowerShell/);
assert.match(protectionChangeErrorMessage(apiError("authority_unavailable")), /in your terminal/);

// Preparation reaches the pack-lifecycle authority, which `recover-authority`
// refuses to touch while the control authority is protected. That cause must
// not send anyone to that command.
const packAuthority = protectionChangeErrorMessage(
  apiError("pack_preparation_unavailable", "pack_authority_unavailable"),
  "hol-guard command controls recover-authority",
);
assert.ok(!packAuthority.includes("recover-authority"), packAuthority);
assert.match(packAuthority, /Update Guard, or reconnect this machine/);

// A write that may already have committed, and an answer this build cannot
// read, must not claim the change was dropped.
for (const code of ["authority_apply_failed", "a_code_this_build_has_never_seen"]) {
  const message = protectionChangeErrorMessage(apiError(code));
  assert.ok(!message.includes("current protection is unchanged"), `${code}: ${message}`);
  assert.match(message, /may or may not have been saved/);
  assert.match(message, /Reload the page/);
}

// Managed settings and stale pages say what is actually wrong.
assert.match(protectionChangeErrorMessage(apiError("managed_layer_mutation")), /managed for you by your organization/);
assert.match(protectionChangeErrorMessage(apiError("revision_conflict")), /Reload the page/);
assert.match(protectionChangeErrorMessage(apiError("approval_required")), /approval password/);

// Errors that are not control-API failures keep their own message.
assert.equal(
  protectionChangeErrorMessage(new Error("Guard did not issue a one-use proof.")),
  "Guard did not issue a one-use proof.",
);
assert.equal(protectionChangeErrorMessage("not an error"), "Protection change failed");

// The dashboard retries the save itself for the causes that clear on their
// own, so the common failure never becomes a sentence the operator must act on.
for (const cause of ["offline", "release_unavailable", "local_storage", "installed_runtime_unresponsive"]) {
  assert.ok(isRetryableProtectionChangeError(apiError("pack_preparation_unavailable", cause)), cause);
}
// A withdrawn pack, a broken install and a protected authority never clear by
// themselves, so retrying them would only hide the real next step.
for (const cause of [undefined, "pack_revoked", "installed_runtime_incomplete", "pack_authority_unavailable", "internal"]) {
  assert.ok(!isRetryableProtectionChangeError(apiError("pack_preparation_unavailable", cause)), String(cause));
}
// A conflict is a different save, not the same one, so it is never retried.
assert.ok(!isRetryableProtectionChangeError(apiError("revision_conflict", "offline")));
assert.ok(!isRetryableProtectionChangeError(new Error("offline")));

console.log("protection-change-error ok");
