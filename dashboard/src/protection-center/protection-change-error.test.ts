import assert from "node:assert/strict";

import { ExtensionControlApiError } from "../extension-controls-api";
import {
  authorityRecoverySentence,
  isRetryableProtectionChangeError,
  isStaleProtectionDataError,
  knownProtectionChangeMessage,
  protectionChangeErrorMessage,
} from "./protection-change-error";

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
  "native_request_too_large",
  "offline",
  "pack_authority_unavailable",
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
// A request the runtime will not read is the one cause a retry cannot clear,
// so it is the one that must not end in "try again"; it still has to say what
// the operator can look at, which the assertions further down pin down.
for (const cause of CAUSES) {
  const message = protectionChangeErrorMessage(apiError("pack_preparation_unavailable", cause));
  assert.match(message, /current protection is unchanged/);
  if (cause !== "native_request_too_large") {
    assert.match(message, /try again/i);
  }
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
// A request the runtime will not read is not a broken install either, and it
// is the one preparation failure a retry cannot clear, so the sentence has to
// rule both of those out rather than leave the operator guessing.
const tooLarge = protectionChangeErrorMessage(
  apiError("pack_preparation_unavailable", "native_request_too_large"),
);
assert.match(tooLarge, /grown past/);
assert.match(tooLarge, /reinstalling Guard will not change it/);
assert.match(tooLarge, /Retrying sends the same request again/);
assert.match(tooLarge, /daemon log records the request that grew and how far past the bound it got/);
assert.doesNotMatch(tooLarge, /Reinstall or update Guard/);
// No local command prunes the state this request is built from, so naming one
// would swap a reinstall dead end for a recover-authority dead end.
assert.doesNotMatch(tooLarge, /hol-guard command controls/);
assert.doesNotMatch(tooLarge, /try again/);

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
// A stale page says it now shows current data only once that reload landed;
// a reload that failed leaves the operator with the old instruction.
for (const code of ["revision_conflict", "catalog_conflict", "unknown_extension"]) {
  const reloaded = protectionChangeErrorMessage(apiError(code), undefined, undefined, { reloaded: true });
  assert.match(reloaded, /This page now shows/, `${code}: ${reloaded}`);
  assert.ok(!/Reload the page/.test(reloaded), `${code}: ${reloaded}`);
  const notReloaded = protectionChangeErrorMessage(apiError(code));
  assert.match(notReloaded, /Reload the page/, `${code}: ${notReloaded}`);
  assert.ok(!/now shows/.test(notReloaded), `${code}: ${notReloaded}`);
}
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
for (const cause of [
  undefined,
  "pack_revoked",
  "installed_runtime_incomplete",
  "native_request_too_large",
  "pack_authority_unavailable",
  "internal",
]) {
  assert.ok(!isRetryableProtectionChangeError(apiError("pack_preparation_unavailable", cause)), String(cause));
}
// A conflict is a different save, not the same one, so it is never retried.
assert.ok(!isRetryableProtectionChangeError(apiError("revision_conflict", "offline")));
assert.ok(!isRetryableProtectionChangeError(new Error("offline")));

// The daemon owns which catalog and which revision a mutation may carry, and
// it refuses one that does not match. The page reloads itself on those codes,
// so the sentence the operator reads is true by the time they read it and
// their next attempt is made against current data. Nothing is replayed: what
// they approved was approved against the catalog the page then held.
for (const code of [
  "authority_conflict",
  "catalog_conflict",
  "invalid_extension",
  "invalid_previous_revision",
  "revision_conflict",
  "unknown_extension",
  "unknown_permission",
]) {
  assert.ok(isStaleProtectionDataError(apiError(code)), code);
  assert.doesNotMatch(protectionChangeErrorMessage(apiError(code), undefined, undefined, { reloaded: true }), /Reload (the|this) page/, code);
}
// A failure that says nothing about staleness must not trigger a reload: the
// operator's unsaved state is worth more than a speculative refresh.
for (const code of ["approval_required", "authority_apply_failed", "control_limit_exceeded", "proof_invalid"]) {
  assert.ok(!isStaleProtectionDataError(apiError(code)), code);
}
assert.ok(!isStaleProtectionDataError(new Error("catalog_conflict")));

// A failure before anything is written has no uncertain outcome to report:
// unknown codes and code-less protocol errors get no sentence here, so a
// preview never claims the change may have been saved.
const unavailable = new ExtensionControlApiError("authority_unavailable", 503, "authority_unavailable");
assert.match(knownProtectionChangeMessage(unavailable) ?? "", /could not open its local protection authority/);
assert.equal(knownProtectionChangeMessage(new ExtensionControlApiError("future_code", 500, "future_code")), undefined);
assert.equal(knownProtectionChangeMessage(new ExtensionControlApiError("Guard returned invalid JSON (500)", 500)), undefined);
assert.equal(knownProtectionChangeMessage(new Error("authority_unavailable")), undefined);

// A read names the repair without saying anything about a save.
const readRecovery = authorityRecoverySentence(unavailable, "C:\\Guard\\hol-guard.exe command controls recover-authority", "powershell") ?? "";
assert.match(readRecovery, /C:\\Guard\\hol-guard\.exe command controls recover-authority/);
assert.match(readRecovery, /PowerShell/);
assert.doesNotMatch(readRecovery, /sav/);
assert.equal(authorityRecoverySentence(new ExtensionControlApiError("revision_conflict", 409, "revision_conflict")), undefined);

console.log("protection-change-error ok");
