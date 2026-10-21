import { ExtensionControlApiError } from "../extension-controls-api";

/**
 * Protection changes used to surface the daemon's protocol code verbatim, so a
 * failed save read as `pack_preparation_unavailable` with no cause and no next
 * step. Every code the control API can answer with gets a sentence here that
 * says what happened to the existing protection and what to do next, and the
 * fallback never prints a protocol token at a person.
 */

const KEPT = "Guard could not save this protection change, so your current protection is unchanged.";
// Some failures happen after the daemon may already have committed, or lose
// the response to a commit that succeeded. Those must not claim the change was
// dropped; they send the operator to the settings the daemon actually holds.
const UNCERTAIN =
  "Guard could not confirm this protection change, so it may or may not have been saved. Reload the page to see the settings Guard is holding now.";

type Recovery = { command: string; terminal: string };

function preparationSentence(cause: string | undefined, recovery: Recovery): string {
  switch (cause) {
    case "offline":
      return `${KEPT} It could not reach the protection release service. Check this machine's connection and try again.`;
    case "release_unavailable":
      return `${KEPT} The protection release it needs is not available yet. Try again shortly.`;
    case "pack_authority_unavailable":
      return `${KEPT} This install has no protection release it can verify yet. Update Guard, or reconnect this machine so it can fetch one, then try again.`;
    case "installed_runtime_incomplete":
      return `${KEPT} This Guard installation is missing part of its runtime, so it cannot read its own protection bundle. Reinstall or update Guard, then try again.`;
    case "installed_runtime_unresponsive":
      return `${KEPT} Guard's packaged compiler did not answer in time. Try again; if it keeps failing, restart Guard.`;
    case "pack_revoked":
      return `${KEPT} A protection pack it needs was withdrawn. Reload this page to pick up the current catalog, then try again.`;
    case "local_storage":
      return `${KEPT} Guard could not read its local protection cache. Try again; if it keeps failing, run \`${recovery.command}\` in ${recovery.terminal}.`;
    default:
      return `${KEPT} Try again; if it keeps failing, the Guard daemon log records the exact cause.`;
  }
}

function codeSentence(code: string, recovery: Recovery): string | undefined {
  const repairAuthority = `Run \`${recovery.command}\` in ${recovery.terminal}, then try again.`;
  switch (code) {
    case "approval_required":
      return `${KEPT} It needs your approval password before it can apply.`;
    case "authority_apply_failed":
      return `${UNCERTAIN} If the change is not there, ${repairAuthority}`;
    case "authority_conflict":
    case "revision_conflict":
    case "invalid_previous_revision":
      return `${KEPT} Your protection settings changed while this page was open. Reload the page and make the change again.`;
    case "authority_unavailable":
    case "authority_unread":
    case "authority_history_unavailable":
      return `${KEPT} Guard could not open its local protection authority. ${repairAuthority}`;
    case "authority_not_degraded":
      return "This Guard install's protection authority is healthy, so there is nothing to recover.";
    case "authority_not_recoverable":
      return `Guard cannot recover this protection authority automatically. ${repairAuthority}`;
    case "authority_recovery_failed":
    case "authority_recovery_incomplete":
      return `Guard could not finish recovering the protection authority. ${repairAuthority}`;
    case "catalog_conflict":
    case "catalog_payload_limit_exceeded":
      return `${KEPT} Guard's protection catalog moved underneath this page. Reload the page and make the change again.`;
    case "control_limit_exceeded":
    case "layer_control_limit_exceeded":
    case "layer_limit_exceeded":
      return `${KEPT} It would take this install past the number of custom protection settings Guard keeps. Return some settings to Recommended, then try again.`;
    case "duplicate_control_target":
      return `${KEPT} The same setting was changed twice in one save. Reload the page and make the change once.`;
    case "extension_control_stopped":
      return `${KEPT} Guard is shutting down. Start Guard again, then make the change.`;
    case "immutable_extension":
    case "immutable_permission":
    case "managed_layer_mutation":
    case "managed_layer_conflict":
      return `${KEPT} This setting is managed for you by your organization and cannot be changed here.`;
    case "invalid_extension":
    case "unknown_extension":
    case "unknown_permission":
      return `${KEPT} Guard no longer recognizes the setting this page asked to change. Reload the page and try again.`;
    case "invalid_layers":
    case "invalid_mutation":
      return `${KEPT} Guard rejected the change as malformed. Reload the page and make the change again; if it keeps failing, the Guard daemon log records the exact cause.`;
    case "invalid_inspection_command":
    case "invalid_test_command":
      return "Guard could not read that command. Enter the command exactly as you would run it, then check it again.";
    case "pack_preparation_unavailable":
      return undefined; // Refined by cause below.
    case "prepared_preview_expired":
      return `${KEPT} The review you approved has expired. Make the change again and apply it straight away.`;
    case "proof_invalid":
    case "proof_mismatch":
    case "proof_not_found":
      return `${KEPT} The approval for this change was no longer valid. Make the change again and re-enter your approval password.`;
    default:
      return undefined;
  }
}

// Preparation runs before the daemon commits anything, and each of these
// clears on its own: a fetch that missed, a release that had not landed, a busy
// local cache, a compiler that did not answer. Retrying once in the dashboard
// turns the common case back into a save that just works, instead of a sentence
// the operator has to act on.
const RETRYABLE_PREPARATION_CAUSES = new Set([
  "installed_runtime_unresponsive",
  "local_storage",
  "offline",
  "release_unavailable",
]);

export function isRetryableProtectionChangeError(error: unknown): boolean {
  return (
    error instanceof ExtensionControlApiError &&
    error.code === "pack_preparation_unavailable" &&
    RETRYABLE_PREPARATION_CAUSES.has(error.cause ?? "")
  );
}

export function protectionChangeErrorMessage(
  error: unknown,
  recoveryCommand?: string,
  recoveryShell?: "powershell",
): string {
  const recovery: Recovery = {
    command: recoveryCommand ?? "hol-guard command controls recover-authority",
    terminal: recoveryShell === "powershell" ? "PowerShell" : "your terminal",
  };
  if (error instanceof ExtensionControlApiError) {
    if (error.code === "pack_preparation_unavailable") return preparationSentence(error.cause, recovery);
    const sentence = error.code ? codeSentence(error.code, recovery) : undefined;
    if (sentence) return sentence;
    // An unmapped code says nothing about whether the daemon committed first,
    // so the outcome is described as unknown rather than as a dropped change.
    // The protocol token stays in the daemon log, not on the screen.
    return `${UNCERTAIN} If it is not there, try again; the Guard daemon log records the exact cause.`;
  }
  return error instanceof Error && error.message ? error.message : "Protection change failed";
}
