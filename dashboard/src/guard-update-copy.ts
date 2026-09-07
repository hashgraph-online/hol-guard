import type { GuardUpdatePhase, GuardUpdateStatus } from "./guard-types";

export function updateStatusLabel(status: GuardUpdateStatus | null | undefined): string {
  if (!status) {
    return "Checking version…";
  }
  if (status.update_available && status.latest_version) {
    return `${status.latest_version} is ready`;
  }
  return `Version ${status.current_version}`;
}

export function shouldPromptRecoveryReinstall(status: GuardUpdateStatus | null | undefined): boolean {
  return (
    status?.recovery_reinstall_available === true &&
    status?.auto_updatable !== true &&
    status?.version_check?.update_available === true
  );
}

function recoveryReinstallHelpCopy(status: GuardUpdateStatus | null | undefined): string | null {
  if (!shouldPromptRecoveryReinstall(status)) {
    return null;
  }
  const blockedReason = status?.blocked_reason ?? "";
  if (blockedReason.includes("local wheel whose source file is no longer available")) {
    return "This install came from a local wheel whose source file is no longer available, so automatic updates are off. Reinstall from PyPI to switch it back to a normal package; Guard restarts briefly and saved approvals stay.";
  }
  if (blockedReason.includes("local wheel")) {
    return "This install came from a local wheel, so automatic updates are off. Reinstall from PyPI to switch it back to a normal package; Guard restarts briefly and saved approvals stay.";
  }
  return "This install came from a local folder, so automatic updates are off. Reinstall from PyPI to switch it back to a normal package; Guard restarts briefly and saved approvals stay.";
}

export function updateHelpCopy(
  status: GuardUpdateStatus | null | undefined,
  phase: GuardUpdatePhase,
  errorMessage?: string | null,
  embeddedInDesktop = false,
): string | null {
  if (phase === "updating") {
    return "Guard is installing the update. The dashboard will pause briefly and reopen when ready.";
  }
  if (phase === "reconnecting") {
    return "Reconnecting to Guard after the update…";
  }
  if (phase === "error") {
    if (embeddedInDesktop) {
      return (
        errorMessage?.trim() ||
        "The update did not finish. Use Check for Updates in the HOL Guard menu bar and watch its progress there."
      );
    }
    return errorMessage?.trim() || "The update did not finish. The installed version stays in place. Try again, or run hol-guard update from your terminal.";
  }
  if (status?.update_suppressed) {
    if (status.retry_command) {
      return `Automatic update already ran but this install is still behind. Run ${status.retry_command} in your terminal.`;
    }
    if (status.update_attempt_message) {
      return status.update_attempt_message;
    }
    return "Automatic update already ran but this install is still behind the latest release.";
  }
  if (status?.update_available) {
    if (embeddedInDesktop) {
      return "Updates run through the HOL Guard app. Use Check for Updates in the HOL Guard menu-bar icon, and the app installs this version with its own progress screen.";
    }
    return "Restarts briefly. Approvals stay saved.";
  }
  if (status && !status.auto_updatable && status.recovery_reinstall_available) {
    if (embeddedInDesktop) {
      return "This install needs a recovery repair. Try Check for Updates in the HOL Guard menu bar first; if the app cannot repair it, run the recovery reinstall from your terminal.";
    }
    return recoveryReinstallHelpCopy(status);
  }
  if (status && !status.auto_updatable && status.blocked_reason) {
    return status.blocked_reason;
  }
  return null;
}
