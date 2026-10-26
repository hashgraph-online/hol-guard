export type SupplyChainRecoveryOperation = "sync" | "audit";

export type SupplyChainRecoveryFailureKind =
  | "unverified_bundle"
  | "rejected_bundle"
  | "local_connection"
  | "service_unavailable"
  | "approval_step"
  | "audit"
  | "generic";

export type SupplyChainRecoveryFailure = {
  kind: SupplyChainRecoveryFailureKind;
  title: string;
  summary: string;
  nextStep: string;
  technicalDetail: string;
};

// Backend verification failures: payload hash, signature, verification keys and the keyring.
const UNVERIFIED_BUNDLE = /payload\s*hash|canonical payload|signature|verification key|keyring|key\s*id/i;
// Backend freshness and rollback failures: expired, too old, dated in the future, older than cached.
const REJECTED_BUNDLE = /bundle expired|exceeds maximum allowed age|generatedAt .* in the future|older than cached version/i;
// The browser lost the local daemon, not the cloud.
const LOCAL_CONNECTION = /lost connection|failed to fetch|networkerror|load failed/i;
// The cloud side did not answer; waiting is the fix, not local troubleshooting.
const SERVICE_UNAVAILABLE =
  /temporarily unavailable|is unavailable|remote endpoint could not be reached|unreachable|timed out|timeout|try syncing again/i;

const EMPTY_SUMMARY = "Guard stopped before the operation completed.";

/**
 * Turn a raw sync or audit failure into what happened and what to do next. The
 * raw text stays available as technical detail where it explains a rejection,
 * so support can still see the exact cause. A bundle that fails verification is
 * never offered as something to skip: it was not installed, and the step is to
 * update Guard and sync again.
 */
export function describeSupplyChainRecoveryFailure(
  message: string,
  options?: { approvalStep?: boolean; operation?: SupplyChainRecoveryOperation },
): SupplyChainRecoveryFailure {
  const technicalDetail = message.trim();
  const operation = options?.operation ?? "sync";
  if (operation === "sync" && UNVERIFIED_BUNDLE.test(technicalDetail)) {
    return {
      kind: "unverified_bundle",
      title: "Guard could not verify the downloaded intel",
      summary:
        "The bundle did not pass Guard's signature checks, so Guard did not install it. Intel already on this device is unchanged.",
      nextStep:
        "Update Guard to the latest version, then sync again. If it still fails, share the technical detail with support.",
      technicalDetail,
    };
  }
  if (operation === "sync" && REJECTED_BUNDLE.test(technicalDetail)) {
    return {
      kind: "rejected_bundle",
      title: "Guard turned down the downloaded intel",
      summary:
        "The bundle is expired, too old, or dated in the future compared with this device, so Guard did not install it. Intel already on this device is unchanged.",
      nextStep: "Check that this device's date and time are correct, then sync again.",
      technicalDetail,
    };
  }
  if (LOCAL_CONNECTION.test(technicalDetail)) {
    return {
      kind: "local_connection",
      title: "Guard lost contact with the local daemon",
      summary: "The daemon stopped answering before the operation finished.",
      nextStep: "Confirm Guard is still running on this device, then try again.",
      technicalDetail,
    };
  }
  if (SERVICE_UNAVAILABLE.test(technicalDetail)) {
    return {
      kind: "service_unavailable",
      title: "Guard Cloud is not answering right now",
      summary: "Guard could not reach Guard Cloud. Protection on this device keeps working.",
      nextStep: "Wait a few minutes, then try again. If it keeps happening, check this device's internet connection.",
      technicalDetail,
    };
  }
  if (operation === "audit") {
    return {
      kind: "audit",
      title: "The workspace audit did not finish",
      summary: technicalDetail === "" ? EMPTY_SUMMARY : technicalDetail,
      nextStep: "Try again. If it keeps failing, check the workspace folder Guard is auditing.",
      technicalDetail: "",
    };
  }
  if (options?.approvalStep === true) {
    return {
      kind: "approval_step",
      title: "The sync did not finish",
      summary: technicalDetail === "" ? EMPTY_SUMMARY : technicalDetail,
      nextStep: "If your approval proof was rejected, enter it again and sync. Otherwise go back and review the steps.",
      technicalDetail: "",
    };
  }
  return {
    kind: "generic",
    title: "The sync did not finish",
    summary: technicalDetail === "" ? EMPTY_SUMMARY : technicalDetail,
    nextStep: "Try again. If it keeps failing, update Guard and sync once more.",
    technicalDetail: "",
  };
}
