import {
  buildClearPolicyPayload,
  buildClearReviewQueuePayload,
  formatTotpEnrollmentExpiry,
  buildTotpQrImageOptions,
  formatTotpManualKey,
  resolveSecurityLevelDescription,
  resolveFineTuningSectionDescription,
  isFineTuningEditable,
  resolveTotpSetupStep,
  hasApprovalGateSettingsChanged,
  resolveApprovalPasswordSectionCopy,
  resolveTotpSetupModalTitle,
} from "./settings-workspace";
import { repairApprovalCenter, setupDesktopNotifications } from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const balancedDesc = resolveSecurityLevelDescription("balanced");
assert(balancedDesc.length > 0, "T529: balanced description should not be empty");
assert(balancedDesc.includes("secrets") || balancedDesc.includes("destructive"), "T529: balanced description should mention secrets or destructive");

const strictDesc = resolveSecurityLevelDescription("strict");
assert(strictDesc.length > 0, "T529: strict description should not be empty");
assert(strictDesc.includes("network") || strictDesc.includes("more"), "T529: strict description should mention network or more");
assert(strictDesc !== balancedDesc, "T529: strict and balanced descriptions should differ");

const customDesc = resolveSecurityLevelDescription("custom");
assert(customDesc.length > 0, "T529: custom description should not be empty");
assert(customDesc.includes("Custom") || customDesc.includes("custom") || customDesc.includes("rules"), "T529: custom description should mention custom rules");

const clearAllPayload = buildClearPolicyPayload(true);
assert(clearAllPayload.all === true, "T530: clearPolicy payload should have all=true");
assert(!("harness" in clearAllPayload) || clearAllPayload.harness === undefined, "T530: clearPolicy payload should not have harness when clearing all");

const clearNonePayload = buildClearPolicyPayload(false);
assert(clearNonePayload.all === false, "T530: clearPolicy payload with all=false should have all=false");

const clearQueuePayload = buildClearReviewQueuePayload({
  approvalPassword: "local-password",
  approvalTotpCode: "123456",
});
assert(clearQueuePayload.status === "pending", "T744: clearReviewQueue payload should target pending reviews");
assert(clearQueuePayload.approval_password === "local-password", "T744: clearReviewQueue payload should include approval password");
assert(clearQueuePayload.approval_totp_code === "123456", "T744: clearReviewQueue payload should include authenticator code");

assert(typeof repairApprovalCenter === "function", "T739: repairApprovalCenter should be exported as a function");
assert(typeof setupDesktopNotifications === "function", "T740: setupDesktopNotifications should be exported as a function");

const qrOptions = buildTotpQrImageOptions();
assert(qrOptions.level === "M", "T741: TOTP QR should use medium error correction for authenticator scanning");
assert(qrOptions.size === 160, "T741: TOTP QR should render at scanner-friendly size");
assert(qrOptions.fgColor === "#121a3a", "T741: TOTP QR should use brand dark color");
assert(qrOptions.bgColor === "#ffffff", "T741: TOTP QR should use white background");

assert(
  formatTotpManualKey("abcd efgh-ijklmnop") === "abcd efgh ijkl mnop",
  "T742: manual TOTP key should be grouped for fallback entry"
);
assert(formatTotpManualKey(null) === "", "T742: manual TOTP key formatter should tolerate null");
assert(
  formatTotpEnrollmentExpiry("not-a-date") === "Enrollment expiration unknown.",
  "T743: invalid TOTP expiry should not render Invalid Date"
);

const strictFineTuningDescription = resolveFineTuningSectionDescription("strict");
assert(
  strictFineTuningDescription.includes("Strict"),
  "fine-tuning: strict description should name the preset"
);
assert(
  !strictFineTuningDescription.includes("Protection"),
  "fine-tuning: strict description should not send users to another tab"
);
assert(
  strictFineTuningDescription.includes("Custom"),
  "fine-tuning: strict description should mention Custom mode"
);

assert(isFineTuningEditable("custom") === true, "fine-tuning: custom level is editable");
assert(isFineTuningEditable("strict") === false, "fine-tuning: strict level is locked until custom");
assert(isFineTuningEditable("balanced") === false, "fine-tuning: balanced level is locked until custom");
assert(isFineTuningEditable("relaxed") === false, "fine-tuning: relaxed level is locked until custom");

assert(resolveTotpSetupStep(null) === "confirm", "totp-setup: fresh setup starts at password confirmation");
assert(
  resolveTotpSetupStep({ provisioning_uri: "otpauth://totp/test", manual_key: "abcd", expires_at: "2026-01-01T00:00:00Z" }) === "scan",
  "totp-setup: pending enrollment resumes at QR scan step",
);

assert(
  hasApprovalGateSettingsChanged(
    { enabled: true, configured: true, cooldown_seconds: 0, strict_all_decisions: false, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: false, totp_enabled: false, totp_pending: false },
    true,
    900,
    false,
  ) === true,
  "approval-password: cooldown edits count as gate setting changes",
);

assert(
  resolveApprovalPasswordSectionCopy(true).includes("Save settings"),
  "approval-password: configured copy points to save flow",
);
assert(
  resolveApprovalPasswordSectionCopy(false).includes("save settings"),
  "approval-password: first-time copy points to save flow",
);
assert(
  resolveTotpSetupModalTitle(true) === "Confirm your approval password",
  "totp-modal: confirm step title",
);
