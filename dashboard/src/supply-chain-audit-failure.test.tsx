import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { ApprovalProofInline } from "./approval-proof-inline";
import { describeSupplyChainRecoveryFailure } from "./supply-chain-audit-failure";
import { SupplyChainAuditFailureNotice } from "./supply-chain-audit-failure-notice";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const HASH_MISMATCH =
  "Guard supply-chain bundle sync failed: Bundle payloadHash does not match the canonical payload";

const mismatch = describeSupplyChainRecoveryFailure(HASH_MISMATCH, { approvalStep: true });
assert(mismatch.kind === "unverified_bundle", "payload hash mismatch is an unverified bundle");
assert(mismatch.nextStep.includes("Update Guard"), "payload hash mismatch tells the user to update Guard");
assert(mismatch.summary.includes("did not install it"), "payload hash mismatch says nothing was installed");
assert(mismatch.technicalDetail === HASH_MISMATCH, "payload hash mismatch keeps the exact technical text");
assert(!/skip|ignore|override|bypass|anyway/i.test(`${mismatch.summary} ${mismatch.nextStep}`), "verification is never offered as skippable");

const signature = describeSupplyChainRecoveryFailure("Bundle signature verification failed");
assert(signature.kind === "unverified_bundle", "signature failures are unverified bundles");

const offline = describeSupplyChainRecoveryFailure(
  "Guard lost connection while syncing supply-chain intel. Confirm the local daemon is still running, then try again.",
);
assert(offline.kind === "local_connection", "daemon connection loss reads as a local connection problem");
assert(offline.nextStep.includes("still running"), "daemon connection loss tells the user to check Guard is running");

const cloudOutage = describeSupplyChainRecoveryFailure(
  "Guard Cloud is temporarily unavailable. Try syncing again in a few minutes.",
);
assert(cloudOutage.kind === "service_unavailable", "a cloud outage is not a local connection problem");
assert(cloudOutage.nextStep.startsWith("Wait a few minutes"), "a cloud outage tells the user to wait and retry");
assert(!cloudOutage.nextStep.includes("still running"), "a cloud outage never sends the user to troubleshoot the daemon");

const auditFailure = describeSupplyChainRecoveryFailure("Audit workspace directory was not found.", { operation: "audit" });
assert(auditFailure.kind === "audit", "an audit failure is reported as an audit failure");
assert(auditFailure.title === "The workspace audit did not finish", "an audit failure names the audit, not the sync");
assert(!/sync/i.test(`${auditFailure.title} ${auditFailure.nextStep}`), "an audit failure never points at the sync");
assert(
  describeSupplyChainRecoveryFailure("Guard Cloud is temporarily unavailable.", { operation: "audit" }).kind ===
    "service_unavailable",
  "an audit that hits a cloud outage says so",
);
assert(
  describeSupplyChainRecoveryFailure("Bundle signature verification failed", { operation: "audit" }).kind === "audit",
  "bundle wording is only used for the sync step",
);

const rejected = describeSupplyChainRecoveryFailure("Approval password is incorrect.", { approvalStep: true });
assert(rejected.kind === "approval_step", "approval step failures keep their own kind");
assert(rejected.summary === "Approval password is incorrect.", "approval step failures keep the message");
assert(rejected.nextStep.includes("enter it again"), "approval step failures tell the user to re-enter proof");

const generic = describeSupplyChainRecoveryFailure("Sync failed.");
assert(generic.kind === "generic" && generic.nextStep.startsWith("Try again"), "other failures say to try again");
assert(describeSupplyChainRecoveryFailure("   ").summary.length > 0, "an empty message still explains the failure");

// Every verification failure the Python bundle verifier can raise must read as a rejected
// bundle, never as a generic retry. The messages come straight from the verifier source.
const verifierSource = readFileSync(
  new URL("../../src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_runtime.py", import.meta.url),
  "utf8",
);
const raised = [...verifierSource.matchAll(/raise SupplyChainBundle(Expired|Rollback|Keyring|Signature|PayloadHash)Error\(\s*f?"([^"]*)"/g)];
assert(raised.length >= 10, `found the verifier's raised messages (${raised.length})`);
const kindsByError: Record<string, string[]> = {
  Expired: ["rejected_bundle"],
  Rollback: ["rejected_bundle"],
  Keyring: ["unverified_bundle"],
  Signature: ["unverified_bundle"],
  PayloadHash: ["unverified_bundle"],
};
for (const [, errorName, template] of raised) {
  const text = `Guard supply-chain bundle sync failed: ${template.replace(/\{[^}]*\}/g, "X")}`;
  const described = describeSupplyChainRecoveryFailure(text);
  assert(
    kindsByError[errorName].includes(described.kind),
    `${errorName} failure "${text}" reads as ${kindsByError[errorName].join(" or ")}, got ${described.kind}`,
  );
  assert(described.technicalDetail === text, `${errorName} failure keeps its technical text`);
}

const noticeMarkup = renderToStaticMarkup(<SupplyChainAuditFailureNotice message={HASH_MISMATCH} />);
assert(noticeMarkup.includes('role="alert"'), "failure notice is announced as an alert");
assert(noticeMarkup.includes("Guard could not verify the downloaded intel"), "failure notice names what happened");
assert(noticeMarkup.includes("Update Guard to the latest version"), "failure notice names the next step");
assert(noticeMarkup.includes("Bundle payloadHash does not match the canonical payload"), "failure notice keeps the technical detail");
assert(!/class="[^"]*\btext-brand-attention(?![-\w])/.test(noticeMarkup), "failure notice never sets text in the pale attention hue");
assert(noticeMarkup.includes("text-brand-attention-text"), "failure notice uses the accessible attention text tone");
assert(noticeMarkup.includes("bg-brand-attention-bg"), "failure notice uses the brand attention surface");
assert(!/yellow|amber|orange|red-/.test(noticeMarkup), "failure notice stays in the brand palette");

const noop = () => undefined;
const approvalMarkup = renderToStaticMarkup(
  <ApprovalProofInline
    approvalGate={{
      enabled: true,
      configured: true,
      cooldown_seconds: 0,
      cooldown_active: false,
      cooldown_expires_at: null,
      locked_until: null,
      fail_closed: true,
      strict_all_decisions: false,
    }}
    approvalPassword=""
    approvalTotpCode=""
    error={<SupplyChainAuditFailureNotice message={HASH_MISMATCH} approvalStep />}
    submitLabel="Sync supply-chain intel"
    submitBusy={false}
    onApprovalPasswordChange={noop}
    onApprovalTotpCodeChange={noop}
    onSubmit={noop}
    onBack={noop}
  />,
);
assert(approvalMarkup.includes("Update Guard to the latest version"), "approval step shows the next step");
assert(approvalMarkup.includes("Sync supply-chain intel"), "approval step keeps its submit action");
assert(approvalMarkup.includes("Go back"), "approval step keeps its way back");

const quietMarkup = renderToStaticMarkup(
  <ApprovalProofInline
    approvalGate={null}
    approvalPassword=""
    approvalTotpCode=""
    error={null}
    submitLabel="Sync supply-chain intel"
    submitBusy={false}
    onApprovalPasswordChange={noop}
    onApprovalTotpCodeChange={noop}
    onSubmit={noop}
    onBack={noop}
  />,
);
assert(!quietMarkup.includes('role="alert"'), "no alert renders without an error");

const modalSource = readFileSync(new URL("./supply-chain-audit-recovery-modal.tsx", import.meta.url), "utf8");
const proofSource = readFileSync(new URL("./approval-proof-inline.tsx", import.meta.url), "utf8");
assert(
  (modalSource.match(/<SupplyChainAuditFailureNotice /g) ?? []).length === 2,
  "both modal steps render errors through the failure notice",
);
assert(!/text-brand-attention"/.test(modalSource) && !/text-brand-attention"/.test(proofSource), "modal text never uses the pale attention hue");

console.log("supply-chain-audit-failure.test.tsx: all assertions passed");
