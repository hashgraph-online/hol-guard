import { useState } from "react";
import { ActionButton } from "./approval-center-primitives";
import { ApprovalProofFieldInputs, buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

export function BusinessPolicyRecoveryPanel(props: {
  requestId: string;
  candidateDigest: string;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onRecovered: () => void;
  policy?: Record<string, unknown>;
  installed?: boolean;
  requestRecovered?: boolean;
  recoverPolicy: typeof import("./business-policy-recovery-api").recoverBusinessPolicy;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [recovered, setRecovered] = useState(false);
  let buttonLabel = "Approve and recover policy";
  if (busy) buttonLabel = "Recovering policy…";
  const showProof = !recovered && !props.installed && props.policy != null;
  async function recover() {
    if (busy || recovered || props.installed || props.policy == null) return;
    const proof = buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, true);
    setPassword("");
    setTotp("");
    setBusy(true);
    setMessage(null);
    try {
      await props.recoverPolicy({ requestId: props.requestId, candidateDigest: props.candidateDigest, ...proof });
      setRecovered(true);
      setMessage("Policy installation recovered. No app action was sent or replayed.");
      props.onRecovered();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The saved policy could not be recovered. Refresh before retrying.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="space-y-4 border-t border-slate-200 pt-5" aria-labelledby="business-policy-recovery-title" aria-busy={busy}>
      <h2 id="business-policy-recovery-title" className="text-lg font-semibold text-brand-dark">Recover interrupted policy installation</h2>
      <p className="max-w-prose text-sm leading-6 text-brand-dark/75">
        Freshly approve this request’s saved policy to finish its installation.
        Guard checks that it matches the saved policy and does not replace newer protection.
        This does not resume an app task or resolve the original request.
      </p>
      {props.policy ? <details open className="space-y-2">
        <summary className="cursor-pointer text-sm font-semibold text-brand-dark">Saved policy rules</summary>
        <p className="text-sm text-brand-dark/75">Author metadata is hidden. The digest identifies the original saved policy.</p>
        <p className="break-all font-mono text-xs text-brand-dark" aria-label="Saved policy digest">{props.candidateDigest}</p>
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-50 p-3 text-xs text-brand-dark">{JSON.stringify(props.policy, null, 2)}</pre>
      </details> : null}
      {props.installed ? <p role="status" className="text-sm text-brand-dark">This policy is already installed. The original request remains unchanged; you can decline it.</p> : null}
      {props.requestRecovered && !props.installed ? <p role="status" className="text-sm text-brand-dark">This request was imported through recovery and cannot be approved again. An interrupted installation can still be recovered with fresh proof.</p> : null}
      {showProof ? <>
        <ApprovalProofFieldInputs
          approvalGate={props.approvalGate ?? null}
          approvalPassword={password}
          approvalTotpCode={totp}
          onApprovalPasswordChange={(event) => setPassword(event.target.value)}
          onApprovalTotpCodeChange={(event) => setTotp(event.target.value)}
          requireFreshTotp
          requireGate
        />
        <ActionButton onClick={() => void recover()} disabled={busy || isApprovalProofSubmitDisabled(props.approvalGate, {
          approvalPassword: password, approvalTotpCode: totp,
        }, busy, true, true)}>{buttonLabel}</ActionButton>
      </> : null}
      {message ? <p role="status" aria-live="polite" className="text-sm leading-6 text-brand-dark">{message}</p> : null}
    </section>
  );
}
