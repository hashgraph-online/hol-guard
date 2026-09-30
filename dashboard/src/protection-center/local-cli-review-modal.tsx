import { useCallback, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { ApprovalProofFieldInputs, buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "../approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import type { LocalCliCommandState, LocalCliItem, LocalCliState } from "../local-cli-api";
import { useModalDialog } from "../use-modal-dialog";
import { InlineError } from "./components/protection-primitives";
import { commandPermissionChanges } from "./mcp-catalog-state";
import type { ProviderActionDraft } from "./mcp-provider-actions";
import { reviewModalDetail, reviewTitle } from "./local-cli-panel-copy";

export function CustomExtensionReviewModal(props: {
  item: LocalCliItem;
  nextState: LocalCliState;
  commandChanges: ReturnType<typeof commandPermissionChanges>;
  providerUpdates: ProviderActionDraft[];
  busy: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const title = props.providerUpdates.length > 0 ? "Review app action permissions" : reviewTitle(props.item.name, props.nextState);
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const digits = event.target.value.replace(/\D/g, "").slice(0, 6);
    event.target.value = digits;
    setTotp(digits);
  }, []);
  const handleSubmit = useCallback((event: FormEvent) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, {
      approvalPassword: password,
      approvalTotpCode: totp,
    }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword: password, approvalTotpCode: totp },
    props.busy,
    false,
    true,
  );
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm">
      <form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="custom-extension-review-title" onSubmit={handleSubmit} className="max-h-[calc(100dvh-2rem)] w-full max-w-lg overflow-y-auto rounded-3xl bg-white p-6 shadow-2xl focus:outline-none">
        <h2 id="custom-extension-review-title" className="text-xl font-semibold text-brand-dark">{title}</h2>
        <p className="mt-2 text-sm leading-6 text-brand-dark/80">
          {reviewModalDetail(props.approvalGate)}
        </p>
        {props.item.surface === "mcp" ? <div className="mt-3 text-sm leading-6 text-brand-dark">
          <p>{props.item.source_label || "This host"} · This configured connection</p>
          <p>{connectionReviewMessage(props.nextState)}</p>
        </div> : null}
        {props.commandChanges.length > 0 ? <section aria-label="Permission changes" className="mt-4 text-sm leading-6 text-brand-dark">
          <p className="font-semibold">{props.commandChanges.length} {props.item.surface === "mcp" ? "tool" : "command"} changes</p>
          <ul className="mt-2 max-h-48 space-y-2 overflow-y-auto">
            {props.commandChanges.map((change) => <li key={change.commandId} className="break-words">
              {change.name}: {permissionLabel(change.before)} → {permissionLabel(change.after)}
            </li>)}
          </ul>
        </section> : null}
        {props.providerUpdates.length > 0 ? (
          <div className="mt-3 max-h-48 overflow-y-auto text-sm leading-6 text-brand-dark">
            <p>{props.providerUpdates.length} action changes for this host connection, across all accounts.</p>
            <ul className="mt-2 space-y-1">
              {props.providerUpdates.map((update) => (
                <li key={update.tool_slug} className="break-words">
                  {update.tool_slug.replaceAll("_", " ").toLowerCase()} → {update.state === "block" ? "Deny" : "Ask"}
                </li>
              ))}
            </ul>
            <p className="mt-2">Any Deny also blocks opaque workbench execution. Allow is unavailable until the account is verified.</p>
          </div>
        ) : null}
        <div className="mt-5">
          <ApprovalProofFieldInputs
            approvalGate={props.approvalGate}
            approvalPassword={password}
            approvalTotpCode={totp}
            requireGate={true}
            onApprovalPasswordChange={handlePassword}
            onApprovalTotpCodeChange={handleTotp}
          />
        </div>
        {props.error ? <div className="mt-4"><InlineError message={props.error} /></div> : null}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" disabled={props.busy} onClick={props.onCancel} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">Cancel</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60">
            {props.busy ? "Saving…" : "Confirm"}
          </button>
        </div>
      </form>
    </div>
  );
}

function permissionLabel(state: LocalCliCommandState | null): string {
  if (state === null) return "Not previously listed";
  const labels: Record<LocalCliCommandState, string> = {
    allow: "Allow", block: "Deny", review: "Ask", inherit: "Policy",
  };
  return labels[state];
}

function connectionReviewMessage(state: LocalCliState): string {
  if (state === "blocked") return "The connection will deny every tool, including tools listed as Allow.";
  if (state === "unset") return "Saved connection permissions will be removed. Future calls return to Guard policy.";
  return "Unknown and future tools still require review. These choices do not verify the provider account.";
}
