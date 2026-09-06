import { ActionButton, SectionLabel } from "../approval-center-primitives";

export function resolveApprovalPasswordSectionCopy(wasConfigured: boolean, enabled = true): string {
  if (wasConfigured) {
    return "Guard asks for this password before allow or trust changes stick. Save settings to confirm changes, or change the password when needed.";
  }
  if (!enabled) {
    return "Enable the approval gate above before setting an approval password.";
  }
  return "Set an approval password before allow or trust changes stick. Use the setup action below to choose it.";
}

export function ApprovalPasswordSetupAction(props: { onClick: () => void }) {
  return <ActionButton onClick={props.onClick} variant="outline">Set up approval password</ActionButton>;
}

export function ApprovalPasswordSection(props: {
  wasConfigured: boolean;
  enabled: boolean;
  onOpenPasswordChangeModal: (mode?: "change-password" | "setup-gate") => void;
}) {
  return (
    <div className="rounded-xl border border-slate-100 bg-white p-4">
      <SectionLabel>Approval password</SectionLabel>
      <p className="mt-1 text-xs text-slate-500">{resolveApprovalPasswordSectionCopy(props.wasConfigured, props.enabled)}</p>
      {props.wasConfigured ? (
        <div className="mt-3">
          <button
            type="button"
            onClick={() => props.onOpenPasswordChangeModal()}
            className="text-xs font-medium text-brand-blue transition-colors hover:text-brand-blue/80"
          >
            Change password
          </button>
        </div>
      ) : null}
      {!props.wasConfigured && props.enabled ? (
        <ApprovalPasswordSetupAction onClick={() => props.onOpenPasswordChangeModal("setup-gate")} />
      ) : null}
    </div>
  );
}
