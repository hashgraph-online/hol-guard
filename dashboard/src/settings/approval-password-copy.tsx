import { ActionButton, SectionLabel } from "../approval-center-primitives";

export function resolveApprovalPasswordSectionCopy(wasConfigured: boolean, enabled = true): string {
  if (wasConfigured) {
    if (!enabled) {
      return "Your approval password is set. Turn on Ask for proof above to change it or connect an authenticator.";
    }
    return "Guard asks for this password before allow or trust changes stick. Save settings to confirm changes, or change the password when needed.";
  }
  if (!enabled) {
    return "Set an approval password to require proof before allow or trust changes stick. Setting one turns on Ask for proof.";
  }
  return "Set an approval password before allow or trust changes stick. Use the setup action below to choose it.";
}

export function ApprovalPasswordSetupAction(props: { onClick: () => void }) {
  return <ActionButton onClick={props.onClick} variant="outline">Set up approval password</ActionButton>;
}

export function ApprovalPasswordSection(props: {
  wasConfigured: boolean;
  enabled: boolean;
  gateActive: boolean;
  onOpenPasswordChangeModal: (mode?: "change-password" | "setup-gate") => void;
}) {
  const copyEnabled = props.wasConfigured ? props.gateActive : props.enabled;
  return (
    <div className="rounded-xl border border-slate-100 bg-white p-4">
      <SectionLabel>Approval password</SectionLabel>
      <p className="mt-1 text-xs text-slate-500">{resolveApprovalPasswordSectionCopy(props.wasConfigured, copyEnabled)}</p>
      {props.wasConfigured && props.gateActive ? (
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
      {!props.wasConfigured ? (
        <ApprovalPasswordSetupAction onClick={() => props.onOpenPasswordChangeModal("setup-gate")} />
      ) : null}
    </div>
  );
}
