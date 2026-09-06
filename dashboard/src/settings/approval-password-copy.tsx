import { ActionButton } from "../approval-center-primitives";

export function resolveApprovalPasswordSectionCopy(wasConfigured: boolean): string {
  if (wasConfigured) {
    return "Guard asks for this password before allow or trust changes stick. Save settings to confirm changes, or change the password when needed.";
  }
  return "Set an approval password before allow or trust changes stick. Use the setup action below to choose it.";
}

export function ApprovalPasswordSetupAction(props: { onClick: () => void }) {
  return <ActionButton onClick={props.onClick} variant="outline">Set up approval password</ActionButton>;
}
