import type { FormEvent, ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { AlphaChannelDialog } from "./alpha-update-channel-dialog";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

type DialogProps = Parameters<typeof AlphaChannelDialog>[0];

function props(overrides: Partial<DialogProps> = {}): DialogProps {
  const noop = () => undefined;
  return {
    useAlpha: false,
    pending: false,
    error: null,
    approvalGate: null,
    approvalPassword: "",
    approvalTotpCode: "",
    onClose: noop,
    onConfirm: noop,
    onApprovalPasswordChange: noop,
    onApprovalTotpCodeChange: noop,
    ...overrides,
  };
}

/** Submits the dialog's form the way Enter does and reports whether it confirmed. */
function submit(overrides: Partial<DialogProps>): { confirmed: number; prevented: boolean } {
  let confirmed = 0;
  let prevented = false;
  const form = AlphaChannelDialog(props({ ...overrides, onConfirm: () => { confirmed += 1; } })) as ReactElement<{
    onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  }>;
  assert(form.type === "form", "the dialog root is a form");
  form.props.onSubmit({ preventDefault: () => { prevented = true; } } as FormEvent<HTMLFormElement>);
  return { confirmed, prevented };
}

// Enter in a field submits the form; only the confirm button is a submit control.
for (const useAlpha of [false, true]) {
  const label = useAlpha ? "Use stable updates" : "Enable alpha updates";
  const markup = renderToStaticMarkup(<AlphaChannelDialog {...props({ useAlpha })} />);
  assert(markup.startsWith("<form"), `the ${label} dialog renders as a form so Enter submits it`);
  const submits = markup.match(/<button type="submit"[^>]*>[^<]*<\/button>/g) ?? [];
  assert(submits.length === 1 && submits[0].includes(label), `only ${label} submits the form`);
}

// Enter confirms exactly when the button would.
const ready = submit({});
assert(ready.confirmed === 1, "Enter confirms the channel change");
assert(ready.prevented, "submitting never reloads the page");
const pending = submit({ pending: true });
assert(pending.confirmed === 0 && pending.prevented, "Enter does not confirm twice while a change is pending");

const gate: GuardApprovalGatePublicConfig = {
  enabled: true,
  configured: true,
  cooldown_seconds: 0,
  cooldown_active: false,
  cooldown_expires_at: null,
  locked_until: null,
  fail_closed: true,
  strict_all_decisions: false,
  totp_enabled: true,
};
assert(submit({ approvalGate: gate, approvalTotpCode: "" }).confirmed === 0, "Enter does not confirm before the code is entered");
assert(submit({ approvalGate: gate, approvalTotpCode: "123456" }).confirmed === 1, "Enter confirms once the code is entered");

console.log("alpha-update-channel-dialog.test.tsx: all tests passed");
