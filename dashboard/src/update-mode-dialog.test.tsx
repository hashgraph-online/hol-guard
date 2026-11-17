import type { FormEvent, ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { UpdateModeDialog } from "./update-mode-dialog";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

type DialogProps = Parameters<typeof UpdateModeDialog>[0];

function props(overrides: Partial<DialogProps> = {}): DialogProps {
  const noop = () => undefined;
  return {
    mode: "automatic",
    draft: "ask",
    pending: false,
    error: null,
    approvalGate: null,
    approvalPassword: "",
    approvalTotpCode: "",
    onDraftChange: noop,
    onClose: noop,
    onConfirm: noop,
    onApprovalPasswordChange: noop,
    onApprovalTotpCodeChange: noop,
    ...overrides,
  };
}

/** Submits the dialog's form the way Enter does and reports whether it saved. */
function submit(overrides: Partial<DialogProps>): { saved: number; prevented: boolean } {
  let saved = 0;
  let prevented = false;
  const form = UpdateModeDialog(props({ ...overrides, onConfirm: () => { saved += 1; } })) as ReactElement<{
    onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  }>;
  assert(form.type === "form", "the dialog root is a form");
  form.props.onSubmit({ preventDefault: () => { prevented = true; } } as FormEvent<HTMLFormElement>);
  return { saved, prevented };
}

// Enter in a field submits the form; only Save preference is a submit control.
const markup = renderToStaticMarkup(<UpdateModeDialog {...props()} />);
assert(markup.startsWith("<form"), "Core update preferences renders as a form so Enter submits it");
const submits = markup.match(/<button type="submit"[^>]*>[^<]*<\/button>/g) ?? [];
assert(submits.length === 1 && submits[0].includes("Save preference"), "only Save preference submits the form");

// Enter saves exactly when the button would.
const changed = submit({});
assert(changed.saved === 1, "Enter saves a changed preference");
assert(changed.prevented, "submitting never reloads the page");
assert(submit({ draft: "automatic" }).saved === 0, "Enter does not save an unchanged preference");
const pending = submit({ pending: true, draft: "automatic" });
assert(pending.saved === 0 && pending.prevented, "Enter does not save twice while a save is pending");

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
assert(submit({ approvalGate: gate, approvalTotpCode: "" }).saved === 0, "Enter does not save before the code is entered");
assert(submit({ approvalGate: gate, approvalTotpCode: "123456" }).saved === 1, "Enter saves once the code is entered");

console.log("update-mode-dialog.test.tsx: all tests passed");
