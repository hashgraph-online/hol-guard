import { useEffect, useState } from "react";
import { HiMiniClipboard, HiMiniClipboardDocumentCheck, HiMiniExclamationTriangle, HiMiniInformationCircle } from "react-icons/hi2";

import { ApprovalProofModal } from "../../approval-proof-modal";
import type { EffectiveExtensionControls } from "../../extension-controls-api";

export type AuthorityNoticeAction =
  | { kind: "repair" }
  | { kind: "acknowledge" }
  | { kind: "configure-approval" }
  | { kind: "none" };

type AuthorityNoticeView = {
  tone: "warning" | "info";
  title: string;
  body: string;
  action: AuthorityNoticeAction;
  actionLabel: string | null;
  actionDetail: string | null;
  command: string;
  commandLabel: string;
  copyButtonLabel: string;
  terminalSummary: string;
};

/**
 * The single surface for every protection-authority state that needs the
 * operator's attention. Every state gets a plain-language cause and exactly
 * one path forward: a proof-bound dashboard action where the daemon supports
 * it, or the terminal command with a copy button where it does not.
 */
function authorityNoticeView(
  health: EffectiveExtensionControls["health"],
  approvalGateReady: boolean | null,
): AuthorityNoticeView {
  switch (health) {
    case "tampered":
    case "recovery-required":
      return {
        tone: "warning",
        title: "Protection needs repair",
        body: "Guard found a problem with this device's trusted protection settings and is staying fail-safe. Protection changes stay locked until the settings are rebuilt with your approval. Commands keep being checked in the meantime.",
        action: { kind: "repair" },
        actionLabel: "Repair protection",
        actionDetail: "Rebuilding the trusted settings needs your approval password. Guard verifies the repair before protection changes unlock again.",
        command: "hol-guard command controls recover-authority",
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: "Run this in your terminal if the button above cannot reach the approval gate.",
      };
    case "degraded-unacknowledged":
      return {
        tone: "warning",
        title: "Protection is limited",
        body: "Guard cannot fully verify the trusted protection settings and is staying fail-safe until that is resolved. Acknowledging records the limited state honestly — it does not restore full protection.",
        action: { kind: "acknowledge" },
        actionLabel: "Acknowledge limited state",
        actionDetail: "Acknowledging the limited state needs your approval password. Guard keeps protecting fail-safe afterwards.",
        command: "hol-guard command controls recover-authority",
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: "A full repair runs from your terminal.",
      };
    case "degraded-acknowledged":
      return {
        tone: "warning",
        title: "Protection is limited",
        body: "The limited state is acknowledged. Guard keeps protection changes locked until the trusted settings are rebuilt from this device's terminal. Commands keep being checked in the meantime.",
        action: { kind: "none" },
        actionLabel: null,
        actionDetail: null,
        command: "hol-guard command controls recover-authority",
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: "Run this in your terminal to rebuild the trusted settings.",
      };
    default:
      if (approvalGateReady === null) {
        return {
          tone: "info",
          title: "Checking approval setup",
          body: "Guard is checking whether this device is ready to enroll trusted protection settings. Enrollment steps will appear when the check finishes. If this takes too long, check again.",
          action: { kind: "none" },
          actionLabel: null,
          actionDetail: null,
          command: "",
          commandLabel: "",
          copyButtonLabel: "",
          terminalSummary: "",
        };
      }
      if (!approvalGateReady) {
        return {
          tone: "info",
          title: "Set up local approval before enrollment",
          body: "Extension controls require this device's local approval gate. Guard Cloud sign-in and account MFA are separate and do not enable this gate. In Settings > Approval gate, enable Ask for proof on allow decisions and set an Approval password, then return here to enroll. Optionally connect an Authenticator app; once enabled, its code replaces the Approval password for every protected action and disables cooldown.",
          action: { kind: "configure-approval" },
          actionLabel: "Set up approval",
          actionDetail: null,
          command: "",
          commandLabel: "",
          copyButtonLabel: "",
          terminalSummary: "",
        };
      }
      return {
        tone: "info",
        title: "Finish setting up protection",
        body: "Command protection settings are not enrolled on this device yet. One command in your terminal creates this device's trusted settings. Local command checking already runs without them.",
        action: { kind: "none" },
        actionLabel: null,
        actionDetail: null,
        command: "hol-guard command controls enroll",
        commandLabel: "Enroll from the terminal",
        copyButtonLabel: "Copy setup command",
        terminalSummary: "Run this in your terminal to create the trusted settings.",
      };
  }
}

export function ProtectionAuthorityNotice(props: {
  effective: EffectiveExtensionControls;
  busy?: boolean;
  error?: string | null;
  status?: string | null;
  approvalGate: Parameters<typeof ApprovalProofModal>[0]["approvalGate"];
  onAction: (kind: "repair" | "acknowledge", credentials: { approval_password?: string; approval_totp_code?: string }) => void;
  onCheckAgain: () => void;
  onOpenApprovalSettings: () => void;
}) {
  const health = props.effective.health;
  const approvalGateReady = props.approvalGate === null
    ? null
    : props.approvalGate.configured && props.approvalGate.enabled;
  const view = authorityNoticeView(health, approvalGateReady);
  const [proofOpen, setProofOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<"repair" | "acknowledge" | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  // A success status means the action completed and the workspace reloaded;
  // close the proof modal so the confirmation is visible on the page.
  useEffect(() => {
    if (props.status) setProofOpen(false);
  }, [props.status]);
  if (health === "protected") return null;
  const gatePending = props.approvalGate === null;

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(view.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };

  const warning = view.tone === "warning";
  const panelClass = warning
    ? "border border-amber-200 bg-amber-50"
    : "border border-brand-blue/25 bg-[rgba(85,153,254,0.06)]";

  return <section aria-labelledby="protection-authority-notice-heading" className={`mt-4 rounded-2xl p-5 sm:p-6 ${panelClass}`}>
    <div className="flex items-start gap-3">
      {warning
        ? <HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0 text-amber-600" aria-hidden="true" />
        : <HiMiniInformationCircle className="mt-0.5 size-5 shrink-0 text-brand-blue" aria-hidden="true" />}
      <div className="min-w-0 flex-1">
        <h2 id="protection-authority-notice-heading" className={`text-base font-semibold ${warning ? "text-amber-950" : "text-brand-dark"}`}>{view.title}</h2>
        <p className={`mt-1 max-w-3xl text-sm leading-6 ${warning ? "text-amber-950/90" : "text-brand-dark/80"}`}>{view.body}</p>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          {view.actionLabel && view.action.kind !== "none" ? <button
            type="button"
            aria-busy={props.busy}
            disabled={props.busy || gatePending}
            onClick={() => {
              if (view.action.kind === "configure-approval") {
                props.onOpenApprovalSettings();
                return;
              }
              setPendingAction(view.action.kind === "repair" ? "repair" : "acknowledge");
              setProofOpen(true);
            }}
            className="inline-flex min-h-11 items-center rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60"
          >{gatePending && !props.error ? "Loading approval settings…" : view.actionLabel}</button> : null}
          {view.action.kind === "none" && view.command ? <button
            type="button"
            onClick={() => { void copyCommand(); }}
            className="inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark"
          >{copyState === "copied" ? <HiMiniClipboardDocumentCheck className="size-4" aria-hidden="true" /> : <HiMiniClipboard className="size-4" aria-hidden="true" />}{copyState === "copied" ? "Command copied" : view.copyButtonLabel}</button> : null}
          <button
            type="button"
            disabled={props.busy}
            onClick={props.onCheckAgain}
            className="inline-flex min-h-11 items-center rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-dark hover:border-brand-blue/40 disabled:opacity-60"
          >Check again</button>
        </div>
        {props.busy ? <p role="status" className={`mt-3 text-sm font-medium ${warning ? "text-amber-950" : "text-brand-dark"}`}>{pendingAction === "acknowledge" ? "Confirming the limited state…" : "Repairing local protection…"}</p> : null}
        {props.error ? <p role="alert" className="mt-3 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">{props.error}</p> : null}
        {props.status ? <p role="status" className="mt-3 text-sm font-medium text-brand-dark">{props.status}</p> : null}
        {view.command ? <details className="mt-4">
          <summary className={`cursor-pointer text-sm font-semibold ${warning ? "text-amber-950" : "text-brand-dark"}`}>{view.commandLabel}</summary>
          <p className={`mt-2 text-sm leading-6 ${warning ? "text-amber-950/80" : "text-brand-dark/70"}`}>{view.terminalSummary}</p>
          <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
            <code className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-brand-dark">{view.command}</code>
            <button
              type="button"
              onClick={() => { void copyCommand(); }}
              className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-blue hover:border-brand-blue/40"
            >{copyState === "copied" ? <HiMiniClipboardDocumentCheck className="size-4" aria-hidden="true" /> : <HiMiniClipboard className="size-4" aria-hidden="true" />}{copyState === "copied" ? "Copied" : "Copy command"}</button>
          </div>
        </details> : null}
      </div>
    </div>
    {proofOpen && (view.action.kind === "repair" || view.action.kind === "acknowledge") ? <ApprovalProofModal
      title={view.action.kind === "repair" ? "Repair protection" : "Acknowledge limited state"}
      detail={view.actionDetail ?? ""}
      confirmLabel={view.actionLabel ?? "Confirm"}
      approvalGate={props.approvalGate}
      busy={props.busy}
      error={props.error}
      onCancel={() => { if (!props.busy) setProofOpen(false); }}
      onConfirm={(credentials) => { props.onAction(view.action.kind === "repair" ? "repair" : "acknowledge", credentials); }}
    /> : null}
  </section>;
}
