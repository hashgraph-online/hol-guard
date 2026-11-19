import { useEffect, useRef, useState } from "react";
import { ActionButton } from "../approval-center-primitives";
import { isGuardDemoMode } from "../guard-demo";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import { SettingsFormSection } from "../settings/settings-row-primitives";
import { ContextAssistanceApiError } from "./api";
import { readCodexShortReplies, setCodexShortReplies, type CodexShortRepliesState } from "./codex-short-replies-api";
import type { ContextProof } from "./workspaces-api";

/** cigarOn: CIGAR's saved switch. Turning CIGAR on can write the instruction, so the page reads it again. */
type Props = { gate: GuardApprovalGatePublicConfig | null; disabled: boolean; cigarOn: boolean };
type Proof = { enabled: boolean; error: string | null };

function message(cause: unknown): string {
  return cause instanceof ContextAssistanceApiError ? cause.message : "Guard could not reach your Codex config. Refresh and try again.";
}

function caption(state: CodexShortRepliesState["state"]): string {
  if (state === "on") return "On. Codex keeps its own words short: no preamble, no recap, a one or two line final answer. Code, commands and paths stay exact. In Guard's tests this cut the Codex bill by 5–14% with no task lost.";
  if (state === "yours") return "Your Codex config has instructions you wrote, so Guard left them as they are.";
  return "Off. Turn it on to ask Codex to keep its own words short. In Guard's tests this cut the Codex bill by 5–14% with no task lost.";
}

function buttonLabel(saving: boolean, on: boolean): string {
  if (saving) return "Saving…";
  return on ? "Turn off" : "Turn on";
}

/**
 * Turning CIGAR on also asks Codex for short replies, unless the user turned that off here.
 * Guard writes one line to the Codex config and never changes instructions the user wrote.
 */
export function CodexShortReplies({ gate, disabled, cigarOn }: Props) {
  const [state, setState] = useState<CodexShortRepliesState | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proof, setProof] = useState<Proof | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  // Each read and save takes a new number; a read answers only if nothing started after it.
  const revision = useRef(0);
  const demo = isGuardDemoMode();

  useEffect(() => {
    if (demo) return;
    const controller = new AbortController();
    revision.current += 1;
    const mine = revision.current;
    readCodexShortReplies(controller.signal).then((read) => {
      if (revision.current !== mine) return;
      setState(read);
      setReadError(null);
    }, (cause: unknown) => {
      if (controller.signal.aborted || revision.current !== mine) return;
      setReadError(message(cause));
    });
    return () => controller.abort();
  }, [demo, cigarOn, attempt]);

  async function save(enabled: boolean, credentials?: ContextProof) {
    revision.current += 1;
    setSaving(true);
    setError(null);
    try {
      setState(await setCodexShortReplies(enabled, credentials));
      setReadError(null);
      setProof(null);
    } catch (cause) {
      if (cause instanceof ContextAssistanceApiError && cause.code.startsWith("approval")) {
        setProof({ enabled, error: credentials ? "That approval did not work. Try again." : null });
      } else {
        setProof(null);
        setError(message(cause));
      }
    } finally {
      setSaving(false);
    }
  }

  if (demo) return null;
  if (state === null) {
    if (readError === null) return null;
    return <SettingsFormSection title="Short Codex replies">
      <div className="flex flex-wrap items-center justify-between gap-3 py-3">
        <p role="alert" className="guard-settings-caption max-w-prose text-amber-800">{readError}</p>
        <ActionButton variant="outline" onClick={() => { setReadError(null); setAttempt((count) => count + 1); }}>Try again</ActionButton>
      </div>
    </SettingsFormSection>;
  }
  const on = state.state === "on";
  const next = !on;
  return <>
    <SettingsFormSection title="Short Codex replies">
      <div className="flex flex-wrap items-center justify-between gap-3 py-3">
        <p className="guard-settings-caption max-w-prose">{caption(state.state)}</p>
        {state.state === "yours" ? null : (
          <ActionButton variant="outline" disabled={disabled || saving}
            onClick={() => { if (gate?.enabled) setProof({ enabled: next, error: null }); else void save(next); }}>
            {buttonLabel(saving, on)}
          </ActionButton>
        )}
      </div>
      {error ?? readError ? <p role="alert" className="guard-settings-caption pb-3 text-amber-800">{error ?? readError}</p> : null}
    </SettingsFormSection>
    <SettingsSaveProofModal open={proof !== null} mode="verify-save" gate={gate}
      title={proof?.enabled ? "Approve short Codex replies" : "Approve turning off short Codex replies"}
      detail={proof?.enabled
        ? "Guard adds one line to your Codex config asking Codex to keep its own words short."
        : "Guard removes the line it added to your Codex config and leaves it off."}
      confirmLabel={proof?.enabled ? "Turn on" : "Turn off"} error={proof?.error ?? null} pending={saving}
      onCancel={() => setProof(null)}
      onConfirm={(credentials) => { void save(proof?.enabled ?? false, { currentPassword: credentials.currentPassword, totpCode: credentials.totpCode }); }} />
  </>;
}
