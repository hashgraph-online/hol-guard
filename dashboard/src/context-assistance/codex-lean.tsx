import { useEffect, useState } from "react";
import { ActionButton } from "../approval-center-primitives";
import { isGuardDemoMode } from "../guard-demo";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import { SettingsFormSection } from "../settings/settings-row-primitives";
import { ContextAssistanceApiError } from "./api";
import { readCodexLean, removeCodexLean, type CodexLeanState } from "./codex-lean-api";
import type { ContextProof } from "./workspaces-api";

type Props = { gate: GuardApprovalGatePublicConfig | null; disabled: boolean };
type Proof = { error: string | null };

function message(cause: unknown): string {
  return cause instanceof ContextAssistanceApiError ? cause.message : "Guard could not reach your Codex config. Refresh and try again.";
}

function size(state: CodexLeanState): string {
  return typeof state.limit === "number" ? `${state.limit.toLocaleString()} tokens` : "a set size";
}

/**
 * Earlier Guard versions wrote a small summary size to the Codex config, and
 * `hol-guard context lean on --limit` still can. A smaller chat is not a cheaper one, so
 * this page never sets one. It only appears while a size Guard wrote is in the config,
 * and offers to remove it.
 */
export function CodexLeanSessions({ gate, disabled }: Props) {
  const [state, setState] = useState<CodexLeanState | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proof, setProof] = useState<Proof | null>(null);
  const demo = isGuardDemoMode();

  useEffect(() => {
    if (demo) return;
    const controller = new AbortController();
    // A read that fails shows nothing: there is nothing to remove that we know of.
    readCodexLean(controller.signal).then(setState, () => undefined);
    return () => controller.abort();
  }, [demo]);

  async function remove(credentials?: ContextProof) {
    setSaving(true);
    setError(null);
    try {
      setState(await removeCodexLean(credentials));
      setProof(null);
    } catch (cause) {
      if (cause instanceof ContextAssistanceApiError && cause.code.startsWith("approval")) {
        setProof({ error: credentials ? "That approval did not work. Try again." : null });
      } else {
        setProof(null);
        setError(message(cause));
      }
    } finally {
      setSaving(false);
    }
  }

  if (demo || state?.state !== "on") return null;
  return <>
    <SettingsFormSection title="Codex summary size">
      <div className="flex flex-wrap items-center justify-between gap-3 py-3">
        <p className="guard-settings-caption max-w-prose">
          Guard set Codex to sum up long sessions once they pass {size(state)}.
          That keeps the chat short but can raise your bill, because Codex then reads files again.
        </p>
        <ActionButton variant="outline" disabled={disabled || saving}
          onClick={() => { if (gate?.enabled) setProof({ error: null }); else void remove(); }}>
          {saving ? "Removing…" : "Remove"}
        </ActionButton>
      </div>
      {error ? <p role="alert" className="guard-settings-caption pb-3 text-amber-800">{error}</p> : null}
    </SettingsFormSection>
    <SettingsSaveProofModal open={proof !== null} mode="verify-save" gate={gate}
      title="Approve removing the Codex summary size"
      detail="Guard removes the size it added to your Codex config. A size you set yourself stays."
      confirmLabel="Remove" error={proof?.error ?? null} pending={saving}
      onCancel={() => setProof(null)}
      onConfirm={(credentials) => { void remove({ currentPassword: credentials.currentPassword, totpCode: credentials.totpCode }); }} />
  </>;
}
