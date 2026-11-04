import { useEffect, useState } from "react";
import { isGuardDemoMode } from "../guard-demo";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { SettingsSaveProofModal } from "../settings-save-proof-modal";
import { SettingsFormSection, SettingsToggleRow } from "../settings/settings-row-primitives";
import { ContextAssistanceApiError } from "./api";
import { readCodexLean, saveCodexLean, type CodexLeanState } from "./codex-lean-api";
import type { ContextProof } from "./workspaces-api";

/** The limit Guard writes; it matches `hol-guard context lean on`. */
const LIMIT = 30_000;

type Props = { gate: GuardApprovalGatePublicConfig | null; disabled: boolean };
type Proof = { enabled: boolean; error: string | null };

function message(cause: unknown): string {
  return cause instanceof ContextAssistanceApiError ? cause.message : "Guard could not reach your Codex config. Refresh and try again.";
}

function describe(state: CodexLeanState | null, loading: boolean): string {
  if (loading && !state) return "Checking your Codex config…";
  if (state?.state === "yours") {
    const limit = typeof state.limit === "number" ? state.limit.toLocaleString() : "its own value";
    return `Your Codex config already sets its own limit (${limit} tokens). Guard leaves it as it is.`;
  }
  return `Codex sums up older turns once a session passes ${LIMIT.toLocaleString()} tokens, instead of carrying the whole conversation. Works with or without CIGAR and saves right away.`;
}

/** One switch for Codex's own compaction limit, saved straight to the Codex config. */
export function CodexLeanSessions({ gate, disabled }: Props) {
  const [state, setState] = useState<CodexLeanState | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proof, setProof] = useState<Proof | null>(null);
  const demo = isGuardDemoMode();

  useEffect(() => {
    if (demo) return;
    const controller = new AbortController();
    readCodexLean(controller.signal).then(setState, (cause: unknown) => {
      if (!controller.signal.aborted) setError(message(cause));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [demo]);

  async function save(enabled: boolean, credentials?: ContextProof) {
    setSaving(true);
    setError(null);
    try {
      setState(await saveCodexLean(enabled, credentials));
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

  function change(enabled: boolean) {
    if (gate?.enabled) setProof({ enabled, error: null });
    else void save(enabled);
  }

  if (demo) return null;
  const yours = state?.state === "yours";
  return <>
    <SettingsFormSection title="Long Codex sessions">
      <SettingsToggleRow label="Keep long Codex sessions lean" checked={state?.state === "on"}
        description={describe(state, loading)} disabled={disabled || saving || loading || yours || state === null}
        onChange={change} />
      {error ? <p role="alert" className="guard-settings-caption py-3 text-amber-800">{error}</p> : null}
    </SettingsFormSection>
    <SettingsSaveProofModal open={proof !== null} mode="verify-save" gate={gate}
      title={proof?.enabled === false ? "Approve turning off lean Codex sessions" : "Approve lean Codex sessions"}
      detail={proof?.enabled === false
        ? "Guard removes the limit it added to your Codex config. A limit you set yourself stays."
        : `Guard adds model_auto_compact_token_limit = ${LIMIT} to your Codex config. Turn the switch off to remove it again.`}
      confirmLabel={proof?.enabled === false ? "Turn off" : "Turn on"} error={proof?.error ?? null} pending={saving}
      onCancel={() => setProof(null)}
      onConfirm={(credentials) => { if (proof) void save(proof.enabled, { currentPassword: credentials.currentPassword, totpCode: credentials.totpCode }); }} />
  </>;
}
