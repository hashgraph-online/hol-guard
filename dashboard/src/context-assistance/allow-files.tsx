import { useEffect, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig, GuardContextAssistanceConfig } from "../guard-types";
import { SettingsSaveProofModal, type SettingsSaveProofCredentials } from "../settings-save-proof-modal";
import { saveCigarPreference } from "./one-click-api";

/** The two switches prompts need: Context for AI apps, and reading the project's documents. */
export function allowProjectFilesPreferences(previous: GuardContextAssistanceConfig): GuardContextAssistanceConfig {
  return { ...previous,
    sources: { ...previous.sources, workspace_documents: true, source_set_id: previous.sources.source_set_id || "selected-workspaces" },
    features: { ...previous.features, agent_context: true } };
}

type Options = {
  saved: GuardContextAssistanceConfig | null;
  dirty: boolean;
  disabled: boolean;
  gate: GuardApprovalGatePublicConfig | null;
  onSaved: (config: GuardContextAssistanceConfig, previous: GuardContextAssistanceConfig) => void;
  /** New settings restart CIGAR, so a running CIGAR is woken straight back up. */
  onRestart: () => void;
};

export type CigarAllowFiles = ReturnType<typeof useCigarAllowFiles>;

/** Turns on reading project files from wherever the page notices it is off, without a trip to Settings. */
export function useCigarAllowFiles(options: Options) {
  const [proof, setProof] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(options);
  latest.current = options;
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  async function save(credentials?: SettingsSaveProofCredentials) {
    const { saved, dirty, disabled } = latest.current;
    if (!saved || dirty || disabled || busy) return;
    setBusy(true); setError(null);
    try {
      const next = await saveCigarPreference(allowProjectFilesPreferences(saved), credentials);
      if (!mounted.current) return;
      setProof(false);
      latest.current.onSaved(next, saved);
      if (next.enabled) latest.current.onRestart();
    } catch (cause) {
      if (!mounted.current) return;
      setError(cause instanceof Error ? cause.message : "Guard did not save this setting. Try again.");
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  return {
    available: options.saved !== null && !options.dirty && !options.disabled,
    busy, error,
    start: () => { setError(null); if (latest.current.gate?.enabled) setProof(true); else void save(); },
    proofOpen: proof, cancel: () => { if (!busy) { setProof(false); setError(null); } },
    confirm: (credentials: SettingsSaveProofCredentials) => void save(credentials),
  };
}

export function CigarAllowFilesProof({ allow, gate }: { allow: CigarAllowFiles; gate: GuardApprovalGatePublicConfig | null }) {
  return <SettingsSaveProofModal open={allow.proofOpen} mode="verify-save" gate={gate} title="Let CIGAR read project files"
    detail="Prompts in your AI apps will get the few project files that match them. Secrets, keys, hidden files and anything your .gitignore leaves out stay skipped."
    confirmLabel="Turn on" error={allow.error} pending={allow.busy} onCancel={allow.cancel} onConfirm={allow.confirm} />;
}

/** One button and one line, for the home screen and for adding a project. */
export function CigarAllowFilesButton({ allow, className, caption }: { allow: CigarAllowFiles; className: string; caption?: string }) {
  return <div className="cigar-allow-files">
    <button type="button" className={className} disabled={!allow.available || allow.busy} onClick={allow.start}>
      {allow.busy ? "Turning on…" : "Let CIGAR read project files"}</button>
    {allow.error && !allow.proofOpen ? <p role="alert" className="cigar-allow-error">{allow.error}</p>
      : caption ? <p className="cigar-setup-caption">{caption}</p> : null}
  </div>;
}
