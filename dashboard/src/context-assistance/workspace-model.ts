import type { ContextAssistanceStatus } from "./types";

/** The calm home screen has no tabs. These sections live behind the Advanced disclosure. */
export const CIGAR_TABS = [
  { value: "runtime", label: "Settings" },
  { value: "access", label: "Projects & AI apps" },
  { value: "versions", label: "Updates" },
  { value: "data", label: "Privacy" },
  { value: "guide", label: "Guides" },
] as const;

export type CigarAdvancedTab = typeof CIGAR_TABS[number]["value"];
/** "overview" is the home screen: Advanced stays closed. */
export type CigarTab = CigarAdvancedTab | "overview";

/** A saved on preference permits a start attempt, not a claim of readiness. */
export function canStartCigar(status: ContextAssistanceStatus | null, dirty: boolean): boolean {
  return !dirty && status !== null && status.requested_enabled && status.preferences.enabled
    && status.effective_preferences.enabled && status.verification_permitted
    && Boolean(status.preferences.runtime_id) && !status.effective_enabled && status.job === null;
}

export function cigarTabFromSearch(search: string): CigarTab {
  const value = new URLSearchParams(search).get("section");
  if (value === "tutorials") return "guide";
  return CIGAR_TABS.find((tab) => tab.value === value)?.value ?? "overview";
}

/** Turned on and verified before, now resting or waking. It needs no click to come back. */
export function cigarWaking(status: ContextAssistanceStatus | null): boolean {
  if (!status || status.effective_enabled) return false;
  return status.diagnostic === "runtime_resting" || (status.requested_enabled && status.job?.operation === "activate");
}

/** Prompts only get project files when both switches are on. */
export function cigarHelpsPrompts(status: ContextAssistanceStatus | null): boolean {
  const effective = status?.effective_preferences;
  return effective?.features.agent_context === true && effective.sources.workspace_documents === true;
}

export type CigarHomeCopy = { headline: string; detail: string; setupHint: boolean };

const PROMPT_PROMISE = "Every prompt you send in Claude Code or Codex gets the few project files that match it.";

/** One headline and one sentence for the home screen. Only native state proves CIGAR is on. */
export function cigarHomeCopy(status: ContextAssistanceStatus | null, loading: boolean, running: boolean): CigarHomeCopy {
  if (running) return { headline: "Turning on CIGAR", detail: "Guard is setting it up. You can keep browsing.", setupHint: false };
  if (!status) {
    if (loading) return { headline: "Checking CIGAR", detail: "One moment.", setupHint: false };
    return { headline: "CIGAR status unavailable", detail: "Guard did not answer. Try refreshing the status.", setupHint: false };
  }
  if (status.effective_enabled) {
    if (cigarHelpsPrompts(status)) return { headline: "CIGAR is on", detail: PROMPT_PROMISE, setupHint: false };
    return { headline: "CIGAR is on, but prompts get no files yet",
      detail: "Turn on Context for AI apps and Allow selected workspace documents in Settings.", setupHint: true };
  }
  if (cigarWaking(status)) {
    return { headline: "CIGAR is on", detail: "It rests when nothing needs it and wakes up by itself. You do not need to turn it on again.", setupHint: false };
  }
  if (status.requested_enabled) {
    return { headline: "CIGAR is not running", detail: "It is saved as on but has not started. Turn it on to start it.", setupHint: false };
  }
  return { headline: "CIGAR is off", detail: "Turn it on and " + PROMPT_PROMISE.charAt(0).toLowerCase() + PROMPT_PROMISE.slice(1), setupHint: false };
}
