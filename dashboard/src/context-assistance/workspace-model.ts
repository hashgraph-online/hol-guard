import type { ContextAssistanceStatus } from "./types";

export const CIGAR_TABS = [
  { value: "overview", label: "Overview" },
  { value: "runtime", label: "Settings" },
  { value: "versions", label: "Updates" },
  { value: "access", label: "Projects & AI apps" },
  { value: "data", label: "Privacy" },
  { value: "tutorials", label: "Tutorials" },
  { value: "guide", label: "How it works" },
] as const;

export type CigarTab = typeof CIGAR_TABS[number]["value"];
export type CigarSetupStep = {
  title: string;
  description: string;
  complete: boolean;
  action: string | null;
  tab: CigarTab;
};

/** A saved on preference permits a start attempt, not a claim of readiness. */
export function canStartCigar(status: ContextAssistanceStatus | null, dirty: boolean): boolean {
  return !dirty && status !== null && status.requested_enabled && status.preferences.enabled
    && status.effective_preferences.enabled && status.verification_permitted
    && Boolean(status.preferences.runtime_id) && !status.effective_enabled && status.job === null;
}

export function cigarTabFromSearch(search: string): CigarTab {
  const value = new URLSearchParams(search).get("section");
  return CIGAR_TABS.find((tab) => tab.value === value)?.value ?? "overview";
}

/** Turned on and verified before, now resting or waking. It needs no click to come back. */
export function cigarWaking(status: ContextAssistanceStatus | null): boolean {
  if (!status || status.effective_enabled) return false;
  return status.diagnostic === "runtime_resting" || (status.requested_enabled && status.job?.operation === "activate");
}

/** Only native state proves CIGAR is on; later steps stay optional. */
export function cigarSetupSteps(status: ContextAssistanceStatus | null): CigarSetupStep[] {
  const on = status?.effective_enabled === true;
  const resting = status?.diagnostic === "runtime_resting";
  let description = "One click. Guard gets everything ready and checks it first.";
  if (on) description = "CIGAR is running on this computer.";
  else if (resting) description = "CIGAR is on. It rests when nothing needs it.";
  return [
    {
      title: "Turn on CIGAR",
      description,
      complete: on || resting,
      action: null,
      tab: "overview",
    },
    {
      title: "Pick a project folder",
      description: "Optional. Choose exactly which files CIGAR uses for a project, instead of the ones that match each prompt.",
      complete: false,
      action: on ? "Pick a folder" : null,
      tab: "access",
    },
    {
      title: "Connect an AI app (optional)",
      description: "Let an AI app ask CIGAR for the parts of your project it needs. You approve each app.",
      complete: false,
      action: on ? "Connect an app" : null,
      tab: "access",
    },
  ];
}
