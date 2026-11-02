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

/** Only the native effective state proves CIGAR is on; later steps stay optional. */
export function cigarSetupSteps(status: ContextAssistanceStatus | null): CigarSetupStep[] {
  const on = status?.effective_enabled === true;
  return [
    {
      title: "Turn on CIGAR",
      description: on ? "CIGAR is running on this computer." : "One click. Guard gets everything ready and checks it first.",
      complete: on,
      action: null,
      tab: "overview",
    },
    {
      title: "Pick a project folder",
      description: "Choose the folder CIGAR may read. It reads nothing else.",
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
