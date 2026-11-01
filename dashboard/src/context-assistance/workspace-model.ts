import type { ContextAssistanceStatus, ContextInstallation } from "./types";

export const CIGAR_TABS = [
  { value: "overview", label: "Overview" },
  { value: "runtime", label: "Runtime & preferences" },
  { value: "versions", label: "Versions & updates" },
  { value: "access", label: "Sources & AI apps" },
  { value: "data", label: "Data & privacy" },
  { value: "tutorials", label: "Tutorials" },
  { value: "guide", label: "How it works" },
] as const;

export type CigarTab = typeof CIGAR_TABS[number]["value"];
export type CigarSetupStep = {
  title: string;
  description: string;
  complete: boolean;
  action: string;
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

/** Registration is metadata. Only the native effective state proves readiness. */
export function cigarSetupSteps(
  status: ContextAssistanceStatus | null,
  installations: ContextInstallation[] | null,
): CigarSetupStep[] {
  const registered = (installations?.length ?? 0) > 0 || status?.runtime !== null && status?.runtime !== undefined;
  const selected = Boolean(status?.preferences.runtime_id) && (
    installations?.some((item) => item.runtime_id === status?.preferences.runtime_id) === true
    || status?.runtime !== null && status?.runtime !== undefined
  );
  return [
    {
      title: "Connect a local runtime",
      description: registered
        ? "A registered CIGAR bundle with Python 3.14 is available on this machine."
        : "Register an approved CIGAR bundle that uses final CPython 3.14, then refresh the runtime list.",
      complete: registered,
      action: registered ? "View runtimes" : "Set up runtime",
      tab: "runtime",
    },
    {
      title: "Choose your preferences",
      description: "Select the runtime, turn on CIGAR, choose the features you want, and save your preferences.",
      complete: selected && status?.requested_enabled === true,
      action: "Choose preferences",
      tab: "runtime",
    },
    {
      title: "Start context assistance",
      description: "Start the saved runtime. Guard verifies Python, the CIGAR package, and its worker before reporting Ready.",
      complete: status?.effective_enabled === true,
      action: status?.effective_enabled ? "Manage runtime" : "Check & start",
      tab: "runtime",
    },
  ];
}

export function cigarRuntimeSummary(
  status: ContextAssistanceStatus | null,
  installations: ContextInstallation[] | null,
): { label: string; detail: string } {
  if (status?.runtime && status.effective_enabled) return {
    label: "Python " + status.runtime.interpreter.version.join("."),
    detail: "CIGAR " + status.runtime.package_version + " · running locally",
  };
  const selected = installations?.find((item) => item.runtime_id === status?.preferences.runtime_id);
  if (selected) return {
    label: "Python " + selected.python_version.join("."),
    detail: "Selected · activation verifies this bundle again",
  };
  if (installations?.length) return {
    label: "Python " + installations[0].python_version.join("."),
    detail: installations.length === 1 ? "Registered · choose it to get started" : String(installations.length) + " registered runtimes · choose one",
  };
  return {
    label: installations === null ? "Runtime status pending" : "Runtime setup needed",
    detail: "Requires a registered CIGAR bundle with CPython 3.14",
  };
}
