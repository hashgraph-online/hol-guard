import type { CigarVersionsRequest } from "./versions-api";
export type CigarVersionAction = { input: CigarVersionsRequest; title: string; detail: string };
export type CigarVersionActionHandler = (action: CigarVersionAction) => void;
export const versionButton = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
export const versionField = "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark";
export const versionCard = "space-y-3 rounded-xl border border-slate-200 bg-white p-4";
export const versionBytes = (bytes: number) => (bytes / 1048576).toFixed(1) + " MiB";
/** Installed runtimes passed Guard's checks on this computer; the record tag predates that wording. */
export const installationLabel = (qualification: "local_candidate" | "guard_qualified") =>
  qualification === "guard_qualified" ? "checked on this computer" : "local development build";
