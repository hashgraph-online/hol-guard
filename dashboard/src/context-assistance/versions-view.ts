import type { CigarVersionsRequest } from "./versions-api";
export type CigarVersionAction = { input: CigarVersionsRequest; title: string; detail: string };
export type CigarVersionActionHandler = (action: CigarVersionAction) => void;
const control = "inline-flex min-h-11 items-center justify-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 motion-reduce:transition-none";
export const versionButton = control + " border border-slate-200 bg-white text-brand-dark hover:border-slate-300 hover:bg-slate-50";
export const versionPrimary = control + " border border-transparent bg-brand-blue text-white shadow-sm shadow-brand-blue/20 hover:bg-brand-blue/90";
export const versionQuiet = control + " text-brand-dark/80 hover:bg-brand-dark/[0.05] hover:text-brand-dark";
export const versionField = "mt-1.5 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark transition-colors hover:border-brand-blue/40 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:bg-slate-50";
export const versionCard = "space-y-3 rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5";
export const versionList = "divide-y divide-brand-dark/[0.07] overflow-hidden rounded-2xl border border-brand-dark/10 bg-white";
export const versionHeading = "text-base font-semibold tracking-[-0.01em] text-brand-dark";
export const versionLead = "mt-1 max-w-[62ch] text-sm leading-6 text-brand-dark/70";
export const versionBytes = (bytes: number) => (bytes / 1048576).toFixed(1) + " MiB";
/** Installed runtimes passed Guard's checks on this computer; the record tag predates that wording. */
export const installationLabel = (qualification: "local_candidate" | "guard_qualified") =>
  qualification === "guard_qualified" ? "checked on this computer" : "local development build";
const OS: Record<string, string> = { darwin: "macOS", linux: "Linux", windows: "Windows", win32: "Windows" };
const ARCH: Record<string, string> = { arm64: "Apple silicon", aarch64: "Arm", x86_64: "Intel", amd64: "Intel", x64: "Intel" };
/** "darwin-arm64" reads as "macOS · Apple silicon"; unknown tags pass through untouched. */
export function platformLabel(platform: string | null | undefined): string {
  if (!platform) return "Unknown computer";
  const [os, ...rest] = platform.split("-");
  const arch = rest.join("-");
  const name = OS[os];
  if (!name) return platform;
  const chip = os === "darwin" ? ARCH[arch] : arch === "arm64" || arch === "aarch64" ? "Arm" : ARCH[arch];
  return chip ? name + " · " + chip : name;
}
