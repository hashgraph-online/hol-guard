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
export function installationLabel(qualification: "local_candidate" | "guard_qualified" | "guard_builtin"): string {
  if (qualification === "guard_builtin") return "built into Guard, no Python needed";
  if (qualification === "guard_qualified") return "checked on this computer";
  return "local development build";
}
/** Who looks after a runtime: shipped in Guard, installed by Guard, or added by hand. */
export function runtimeOwnerLabel(item: { builtin?: boolean; managed?: boolean }): string {
  if (item.builtin) return "ships with Guard";
  if (item.managed) return "Guard managed";
  return "added outside Guard";
}
/** "Python 3.12.4", or "Built into Guard" for the engine that needs no Python. */
export const runtimeHostLabel = (python: [number, number, number] | null) =>
  python === null ? "Built into Guard" : "Python " + python.join(".");
const OS: Record<string, string> = { darwin: "macOS", linux: "Linux", windows: "Windows", win32: "Windows" };
const ARCH: Record<string, string> = { arm64: "Apple silicon", aarch64: "Arm", x86_64: "Intel", amd64: "Intel", x64: "Intel" };
/** "darwin-arm64" reads as "macOS · Apple silicon"; unknown tags pass through untouched. */
export function platformLabel(platform: string | null | undefined): string {
  if (!platform) return "Unknown computer";
  // Linux tags carry a libc suffix ("linux-x64-gnu", "linux-arm64-musl"); the chip is the first token.
  const [os, arch = ""] = platform.split("-");
  const name = OS[os];
  if (!name) return platform;
  const arm = arch === "arm64" || arch === "aarch64";
  const chip = arm && os !== "darwin" ? "Arm" : ARCH[arch];
  return chip ? name + " · " + chip : name;
}
