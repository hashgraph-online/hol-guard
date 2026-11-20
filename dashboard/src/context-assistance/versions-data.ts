import { fetchContextInstallations } from "./api";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { requestCigarVersions } from "./versions-api";
import { parseCigarCatalog, type CigarCatalog } from "./versions-catalog";
import { parseCigarInterpreters, type CigarInterpreter } from "./versions-interpreters";
import { parseCigarVersionJobs, type CigarVersionJob } from "./versions-jobs";
import { parseCigarUpdateSettings, type CigarUpdateSettings } from "./versions-preferences";
export type CigarVersionsData = {
  catalog: CigarCatalog; interpreters: CigarInterpreter[]; jobs: CigarVersionJob[];
  updates: CigarUpdateSettings; installations: ContextInstallation[]; state: ContextAssistanceStatus;
};
/** All inputs are native metadata. No discovery, imports, verification or automatic effects. */
export async function loadCigarVersionsData(signal: AbortSignal): Promise<CigarVersionsData> {
  const [releases, interpreters, jobs, updates] = await Promise.all([
    requestCigarVersions({ action: "releases" }, undefined, signal),
    requestCigarVersions({ action: "interpreters" }, undefined, signal),
    requestCigarVersions({ action: "jobs" }, undefined, signal),
    requestCigarVersions({ action: "preferences" }, undefined, signal),
  ]);
  const catalog = parseCigarCatalog(releases.result), python = parseCigarInterpreters(interpreters.result);
  const progress = parseCigarVersionJobs(jobs.result), preferences = parseCigarUpdateSettings(updates.result);
  const state = await fetchContextInstallations(signal);
  if (state.installation_options === null) throw new Error("Refresh CIGAR updates to read registered installations.");
  return { catalog, interpreters: python, jobs: progress, updates: preferences, installations: state.installation_options, state };
}
