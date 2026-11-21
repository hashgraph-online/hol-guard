import { fetchContextInstallations } from "./api";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { requestCigarVersions } from "./versions-api";
import { parseCigarVersionJobs, type CigarVersionJob } from "./versions-jobs";
export type CigarVersionsData = { jobs: CigarVersionJob[]; installations: ContextInstallation[]; state: ContextAssistanceStatus };
/** All inputs are native metadata. No discovery, imports, verification or automatic effects. */
export async function loadCigarVersionsData(signal: AbortSignal): Promise<CigarVersionsData> {
  const jobs = parseCigarVersionJobs((await requestCigarVersions({ action: "jobs" }, undefined, signal)).result);
  const state = await fetchContextInstallations(signal);
  if (state.installation_options === null) throw new Error("Refresh CIGAR to read its installed engine.");
  return { jobs, installations: state.installation_options, state };
}
