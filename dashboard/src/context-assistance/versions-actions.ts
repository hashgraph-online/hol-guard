import type { ContextAssistanceStatus } from "./types";
import type { CigarCatalog, CigarCatalogBuild, CigarInterpreterBuild } from "./versions-catalog";
import type { CigarSelectionJob, CigarVersionJob } from "./versions-jobs";
import type { CigarUpdateSettings } from "./versions-preferences";
export const cigarVersionJobId = () => "dashboard:" + crypto.randomUUID();
export function canCommitCigarJob(job: CigarSelectionJob, status: ContextAssistanceStatus | null): boolean {
  return status !== null && job.can_commit && !job.cleanup_pending && job.expected_generation === status.generation
    && (job.initial_selection ? status.preferences.runtime_id === "" : job.source_runtime_id === status.preferences.runtime_id);
}
export function cigarJobPending(job: CigarVersionJob): boolean {
  return job.worker_live === true || (!job.recovery_available && !["ready", "completed", "cancelled", "failed", "recovery_required"].includes(job.phase));
}
export function cigarBuildBlock(catalog: CigarCatalog, build: CigarCatalogBuild, updates: CigarUpdateSettings): string | null {
  if (build.withdrawn) return "This build has been withdrawn.";
  if (!catalog.catalog.fresh_for_preparation) return "Refresh the catalog before preparing a build.";
  const host = build.platforms.find((p) => p.platform === catalog.host_platform);
  if (!host) return "No artifact is available for this Guard host.";
  if (!host.has_wheel) return "This entry has no installable SDK package.";
  if (build.channel !== "stable") return "Preview and local candidate installation is unavailable in this Guard build.";
  if (updates.effective.pinned_build && updates.effective.pinned_build !== build.identity.build_id) return "Update preferences pin another build.";
  return null;
}
export function cigarPythonBlock(catalog: CigarCatalog, build: CigarInterpreterBuild): string | null {
  if (build.withdrawn) return "This Python build has been withdrawn.";
  if (!catalog.catalog.fresh_for_preparation) return "Refresh the catalog before preparing Python.";
  if (build.platform !== catalog.host_platform) return "This Python build is for another Guard host.";
  if (build.qualification === "local_candidate") return "This Python build is a local development candidate.";
  return null;
}
