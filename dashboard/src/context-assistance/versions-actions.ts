import type { ContextAssistanceStatus } from "./types";
import type { CigarSelectionJob, CigarVersionJob } from "./versions-jobs";
export const cigarVersionJobId = () => "dashboard:" + crypto.randomUUID();
export function canCommitCigarJob(job: CigarSelectionJob, status: ContextAssistanceStatus | null): boolean {
  return status !== null && job.can_commit && !job.cleanup_pending && job.expected_generation === status.generation
    && (job.initial_selection ? status.preferences.runtime_id === "" : job.source_runtime_id === status.preferences.runtime_id);
}
export function cigarJobPending(job: CigarVersionJob): boolean {
  return job.worker_live === true || (!job.recovery_available && !["ready", "completed", "cancelled", "failed", "recovery_required"].includes(job.phase));
}
/** Jobs that still need Guard or the user; finished history stays out of "In progress". */
export function cigarJobActive(job: CigarVersionJob): boolean {
  return cigarJobPending(job) || job.can_commit || job.recovery_available || job.phase === "recovery_required";
}
