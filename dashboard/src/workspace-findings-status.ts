import type { TagTone } from "./approval-center-primitives";
import type { WorkspaceAssessment, WorkspaceRun, WorkspaceWorktree } from "./workspace-findings-api";

const FAILURE_REASONS: Record<string, string> = {
  workspace_snapshot_failed: "Guard could not read this workspace.",
  workspace_snapshot_native_unavailable: "The Guard runtime needed to read files is unavailable.",
  workspace_identity_changed: "The folder now points at a different repository. Add it again.",
  supply_chain_detector_failed: "The dependency check stopped before it finished.",
  assessment_result_too_large: "The result was too large to store.",
  lease_expired: "The assessment took too long and was retried.",
  assessment_timed_out: "The assessment took too long twice and was stopped. It runs again when files change or you choose Assess now.",
  feed_context_unavailable: "Guard could not read its cached advisories.",
};

export type WorktreeStatus = { label: string; tone: TagTone; detail: string | null };

export function sameWorktree(left: WorkspaceWorktree, right: { codebaseKey: string; worktreeKey: string }): boolean {
  return left.codebaseKey === right.codebaseKey && left.worktreeKey === right.worktreeKey;
}

export function worktreeStatus(
  worktree: WorkspaceWorktree,
  newestRun: WorkspaceRun | undefined,
  assessment: WorkspaceAssessment | undefined,
): WorktreeStatus {
  if (worktree.paused) return { label: "Paused", tone: "slate", detail: "Guard is not watching this workspace." };
  if (newestRun?.state === "running") return { label: "Assessing", tone: "slate", detail: null };
  if (newestRun?.state === "queued") return { label: "Queued", tone: "slate", detail: null };
  if (newestRun?.state === "failed" && newestRun.errorCode !== "lease_expired") {
    const detail = FAILURE_REASONS[newestRun.errorCode ?? ""] ?? "The last assessment did not finish.";
    return { label: "Assessment failed", tone: "red", detail };
  }
  if (assessment === undefined) return { label: "Not assessed yet", tone: "slate", detail: null };
  if (worktree.stale) return { label: "Out of date", tone: "attention", detail: "Files changed since the last assessment." };
  if (assessment.partial) return { label: "Partial coverage", tone: "attention", detail: null };
  return { label: "Up to date", tone: "green", detail: null };
}
