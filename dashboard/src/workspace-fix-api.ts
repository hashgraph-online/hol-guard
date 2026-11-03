import { fetchGuardApi } from "./guard-api";
import type { WorktreeKeys } from "./workspace-findings-api";

const FIX_PROPOSALS_PATH = "/v1/supply-chain/workspace-fix-proposals";

/**
 * `prepared` waits for review; `applied` waits for a complete re-check, which
 * settles it as `verified_fixed` or `still_present`. `stale` means the
 * manifest changed after the review, so nothing was written.
 */
export type FixProposalState = "prepared" | "applied" | "verified_fixed" | "still_present" | "stale";

export type FixEdit = { section: string; fromSpec: string; toSpec: string };

export type FixProposal = WorktreeKeys & {
  proposalId: string;
  findingId: string;
  packageName: string;
  fixVersion: string;
  advisoryIds: string[];
  manifestPath: string;
  edits: FixEdit[];
  /** Present only while the proposal still waits for review. */
  diff: string | null;
  state: FixProposalState;
  createdAtMs: number;
  appliedAtMs: number | null;
  verifiedAtMs: number | null;
};

export type SkippedManifest = { manifestPath: string; reason: string };

export type PreparedFix = { proposals: FixProposal[]; skipped: SkippedManifest[]; truncated: boolean };

export type AppliedFix = { proposal: FixProposal; lockfiles: string[]; verificationQueued: boolean };

export class FixRequestError extends Error {
  readonly code: string;
  readonly reason: string | null;
  /** Files a refused prepare left unchanged, so the review can still list them. */
  readonly skipped: SkippedManifest[];
  readonly truncated: boolean;

  constructor(code: string, reason: string | null, skipped: SkippedManifest[] = [], truncated = false) {
    super(fixErrorMessage(code, reason));
    this.name = "FixRequestError";
    this.code = code;
    this.reason = reason;
    this.skipped = skipped;
    this.truncated = truncated;
  }
}

const STATES = new Set<string>(["prepared", "applied", "verified_fixed", "still_present", "stale"]);

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function time(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function normalizeEdit(value: unknown): FixEdit | null {
  const item = record(value);
  const section = text(item.section);
  const fromSpec = text(item.from_spec);
  const toSpec = text(item.to_spec);
  return section && fromSpec && toSpec ? { section, fromSpec, toSpec } : null;
}

export function normalizeFixProposal(value: unknown): FixProposal | null {
  const item = record(value);
  const proposalId = text(item.proposal_id);
  const codebaseKey = text(item.codebase_key);
  const worktreeKey = text(item.worktree_key);
  const findingId = text(item.finding_id);
  const packageName = text(item.package_name);
  const fixVersion = text(item.fix_version);
  const manifestPath = text(item.manifest_path);
  const state = text(item.state);
  const createdAtMs = time(item.created_at_ms);
  const edits = list(item.edits)
    .map(normalizeEdit)
    .filter((entry): entry is FixEdit => entry !== null);
  if (
    !proposalId || !codebaseKey || !worktreeKey || !findingId || !packageName || !fixVersion ||
    !manifestPath || !state || !STATES.has(state) || createdAtMs === null || edits.length === 0
  ) {
    return null;
  }
  return {
    proposalId,
    codebaseKey,
    worktreeKey,
    findingId,
    packageName,
    fixVersion,
    advisoryIds: list(item.advisory_ids).filter((entry): entry is string => typeof entry === "string"),
    manifestPath,
    edits,
    diff: state === "prepared" ? text(item.diff) : null,
    state: state as FixProposalState,
    createdAtMs,
    appliedAtMs: time(item.applied_at_ms),
    verifiedAtMs: time(item.verified_at_ms),
  };
}

function normalizeSkipped(value: unknown): SkippedManifest[] {
  return list(value).flatMap((entry) => {
    const item = record(entry);
    const manifestPath = text(item.manifest_path);
    const reason = text(item.reason);
    return manifestPath && reason ? [{ manifestPath, reason }] : [];
  });
}

function normalizeProposals(value: unknown): FixProposal[] {
  return list(value)
    .map(normalizeFixProposal)
    .filter((entry): entry is FixProposal => entry !== null);
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetchGuardApi(path, init);
  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const detail = record(body);
    throw new FixRequestError(
      text(detail.error) ?? "workspace_fix_failed",
      text(detail.reason),
      normalizeSkipped(detail.skipped),
      detail.truncated === true,
    );
  }
  return body;
}

function postJson(path: string, payload: Record<string, string>): Promise<unknown> {
  return request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function fetchFixProposals(worktree: WorktreeKeys, signal?: AbortSignal): Promise<FixProposal[]> {
  const query = new URLSearchParams({ codebase_key: worktree.codebaseKey, worktree_key: worktree.worktreeKey });
  return normalizeProposals(record(await request(`${FIX_PROPOSALS_PATH}?${query}`, { signal })).proposals);
}

export async function prepareFix(worktree: WorktreeKeys, findingId: string): Promise<PreparedFix> {
  const body = record(
    await postJson(FIX_PROPOSALS_PATH, {
      codebase_key: worktree.codebaseKey,
      worktree_key: worktree.worktreeKey,
      finding_id: findingId,
    }),
  );
  return {
    proposals: normalizeProposals(body.proposals),
    skipped: normalizeSkipped(body.skipped),
    truncated: body.truncated === true,
  };
}

export async function applyFix(proposalId: string): Promise<AppliedFix> {
  const body = record(await postJson(`${FIX_PROPOSALS_PATH}/${encodeURIComponent(proposalId)}/apply`, {}));
  const proposal = normalizeFixProposal(body.proposal);
  if (proposal === null) throw new FixRequestError("workspace_fix_failed", null);
  return {
    proposal,
    lockfiles: list(body.lockfiles).filter((entry): entry is string => typeof entry === "string"),
    verificationQueued: body.verification_queued === true,
  };
}

const SKIP_REASONS: Record<string, string> = {
  spec_workspace_protocol: "It points at another package in this workspace.",
  spec_npm_alias: "It installs the package under another name.",
  spec_git_or_url: "It installs from a Git repository or URL.",
  spec_local_path: "It installs from a local folder or file.",
  spec_dist_tag: "It follows a release tag rather than a version.",
  spec_not_plain_semver: "Its version range is too complex to change safely.",
  spec_not_a_string: "Its entry is not a version string.",
  declared_range_already_covers_fix: "Its range already allows the fixed version. Update the lockfile instead.",
  manifest_duplicate_section: "The file declares the same section twice.",
  manifest_duplicate_declaration: "The file declares the package twice.",
  manifest_invalid_json: "The file is not valid JSON.",
  manifest_too_large: "The file is too large to edit safely.",
  manifest_too_deep: "The file is nested too deeply to edit safely.",
  manifest_is_symlink: "The file is a symbolic link.",
  manifest_not_regular: "The path is not a regular file.",
  manifest_unreadable: "The file could not be read.",
  diff_too_large: "The change would be too large to review.",
};

export function skippedManifestMessage(reason: string): string {
  return SKIP_REASONS[reason] ?? "Guard could not change this file safely.";
}

const UNSUPPORTED_REASONS: Record<string, string> = {
  unsupported_source: "Guard prepares fixes for dependency findings only.",
  unsupported_ecosystem: "Guard prepares fixes for npm dependencies only.",
  no_fix_version: "No fixed version has been published yet.",
  finding_incomplete: "This finding is missing the details a fix needs. Run Assess now, then try again.",
  transitive_dependency:
    "No package.json lists this package directly. It comes in through another dependency, so update that dependency instead.",
  manifest_scan_incomplete: "Guard could not read every package.json in this workspace, so it prepared no change.",
};

const ERROR_MESSAGES: Record<string, string> = {
  no_assessed_run: "Guard has not finished checking this workspace yet. Wait for the check, then try again.",
  finding_not_found: "This finding changed since the last check. Refresh to see the current findings.",
  worktree_not_found: "This workspace is no longer tracked. Refresh the list.",
  worktree_paused: "Resume this workspace before applying a fix.",
  worktree_unavailable: "Guard cannot reach this workspace folder. Check that it still exists.",
  fix_proposal_not_found: "This fix is no longer available. Prepare it again.",
  fix_proposal_not_prepared: "This fix was already applied or replaced.",
  fix_proposal_stale: "The file changed after you reviewed this fix, so Guard wrote nothing. Prepare the fix again.",
  fix_apply_unsupported:
    "Guard cannot apply fixes on this system yet, so it wrote nothing. Make the change shown above yourself.",
  fix_native_unavailable: "The Guard runtime needed to edit files is unavailable. Repair Guard, then try again.",
  fix_apply_failed: "Guard could not write the change. The file was left as it was.",
};

export function fixErrorMessage(code: string, reason: string | null): string {
  if (code === "fix_unsupported") {
    if (reason && UNSUPPORTED_REASONS[reason]) return UNSUPPORTED_REASONS[reason];
    if (reason && SKIP_REASONS[reason]) return `Guard prepared no change. ${SKIP_REASONS[reason]}`;
    return "Guard cannot prepare a fix for this finding.";
  }
  return ERROR_MESSAGES[code] ?? "Guard could not prepare or apply this fix. Check that Guard is running, then retry.";
}
