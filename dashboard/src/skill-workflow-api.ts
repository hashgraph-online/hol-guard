import { fetchLocalCliApi } from "./guard-api";
import { startCancelableDiscoveryJob } from "./discovery-job-start";
import { isLocalCliId, normalizeLocalCliList, waitForMcpDiscoveryJob } from "./local-cli-api";

export type LocalSkillRoot = { root_id: string; path: string; available: boolean };
export type LocalSkill = {
  skill_id: string; root_id: string; uri: string; name: string; description: string;
  compatibility: string; requested_tools: string; duplicate_name: boolean; metadata_digest: string;
};
export type LocalSkillPage = {
  skills: LocalSkill[]; known_count: number; matched_count: number; revision: number;
  next_offset: number | null; complete: boolean; issue_count: number;
};
const digest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const integer = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

async function request(payload: Record<string, unknown>, signal?: AbortSignal): Promise<Record<string, unknown>> {
  const response = await fetchLocalCliApi("/v1/local-clis/skills", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload), signal,
  });
  const body: unknown = await response.json();
  if (!response.ok) throw new Error(record(body) && typeof body.message === "string" ? body.message : "Could not read skill metadata.");
  if (!record(body)) throw new Error("Invalid skill metadata response");
  return body;
}

export async function fetchLocalSkillRoots(signal?: AbortSignal): Promise<LocalSkillRoot[]> {
  const body = await request({ operation: "roots" }, signal);
  if (!Array.isArray(body.roots) || body.roots.length > 16 || body.permissions_granted !== false) throw new Error("Invalid skill roots");
  return body.roots.map((root) => {
    if (!record(root) || !digest(root.root_id) || typeof root.path !== "string" || root.path.length > 4096
      || typeof root.available !== "boolean") throw new Error("Invalid skill root");
    return { root_id: root.root_id, path: root.path, available: root.available };
  });
}

export async function scanLocalSkillMetadata(rootIds: string[], signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  const job = await startCancelableDiscoveryJob(signal, (clientJobId) => request(
    { operation: "scan", confirm_metadata_read: true, approved_root_ids: rootIds, client_job_id: clientJobId }, signal,
  ));
  if (job === null) return;
  await waitForMcpDiscoveryJob("inventory:skills", job, signal);
}

export async function fetchLocalSkillPage(
  options: { offset: number; search: string; revision?: number; signal?: AbortSignal },
): Promise<LocalSkillPage> {
  const body = await request({ operation: "list", offset: options.offset, search: options.search,
    ...(options.revision === undefined ? {} : { revision: options.revision }) }, options.signal);
  if (!Array.isArray(body.skills) || body.skills.length > 50 || body.permissions_granted !== false
    || !integer(body.known_count) || body.known_count > 1000 || !integer(body.matched_count)
    || body.matched_count > body.known_count || !integer(body.revision) || !integer(body.issue_count)
    || typeof body.complete !== "boolean" || (body.next_offset !== null && body.next_offset !== options.offset + 50)) {
    throw new Error("Invalid skill inventory");
  }
  const skills = body.skills.map((skill): LocalSkill => {
    if (!record(skill) || !digest(skill.skill_id) || !digest(skill.root_id) || !digest(skill.metadata_digest)
      || skill.origin !== "local-agent-skill" || skill.permission_state !== "not-granted"
      || skill.requirements_complete !== false || skill.instruction_content_loaded !== false
      || typeof skill.name !== "string" || skill.name.length > 64 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(skill.name)
      || typeof skill.description !== "string" || skill.description.length > 1024
      || typeof skill.uri !== "string" || !skill.uri.startsWith("file://") || skill.uri.length > 8192
      || typeof skill.compatibility !== "string" || skill.compatibility.length > 500
      || typeof skill.requested_tools !== "string" || skill.requested_tools.length > 2048
      || typeof skill.duplicate_name !== "boolean") throw new Error("Invalid local skill evidence");
    return { skill_id: skill.skill_id, root_id: skill.root_id, metadata_digest: skill.metadata_digest,
      name: skill.name, description: skill.description, uri: skill.uri, compatibility: skill.compatibility,
      requested_tools: skill.requested_tools, duplicate_name: skill.duplicate_name };
  });
  return { skills, known_count: body.known_count, matched_count: body.matched_count, revision: body.revision,
    next_offset: body.next_offset as number | null, complete: body.complete, issue_count: body.issue_count };
}

export type SkillWorkflowPreflight = {
  skill_id: string; dependency_status: "absent" | "invalid" | "declared"; authority_revision: number;
  inspection: { status: "complete" | "incomplete"; manifest_digest: string | null; entry_count: number };
  native_state: "acknowledged" | "pending" | "failed" | "unavailable";
  expires_at: number;
  requirements: Array<{ connection_id: string; tool_name: string; state: "saved-allow" | "deny" | "ask" | "unresolved" }>;
};

export async function prepareSkillWorkflow(skillId: string, signal: AbortSignal): Promise<SkillWorkflowPreflight | null> {
  if (signal.aborted) return null;
  const job = await startCancelableDiscoveryJob(signal, (clientJobId) => request(
    { operation: "preflight", skill_id: skillId, confirm_directory_read: true, client_job_id: clientJobId }, signal,
  ));
  if (job === null) return null;
  await waitForMcpDiscoveryJob(`skill:${skillId}`, job, signal);
  if (signal.aborted) return null;
  const body = await request({ operation: "preflight-result", skill_id: skillId }, signal);
  if (body.skill_id !== skillId || body.schema_version !== "guard.workflow-preflight.v1"
    || body.dependency_source !== "guard-extension" || !["absent", "invalid", "declared"].includes(String(body.dependency_status))
    || !integer(body.authority_revision) || !integer(body.expires_in_seconds) || body.expires_in_seconds > 30
    || body.requirements_complete !== false || body.permissions_granted !== false
    || body.runtime_checks_required !== true || !Array.isArray(body.requirements) || body.requirements.length > 50
    || !record(body.inspection) || !["complete", "incomplete"].includes(String(body.inspection.status))
    || !integer(body.inspection.entry_count) || body.inspection.permissions_granted !== false
    || (body.inspection.status === "complete" && (typeof body.inspection.manifest_digest !== "string"
      || !/^sha256:[a-f0-9]{64}$/.test(body.inspection.manifest_digest)))) throw new Error("Invalid workflow preflight");
  const requirements = body.requirements.map((entry): SkillWorkflowPreflight["requirements"][number] => {
    if (!record(entry) || typeof entry.connection_id !== "string" || !isLocalCliId(entry.connection_id)
      || typeof entry.tool_name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(entry.tool_name)
      || !["saved-allow", "deny", "ask", "unresolved"].includes(String(entry.state))) throw new Error("Invalid workflow requirement");
    return { connection_id: entry.connection_id, tool_name: entry.tool_name,
      state: entry.state as SkillWorkflowPreflight["requirements"][number]["state"] };
  });
  const native = normalizeLocalCliList({ schema_version: "guard.daemon.local-clis.v1", revision: body.authority_revision,
    items: [], native_publication: body.native_publication }).native_publication;
  return { skill_id: skillId, dependency_status: body.dependency_status as SkillWorkflowPreflight["dependency_status"],
    authority_revision: body.authority_revision, requirements,
    native_state: native?.state ?? "unavailable", inspection: {
      status: body.inspection.status as "complete" | "incomplete", entry_count: body.inspection.entry_count,
      manifest_digest: typeof body.inspection.manifest_digest === "string" ? body.inspection.manifest_digest : null,
    }, expires_at: performance.now() + body.expires_in_seconds * 1000 };
}
