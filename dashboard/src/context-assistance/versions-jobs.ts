import { ContextAssistanceApiError } from "./api";
import { isCigarCoreLabel, isCigarProducerVersion } from "./release-version";

export type CigarRecoveryAttempt = {
  id: string; expected_generation: string; started_at_ms: number; deadline_at_ms: number;
};
type JobBase = {
  schema: string; job_id: string; phase: string; code: string;
  created_at_ms: number; updated_at_ms: number; deadline_at_ms: number;
  worker_live: boolean | null; cancel_requested: boolean; recovery_available: boolean;
};
export type CigarSelectionJob = JobBase & {
  family: "selection"; operation: "switch" | "rollback" | "select" | "recover";
  target_runtime_id: string; source_runtime_id: string | null; expected_generation: string;
  can_commit: boolean; keeps_disabled: boolean; reconnect_required: boolean;
  initial_selection: boolean; cleanup_pending: boolean; recovery_attempt: CigarRecoveryAttempt | null;
};
export type CigarPreparationJob = JobBase & {
  family: "preparation"; operation: "install" | "verify" | "setup_interpreter" | "refresh_catalog";
  can_commit: false; build_id?: string; interpreter_id?: string | null; runtime_id?: string;
  sdk_version?: string; core_version?: string;
};
export type CigarVersionJob = CigarSelectionJob | CigarPreparationJob;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const id = (v: unknown): v is string => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const word = (v: unknown): v is string => typeof v === "string" && /^[a-z0-9_]{1,128}$/.test(v);
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
export const isCigarGeneration = (v: unknown): v is string => typeof v === "string"
  && /^[1-9][0-9]{0,19}$/.test(v) && (v.length < 20 || v <= "18446744073709551615");
function invalid(): never {
  throw new ContextAssistanceApiError("versions_job_invalid", "Guard returned incompatible CIGAR job data. Refresh jobs.");
}
function recovery(v: unknown): CigarRecoveryAttempt | null {
  if (v === undefined || v === null) return null;
  if (!object(v) || typeof v.id !== "string" || !/^[a-f0-9]{32}$/.test(v.id)
    || !isCigarGeneration(v.expected_generation) || !count(v.started_at_ms)
    || !count(v.deadline_at_ms) || v.deadline_at_ms < v.started_at_ms) invalid();
  return { id: v.id, expected_generation: v.expected_generation, started_at_ms: v.started_at_ms, deadline_at_ms: v.deadline_at_ms };
}

/** Validate native metadata only. This never derives SDK eligibility or starts work. */
export function parseCigarVersionJob(value: unknown): CigarVersionJob {
  if (!object(value) || !id(value.job_id) || !word(value.phase) || !word(value.code)
    || !count(value.created_at_ms) || !count(value.updated_at_ms) || value.updated_at_ms < value.created_at_ms
    || !count(value.deadline_at_ms) || value.deadline_at_ms < value.created_at_ms
    || !(value.worker_live === null || typeof value.worker_live === "boolean")
    || typeof value.cancel_requested !== "boolean" || typeof value.recovery_available !== "boolean"
    || (value.worker_live === true && value.recovery_available)) invalid();
  const base = { schema: String(value.schema), job_id: value.job_id, phase: value.phase, code: value.code,
    created_at_ms: value.created_at_ms, updated_at_ms: value.updated_at_ms, deadline_at_ms: value.deadline_at_ms,
    worker_live: value.worker_live, cancel_requested: value.cancel_requested, recovery_available: value.recovery_available };
  if (value.schema === "guard-cigar-switch-job.v1") {
    if (!["switch", "rollback", "select", "recover"].includes(String(value.operation))
      || !id(value.target_runtime_id) || !(value.source_runtime_id === null || id(value.source_runtime_id))
      || !isCigarGeneration(value.expected_generation) || value.authority_restored !== false
      || ["can_commit", "keeps_disabled", "reconnect_required", "initial_selection", "cleanup_pending"]
        .some((key) => typeof value[key] !== "boolean")
      || value.keeps_disabled === value.reconnect_required
      || (value.initial_selection ? value.source_runtime_id !== null || !value.keeps_disabled
        : !id(value.source_runtime_id) || value.source_runtime_id === value.target_runtime_id)
      || (value.operation === "select" && !value.initial_selection)
      || (["switch", "rollback"].includes(String(value.operation)) && value.initial_selection)
      || (value.can_commit && (value.phase !== "ready" || value.worker_live !== true || value.cancel_requested))) invalid();
    const attempt = recovery(value.recovery_attempt);
    if (value.operation === "recover" ? !attempt || attempt.expected_generation !== value.expected_generation || value.can_commit
      : attempt !== null) invalid();
    return { ...base, family: "selection", operation: value.operation as CigarSelectionJob["operation"],
      target_runtime_id: value.target_runtime_id, source_runtime_id: value.source_runtime_id,
      expected_generation: value.expected_generation, can_commit: value.can_commit as boolean,
      keeps_disabled: value.keeps_disabled as boolean, reconnect_required: value.reconnect_required as boolean,
      initial_selection: value.initial_selection as boolean, cleanup_pending: value.cleanup_pending as boolean,
      recovery_attempt: attempt };
  }
  const schemas: Record<string, string[]> = {
    "guard-cigar-install-job.v1": ["install", "verify"],
    "guard-cigar-python-setup-job.v1": ["setup_interpreter"],
    "guard-cigar-catalog-refresh-job.v1": ["refresh_catalog"],
  };
  if (!Object.hasOwn(schemas, String(value.schema)) || !schemas[String(value.schema)].includes(String(value.operation))
    || value.activation_granted !== false) invalid();
  if (value.operation === "refresh_catalog") return { ...base, family: "preparation", operation: "refresh_catalog", can_commit: false };
  if (!id(value.build_id)) invalid();
  if (value.operation === "setup_interpreter") {
    if (!(value.interpreter_id === null || id(value.interpreter_id))
      || (value.phase === "ready" && value.interpreter_id === null)) invalid();
    return { ...base, family: "preparation", operation: "setup_interpreter",
      build_id: value.build_id, interpreter_id: value.interpreter_id, can_commit: false };
  }
  if (!id(value.interpreter_id)) invalid();
  if (!id(value.runtime_id) || !isCigarProducerVersion(value.sdk_version) || !isCigarCoreLabel(value.core_version)) invalid();
  return { ...base, family: "preparation", operation: value.operation as "install" | "verify", build_id: value.build_id,
    interpreter_id: value.interpreter_id, runtime_id: value.runtime_id, sdk_version: value.sdk_version,
    core_version: value.core_version, can_commit: false };
}
export function parseCigarVersionJobs(value: unknown): CigarVersionJob[] {
  if (!object(value) || !Array.isArray(value.jobs) || value.jobs.length > 32) invalid();
  const jobs = value.jobs.map(parseCigarVersionJob);
  if (new Set(jobs.map((job) => job.job_id)).size !== jobs.length) invalid();
  return jobs;
}
