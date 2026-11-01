import type { GuardContextAssistanceConfig } from "../guard-types";
import type { ContextAssistanceStatus, ContextInstallation, ContextRuntime } from "./types";
import { isContextExecutionObservation } from "./execution-observation";
import { isCigarCoreLabel, isCigarProducerVersion, isCigarReleaseBinding } from "./release-version";

const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown, max = 256): value is string =>
  typeof value === "string" && value.length <= max;
const digest = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const revision = (value: unknown): value is string =>
  typeof value === "string" && /^[1-9][0-9]{0,19}$/.test(value);
const version = (value: unknown): value is [number, number, number] =>
  Array.isArray(value) && value.length === 3
  && value.every((part) => Number.isSafeInteger(part) && part >= 0 && part <= 65535);

function config(value: unknown): value is GuardContextAssistanceConfig {
  if (!record(value) || value.schema_version !== 1 || typeof value.enabled !== "boolean"
      || !text(value.runtime_id, 128)
      || !["low_memory", "balanced", "custom"].includes(String(value.resource_profile))
      || !record(value.features) || !record(value.sources)
      || !record(value.storage) || !record(value.limits)) return false;
  const { features, sources, storage, limits } = value;
  return ["review_briefs", "agent_context", "shared_agents"].every((key) => typeof features[key] === "boolean")
    && (features.execution_context === undefined || typeof features.execution_context === "boolean")
    && ["native_policy_facts", "sanitized_receipt_facts", "workspace_documents"].every((key) => typeof sources[key] === "boolean")
    && text(sources.source_set_id, 128)
    && (storage.mode === "memory" || storage.mode === "sqlite")
    && Number.isSafeInteger(storage.retention_hours)
    && ["context_tokens", "reserve_tokens", "max_active_workspaces", "idle_shutdown_seconds"]
      .every((key) => Number.isSafeInteger(limits[key]));
}

function runtime(value: unknown): value is ContextRuntime {
  if (!record(value) || value.schema !== "guard-cigar-runtime-status.v1" || !record(value.interpreter)) return false;
  const facts = value.interpreter;
  return facts.schema === "guard-cigar-interpreter.v1" && version(facts.version)
    && ["implementation", "release_level", "abi", "platform"].every((key) => text(facts[key]))
    && typeof facts.free_threaded === "boolean" && typeof facts.debug_build === "boolean"
    && isCigarProducerVersion(value.package_version) && text(value.protocol)
    && (value.core_version === undefined || isCigarCoreLabel(value.core_version))
    && (value.release === undefined || (isCigarReleaseBinding(value.release)
      && value.package_version === value.release.identity.sdk_version && value.core_version === value.release.identity.core_version
      && value.adapter_id === value.release.adapter_id && value.adapter_revision === value.release.adapter_revision))
    && digest(value.package_fingerprint) && digest(value.worker_fingerprint)
    && Array.isArray(value.features) && value.features.length <= 64 && value.features.every((item) => text(item, 64))
    && typeof value.compile_verified === "boolean" && typeof value.active === "boolean"
    && (value.shared_compile_verified === undefined || typeof value.shared_compile_verified === "boolean")
    && (value.persistence_compile_verified === undefined || typeof value.persistence_compile_verified === "boolean")
    && (value.execution_handoff_verified === undefined || typeof value.execution_handoff_verified === "boolean");
}

function installation(value: unknown): value is ContextInstallation {
  if (!record(value) || !text(value.runtime_id, 128)
      || !["local_candidate", "guard_qualified"].includes(String(value.qualification))
      || !version(value.python_version) || !text(value.platform) || !digest(value.worker_fingerprint)) return false;
  const metadata = ["sdk_version", "core_version", "build_id", "adapter_id", "adapter_revision", "managed"];
  if (!metadata.some((key) => value[key] !== undefined)) return value.qualification === "local_candidate";
  if (!isCigarProducerVersion(value.sdk_version) || !isCigarCoreLabel(value.core_version)
      || !text(value.adapter_id, 128) || !Number.isSafeInteger(value.adapter_revision)
      || Number(value.adapter_revision) < 1 || Number(value.adapter_revision) > 65535
      || typeof value.managed !== "boolean") return false;
  return value.qualification === "guard_qualified"
    ? value.managed && typeof value.build_id === "string" && value.build_id === value.build_id.trim()
      && /^[a-z0-9_:-]{1,128}$/i.test(value.build_id)
    : !value.managed && value.build_id === null;
}

/** Validate the native projection; this never discovers or qualifies Python. */
export function parseContextAssistanceStatus(value: unknown): ContextAssistanceStatus {
  if (!record(value) || value.schema !== "guard-context-assistance-status.v2"
      || !["off", "unavailable", "checking", "ready"].includes(String(value.availability))
      || typeof value.requested_enabled !== "boolean" || typeof value.effective_enabled !== "boolean"
      || !config(value.preferences) || !config(value.effective_preferences) || !revision(value.generation)
      || !(value.restriction === null || text(value.restriction)) || typeof value.verification_permitted !== "boolean"
      || !(value.diagnostic === null || text(value.diagnostic))
      || !(value.runtime === null || runtime(value.runtime))
      || !(value.last_check === null || runtime(value.last_check))
      || !(value.qualification === null || ["local_candidate", "guard_qualified"].includes(String(value.qualification)))
      || !(value.capabilities === undefined || (record(value.capabilities)
        && typeof value.capabilities.shared_agents === "boolean" && typeof value.capabilities.private_persistence === "boolean"
        && (value.capabilities.execution_context === undefined || typeof value.capabilities.execution_context === "boolean")))
      || !(value.execution_ready === undefined || typeof value.execution_ready === "boolean")
      || !(value.execution_observations === undefined || value.execution_observations === null
        || (Array.isArray(value.execution_observations) && value.execution_observations.length <= 32
          && value.execution_observations.every(isContextExecutionObservation)))
      || !(value.installation_options === null || (Array.isArray(value.installation_options)
        && value.installation_options.length <= 8 && value.installation_options.every(installation)))
      || !(value.job === null || (record(value.job) && revision(value.job.id)
        && (value.job.operation === "activate" || value.job.operation === "recheck")
        && (value.job.phase === "verifying" || value.job.phase === "cancelling")))) {
    throw new Error("Context assistance returned an incompatible status. Update Guard and check again.");
  }
  if (value.qualification === "guard_qualified") {
    const checked = value.runtime ?? value.last_check;
    if (!record(checked) || !isCigarReleaseBinding(checked.release)) {
      throw new Error("Context assistance did not provide a qualified release identity. Check again.");
    }
  }
  if (value.requested_enabled !== value.preferences.enabled
      || (value.effective_enabled && (value.availability !== "ready" || !value.requested_enabled
        || !value.effective_preferences.enabled || !value.verification_permitted
        || !record(value.runtime) || value.runtime.active !== true || value.runtime.compile_verified !== true
        || (value.effective_preferences.features.shared_agents && value.runtime.shared_compile_verified !== true)
        || (value.effective_preferences.storage.mode === "sqlite" && (value.runtime.persistence_compile_verified !== true
          || !record(value.capabilities) || value.capabilities.private_persistence !== true))))
      || (value.availability === "ready" && !value.effective_enabled)
      || (value.execution_ready === true && (!value.effective_enabled
        || value.effective_preferences.features.execution_context !== true
        || !value.effective_preferences.sources.native_policy_facts
        || !record(value.capabilities) || value.capabilities.execution_context !== true
        || !record(value.runtime) || value.runtime.execution_handoff_verified !== true))) {
    throw new Error("Context assistance did not provide a current readiness proof. Check again.");
  }
  return value as ContextAssistanceStatus;
}

export function contextStatusCopy(status: ContextAssistanceStatus): { label: string; detail: string } {
  if (status.job) return status.job.phase === "cancelling"
    ? { label: "Stopping", detail: "Cancelling the pending runtime check." }
    : { label: "Checking runtime", detail: "Guard is verifying Python, CIGAR and its worker in the background." };
  if (status.effective_enabled) return {
    label: "Ready", detail: "The local CIGAR runtime is ready. Context uses only the sources and app access you authorize.",
  };
  if (!status.requested_enabled && !status.diagnostic) return {
    label: "Off", detail: "Optional context assistance is off. Guard continues protecting your commands.",
  };
  if (status.requested_enabled && status.verification_permitted && status.effective_preferences.enabled
      && (status.diagnostic === "runtime_not_verified" || status.diagnostic === null)) return {
    label: "Not started", detail: "Your preferences are saved. Click Start CIGAR to verify and run the selected runtime.",
  };
  if (status.diagnostic === "runtime_idle") return {
    label: "Paused", detail: "CIGAR stopped after being idle. Click Start CIGAR when you need context again.",
  };
  const code = status.diagnostic ?? "runtime_not_verified";
  const detail = code === "policy_restricted"
      ? "Your preference is saved. Organization or workspace policy currently prevents context assistance. You can still turn it off."
    : code.startsWith("python_")
      ? "Choose a verified final CPython 3.14 runtime. Other Python versions cannot run this feature."
      : code.includes("managed") || code.includes("configuration")
        ? "Local or managed settings currently restrict context assistance. Review this machine's settings."
        : code === "runtime_not_verified"
          ? "Your preference is saved. Review the selected runtime and any policy restrictions before starting CIGAR."
          : "Context assistance needs attention. Check the selected runtime; Guard protection remains available.";
  return { label: "Unavailable", detail };
}
