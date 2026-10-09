import type { LocalCliContinuity } from "./custom-extension-continuity-api";
import { normalizeCodexHostInventory } from "./codex-host-inventory";
import type { LocalCliCommand, LocalCliItem, LocalCliListResponse, LocalCliSurface, LocalMcpCatalog, McpClassification } from "./local-cli-api";
import { normalizeProfileFields, normalizeSuggestedState } from "./local-cli-profile-fields";
import { SHA256_PATTERN, isLocalCliId, isRecord, optionalString, requiredInt, requiredString } from "./local-cli-fields";

export function normalizeMcpClassification(value: unknown): McpClassification | undefined {
  if (!isRecord(value) || value.schema_version !== "guard.mcp-classification.v1" || value.advisory_only !== true
    || !["reviewed-mapping", "limited"].includes(String(value.confidence))) return undefined;
  const labels = [value.effect, value.data, value.destination, value.reversibility];
  if (!labels.every((label) => typeof label === "string" && /^[a-z-]{1,40}$/.test(label))) return undefined;
  const codes = (list: unknown): list is string[] => Array.isArray(list) && list.length <= 16
    && list.every((code) => typeof code === "string" && /^[a-z0-9:-]{1,80}$/.test(code));
  if (!codes(value.evidence) || !codes(value.warnings)) return undefined;
  return { effect: value.effect as string, data: value.data as string, destination: value.destination as string,
    reversibility: value.reversibility as string, confidence: value.confidence as McpClassification["confidence"],
    evidence: value.evidence, warnings: value.warnings };
}
export function normalizeLocalCliItem(value: unknown): LocalCliItem {
  if (!isRecord(value)) throw new Error("Invalid local CLI item");
  const cliId = requiredString(value.cli_id, "id");
  if (!isLocalCliId(cliId)) throw new Error("Invalid local CLI id");
  const identityHash = requiredString(value.identity_hash, "identity");
  if (!SHA256_PATTERN.test(identityHash)) throw new Error("Invalid local CLI identity");
  const kind = value.kind;
  if (kind !== "executable" && kind !== "script") throw new Error("Invalid local CLI kind");
  const state = value.state;
  if (state !== "unset" && state !== "allowed" && state !== "blocked") throw new Error("Invalid local CLI state");
  const catalog = normalizeMcpCatalog(value.mcp_catalog);
  const providerCatalog = normalizeProviderCatalog(value.provider_catalog);
  return {
    cli_id: cliId,
    name: requiredString(value.name, "name").slice(0, 120),
    kind,
    identity_hash: identityHash,
    example_label: requiredString(value.example_label, "example").slice(0, 160),
    interpreter_name: optionalString(value.interpreter_name),
    observed_count: requiredInt(value.observed_count, "count"),
    last_seen_at: optionalString(value.last_seen_at),
    source_path: optionalString(value.source_path),
    help_status: normalizeHelpStatus(value.help_status),
    surface: normalizeSurface(value.surface),
    server_identity_hash: normalizeIdentityHash(value.server_identity_hash),
    source_label: optionalSourceLabel(value.source_label),
    state,
    stale: value.stale === true,
    grant_revision: value.grant_revision === null || value.grant_revision === undefined
      ? null
      : requiredInt(value.grant_revision, "grant revision"),
    authority_revision: requiredInt(value.authority_revision, "revision"),
    suggestable: value.suggestable === true,
    suggestion_score: optionalScore(value.suggestion_score),
    commands: Array.isArray(value.commands) ? value.commands.map(normalizeLocalCliCommand) : [],
    continuity: normalizeContinuity(value.continuity),
    ...(catalog ? { mcp_catalog: catalog } : {}),
    ...(providerCatalog ? { provider_catalog: providerCatalog } : {}),
    ...(["configured-connection", "host-namespace", "legacy-device"].includes(String(value.permission_scope))
      ? { permission_scope: value.permission_scope as LocalCliItem["permission_scope"] } : {}),
    ...normalizeProfileFields(value),
  };
}

function normalizeMcpCatalog(value: unknown): LocalMcpCatalog | null {
  if (!isRecord(value) || typeof value.complete !== "boolean" || typeof value.stale !== "boolean") return null;
  const count = (candidate: unknown): candidate is number =>
    typeof candidate === "number" && Number.isSafeInteger(candidate) && candidate >= 0 && candidate <= 10_000;
  if (!count(value.pages) || !count(value.listed_count) || !count(value.known_count)) return null;
  if (value.listed_count > value.known_count) return null;
  if (typeof value.revision !== "number" || !Number.isSafeInteger(value.revision) || value.revision < 1) return null;
  if (typeof value.updated_at !== "string" || !Number.isFinite(Date.parse(value.updated_at))) return null;
  const reason = typeof value.reason === "string" ? value.reason.slice(0, 80) : null;
  if (value.complete && reason !== null) return null;
  const changes = normalizeMcpCatalogChanges(value.changes);
  const skills = value.skills_catalog;
  const skillsCatalog = isRecord(skills) && typeof skills.declared === "boolean" && typeof skills.complete === "boolean"
    && typeof skills.stale === "boolean" && count(skills.known_count) && skills.known_count <= 1000
    && skills.activation_supported === false
    ? { declared: skills.declared, complete: skills.complete, stale: skills.stale, known_count: skills.known_count,
      reason: typeof skills.reason === "string" ? skills.reason.slice(0, 80) : null } : undefined;
  return {
    complete: value.complete,
    stale: value.stale,
    reason,
    pages: value.pages,
    listed_count: value.listed_count,
    known_count: value.known_count,
    protocol_version: typeof value.protocol_version === "string" ? value.protocol_version.slice(0, 40) : null,
    revision: value.revision,
    updated_at: value.updated_at.slice(0, 64),
    last_complete_at: typeof value.last_complete_at === "string" && Number.isFinite(Date.parse(value.last_complete_at))
      ? value.last_complete_at.slice(0, 64)
      : null,
    ...(changes ? { changes } : {}),
    ...(skillsCatalog ? { skills_catalog: skillsCatalog } : {}),
    ...(typeof value.fresh_until === "string" && Number.isFinite(Date.parse(value.fresh_until))
      ? { fresh_until: value.fresh_until } : {}),
    ...(value.cache_scope === "private" || value.cache_scope === "public" ? { cache_scope: value.cache_scope } : {}),
  };
}

function normalizeProviderCatalog(value: unknown): LocalCliItem["provider_catalog"] {
  if (!isRecord(value) || value.provider !== "composio" || value.coverage !== "discovery-subset"
    || value.account_binding !== "unverified"
    || typeof value.known_count !== "number" || !Number.isSafeInteger(value.known_count)
    || value.known_count < 1 || value.known_count > 10_000
    || typeof value.full_schema_count !== "number" || !Number.isSafeInteger(value.full_schema_count)
    || value.full_schema_count < 0 || value.full_schema_count > value.known_count
    || typeof value.updated_at !== "string" || !Number.isFinite(Date.parse(value.updated_at))) return undefined;
  return {
    provider: "composio", known_count: value.known_count, full_schema_count: value.full_schema_count,
    updated_at: value.updated_at.slice(0, 64), coverage: "discovery-subset", account_binding: "unverified",
  };
}

function normalizeMcpCatalogChanges(value: unknown): LocalMcpCatalog["changes"] {
  if (!isRecord(value)) return undefined;
  const result: NonNullable<LocalMcpCatalog["changes"]> = { added: [], changed: [], removed: [], stale: [] };
  for (const key of ["added", "changed", "removed", "stale"] as const) {
    const names = value[key];
    if (!Array.isArray(names) || names.length > 10_000 || !names.every(
      (name) => typeof name === "string" && name.length > 0 && name.length <= 256 && name.trim() === name,
    )) return undefined;
    result[key] = [...new Set(names as string[])];
  }
  return result;
}

function normalizeContinuity(value: unknown): LocalCliContinuity | null {
  if (!isRecord(value)) return null;
  const status = value.status;
  if (
    status !== "applied" &&
    status !== "pending_observation" &&
    status !== "changed_identity" &&
    status !== "locally_overridden" &&
    status !== "removed" &&
    status !== "stale"
  ) return null;
  return {
    status,
    reason: typeof value.reason === "string" ? value.reason : "",
    cloud_revision: typeof value.cloud_revision === "number" && Number.isInteger(value.cloud_revision)
      ? value.cloud_revision
      : null,
    surface: value.surface === "cli" || value.surface === "mcp" || value.surface === "package-scripts"
      ? value.surface
      : null,
  };
}

function normalizeSurface(value: unknown): LocalCliSurface {
  if (value === "mcp") return "mcp";
  if (value === "package-scripts") return "package-scripts";
  return "cli";
}

export function normalizeHelpStatus(value: unknown): LocalCliItem["help_status"] {
  if (value === "ok" || value === "empty" || value === "failed") return value;
  return null;
}

function normalizeIdentityHash(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) return null;
  return value;
}

function optionalScore(value: unknown): number {
  if (value === null || value === undefined) return 0;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error("Invalid local CLI suggestion score");
  }
  return value;
}

function optionalSourceLabel(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string") return null;
  return value.trim().slice(0, 120) || null;
}

export function normalizeLocalCliCommand(value: unknown): LocalCliCommand {
  if (!isRecord(value)) throw new Error("Invalid local CLI command");
  const state = value.state;
  if (state !== "inherit" && state !== "allow" && state !== "review" && state !== "block") {
    throw new Error("Invalid local CLI command state");
  }
  const parent = value.parent_id;
  if (parent !== null && parent !== undefined && typeof parent !== "string") {
    throw new Error("Invalid local CLI command parent");
  }
  return {
    command_id: requiredString(value.command_id, "command").slice(0, 80),
    name: requiredString(value.name, "command name").slice(0, 120),
    usage: requiredString(value.usage, "command usage").slice(0, 160),
    description: typeof value.description === "string" ? value.description.slice(0, 240) : "",
    parent_id: typeof parent === "string" && parent.trim() ? parent : null,
    state,
    classification: normalizeMcpClassification(value.classification),
    ...normalizeSuggestedState(value.suggested_state),
  };
}

export function normalizeLocalCliList(value: unknown): LocalCliListResponse {
  if (!isRecord(value)) throw new Error("Invalid local CLI list");
  const cloud = isRecord(value.cloud) ? value.cloud : {};
  const items = Array.isArray(value.items)
    ? value.items.flatMap((entry) => { try { return [normalizeLocalCliItem(entry)]; } catch { return []; } })
    : [];
  const seededItems = Array.isArray(value.seeded_items)
    ? value.seeded_items.flatMap((entry) => { try { return [normalizeLocalCliItem(entry)]; } catch { return []; } })
      .filter((item) => item.seeded === true)
    : [];
  const revision = requiredInt(value.revision, "revision");
  const publication = value.native_publication;
  const discoveryIssue = value.discovery_issue;
  const hostInventory = normalizeCodexHostInventory(value.host_inventory);
  let nativePublication: LocalCliListResponse["native_publication"];
  if (isRecord(publication) && publication.revision === revision && (
    publication.state === "pending" || publication.state === "failed" || publication.state === "unavailable"
  )) {
    nativePublication = { state: publication.state, revision };
  } else if (isRecord(publication) && publication.state === "acknowledged" && publication.revision === revision
    && typeof publication.generation === "number" && Number.isSafeInteger(publication.generation) && publication.generation > 0
    && typeof publication.policy_digest === "string" && /^[a-f0-9]{64}$/.test(publication.policy_digest)) {
    nativePublication = { state: "acknowledged", revision, generation: publication.generation };
  }
  return {
    schema_version: requiredString(value.schema_version, "schema"),
    revision,
    ...((discoveryIssue === "catalog_limit_reached" || discoveryIssue === "observed_provider_scan_failed"
      || discoveryIssue === "configured_host_scan_failed" || discoveryIssue === "package_catalog_refresh_failed")
      ? { discovery_issue: discoveryIssue } : {}),
    ...(nativePublication ? { native_publication: nativePublication } : {}),
    ...(hostInventory ? { host_inventory: hostInventory } : {}),
    items,
    seeded_items: seededItems,
    cloud: {
      sync_local_only: cloud.sync_local_only !== false,
      continuity_enabled: cloud.continuity_enabled === true,
      summary: typeof cloud.summary === "string"
        ? cloud.summary
        : "Custom Extensions remain local to this device until portable continuity is enabled.",
    },
  };
}
