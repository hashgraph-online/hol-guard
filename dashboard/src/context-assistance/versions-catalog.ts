import { ContextAssistanceApiError } from "./api";
import { isCigarBuildIdentity, type CigarBuildIdentity } from "./release-version";

export type CigarQualification = "local_candidate" | "upstream_only" | "guard_qualified";
export type CigarPlatformBuild = {
  platform: string; qualification: CigarQualification; features: string[];
  worker_sha256: string; package_tree_sha256: string | null;
  qualification_receipt_sha256: string | null; has_wheel: boolean; download_bytes: number;
  /** Native install also needs the package tree digest and the protobuf lock. */
  has_dependency_lock: boolean;
};
export type CigarCatalogBuild = {
  identity: CigarBuildIdentity; profile_id: string; channel: "stable" | "preview" | "local_candidate";
  withdrawn: boolean; platforms: CigarPlatformBuild[];
};
export type CigarInterpreterBuild = {
  build_id: string; python_version: [number, number, number]; platform: string;
  qualification: CigarQualification; withdrawn: boolean; archive_bytes: number;
};
export type CigarCatalogMetadata = {
  source: "bundled" | "cached"; fresh_for_preparation: boolean; diagnostic: string | null;
  trust_configured: boolean; trust_diagnostic: string | null;
  remote_feed_configured: boolean; feed_diagnostic: string | null;
};
export type CigarCatalog = {
  host_platform: string | null; builds: CigarCatalogBuild[];
  interpreter_builds: CigarInterpreterBuild[]; catalog: CigarCatalogMetadata;
};
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const id = (v: unknown): v is string => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const digest = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const platform = (v: unknown): v is string => typeof v === "string"
  && ["darwin-arm64", "darwin-x64", "linux-x64-gnu", "linux-arm64-gnu", "linux-x64-musl", "linux-arm64-musl", "win32-x64"].includes(v);
const qualification = (v: unknown): v is CigarQualification => typeof v === "string"
  && ["local_candidate", "upstream_only", "guard_qualified"].includes(v);
const diagnostic = (v: unknown): v is string | null => v === null || typeof v === "string" && /^[a-z0-9_]{1,160}$/.test(v);
function invalid(): never { throw new ContextAssistanceApiError("versions_catalog_invalid", "Guard returned incompatible CIGAR catalog data. Refresh the catalog."); }
function pythonVersion(v: unknown): v is [number, number, number] {
  return Array.isArray(v) && v.length === 3 && v.every((n) => count(n) && n <= 65535);
}
function wheelBytes(v: unknown): number {
  if (!object(v) || !count(v.bytes) || v.bytes === 0 || !digest(v.sha256)) invalid();
  return v.bytes;
}
function parsePlatform(v: unknown): CigarPlatformBuild {
  if (!object(v) || !platform(v.platform) || !qualification(v.qualification) || !digest(v.worker_sha256)
    || !(v.package_tree_sha256 === null || digest(v.package_tree_sha256))
    || !(v.qualification_receipt_sha256 === null || digest(v.qualification_receipt_sha256))
    || (v.qualification === "guard_qualified" && v.qualification_receipt_sha256 === null)
    || !Array.isArray(v.features) || v.features.length > 16
    || !v.features.every((f) => typeof f === "string" && /^[a-z0-9_]{1,128}$/.test(f))
    || new Set(v.features).size !== v.features.length || !Array.isArray(v.dependencies) || v.dependencies.length > 32) invalid();
  const hasWheel = v.wheel !== null;
  const locked = v.package_tree_sha256 !== null
    && v.dependencies.some((w) => object(w) && w.distribution === "protobuf");
  const bytes = (hasWheel ? wheelBytes(v.wheel) : 0) + v.dependencies.reduce((n, w) => n + wheelBytes(w), 0);
  if (!count(bytes)) invalid();
  return { platform: v.platform, qualification: v.qualification, features: v.features as string[],
    worker_sha256: v.worker_sha256, package_tree_sha256: v.package_tree_sha256,
    qualification_receipt_sha256: v.qualification_receipt_sha256, has_wheel: hasWheel, download_bytes: bytes,
    has_dependency_lock: locked };
}
function parseBuild(v: unknown): CigarCatalogBuild {
  if (!object(v) || !isCigarBuildIdentity(v.identity) || !id(v.profile_id)
    || !["stable", "preview", "local_candidate"].includes(String(v.channel)) || typeof v.withdrawn !== "boolean"
    || !Array.isArray(v.platforms) || v.platforms.length === 0 || v.platforms.length > 7) invalid();
  const platforms = v.platforms.map(parsePlatform);
  if (new Set(platforms.map((p) => p.platform)).size !== platforms.length) invalid();
  return { identity: { build_id: v.identity.build_id, sdk_version: v.identity.sdk_version, core_version: v.identity.core_version,
    source_revision: v.identity.source_revision, manifest_sha256: v.identity.manifest_sha256 }, profile_id: v.profile_id, channel: v.channel as CigarCatalogBuild["channel"], withdrawn: v.withdrawn, platforms };
}
function parseInterpreter(v: unknown): CigarInterpreterBuild {
  if (!object(v) || !id(v.build_id) || !pythonVersion(v.python_version) || !platform(v.platform)
    || !qualification(v.qualification) || typeof v.withdrawn !== "boolean" || !count(v.archive_bytes) || v.archive_bytes === 0) invalid();
  return { build_id: v.build_id, python_version: [...v.python_version], platform: v.platform,
    qualification: v.qualification, withdrawn: v.withdrawn, archive_bytes: v.archive_bytes };
}
export function parseCigarCatalogMetadata(v: unknown): CigarCatalogMetadata {
  if (!object(v) || !["bundled", "cached"].includes(String(v.source)) || typeof v.fresh_for_preparation !== "boolean"
    || !diagnostic(v.diagnostic) || !diagnostic(v.trust_diagnostic) || !diagnostic(v.feed_diagnostic)
    || typeof v.trust_configured !== "boolean" || typeof v.remote_feed_configured !== "boolean"
    || v.activation_granted !== false || (v.fresh_for_preparation && v.diagnostic !== null)) invalid();
  return { source: v.source as CigarCatalogMetadata["source"], fresh_for_preparation: v.fresh_for_preparation,
    diagnostic: v.diagnostic, trust_configured: v.trust_configured, trust_diagnostic: v.trust_diagnostic,
    remote_feed_configured: v.remote_feed_configured, feed_diagnostic: v.feed_diagnostic };
}
/** Projection only; native qualification and operation admission remain authoritative. */
export function parseCigarCatalog(v: unknown): CigarCatalog {
  if (!object(v) || v.schema !== "guard-cigar-releases.v1"
    || !(v.host_platform === undefined || v.host_platform === null || platform(v.host_platform))
    || !Array.isArray(v.builds) || v.builds.length > 128
    || !Array.isArray(v.interpreter_builds) || v.interpreter_builds.length > 128) invalid();
  const builds = v.builds.map(parseBuild), interpreters = v.interpreter_builds.map(parseInterpreter);
  if (new Set(builds.map((b) => b.identity.build_id)).size !== builds.length
    || new Set(interpreters.map((b) => b.build_id)).size !== interpreters.length) invalid();
  return { host_platform: v.host_platform ?? null, builds, interpreter_builds: interpreters, catalog: parseCigarCatalogMetadata(v.catalog) };
}
