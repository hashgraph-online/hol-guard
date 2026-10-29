/** Producer labels describe history; native release qualification owns execution. */
export const isCigarProducerVersion = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= 128 && value === value.trim()
  && /^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$/i.test(value);

export const isCigarCoreLabel = (value: unknown): value is string =>
  typeof value === "string" && value === value.trim() && value.length <= 128
  && /^[a-z0-9][a-z0-9._+!-]{0,127}$/i.test(value) && !value.includes("..");

export type CigarBuildIdentity = { build_id: string; sdk_version: string; core_version: string; source_revision: string; manifest_sha256: string };
export type CigarReleaseBinding = {
  identity: CigarBuildIdentity;
  profile_id: string; adapter_id: string; adapter_revision: number; profile_sha256: string; platform: string;
};
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const identifier = (value: unknown): value is string => typeof value === "string" && value === value.trim() && /^[a-z0-9_:-]{1,128}$/i.test(value);
const digest = (value: unknown): value is string => typeof value === "string" && value.length === 64 && /^[a-f0-9]{64}$/.test(value);
export function isCigarBuildIdentity(value: unknown): value is CigarBuildIdentity {
  return object(value) && identifier(value.build_id) && isCigarProducerVersion(value.sdk_version) && isCigarCoreLabel(value.core_version)
    && typeof value.source_revision === "string" && value.source_revision.length === 40 && /^[a-f0-9]{40}$/.test(value.source_revision) && digest(value.manifest_sha256);
}
export function isCigarReleaseBinding(value: unknown): value is CigarReleaseBinding {
  if (!object(value) || !isCigarBuildIdentity(value.identity)) return false;
  return identifier(value.profile_id) && identifier(value.adapter_id) && Number.isSafeInteger(value.adapter_revision)
    && Number(value.adapter_revision) >= 1 && Number(value.adapter_revision) <= 65535
    && digest(value.profile_sha256) && typeof value.platform === "string"
    && ["darwin-arm64", "darwin-x64", "linux-x64-gnu", "linux-arm64-gnu", "linux-x64-musl", "linux-arm64-musl", "win32-x64"].includes(value.platform);
}
