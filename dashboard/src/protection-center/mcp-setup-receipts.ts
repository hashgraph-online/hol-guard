export type RecentMcpSetup = {
  rollback_handle: string; setup_name: string; kind: "remote" | "package";
  registry_name: string; version: string; selection_digest: string;
  rollback_available?: boolean;
};

export const isSetupDigest = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

export function parseRecentMcpSetups(value: unknown): RecentMcpSetup[] {
  if (!Array.isArray(value) || value.length > 32) throw new Error("Could not verify recent setup history. Retry history.");
  const handles = new Set<string>();
  return value.map((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)
      || !isSetupDigest(entry.rollback_handle) || !isSetupDigest(entry.selection_digest)
      || handles.has(entry.rollback_handle)
      || typeof entry.setup_name !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(entry.setup_name)
      || !["remote", "package"].includes(entry.kind)
      || typeof entry.registry_name !== "string" || entry.registry_name.length > 256
      || typeof entry.version !== "string" || entry.version.length > 80) {
      throw new Error("Could not verify recent setup history. Retry history.");
    }
    handles.add(entry.rollback_handle);
    if (entry.rollback_available !== undefined && typeof entry.rollback_available !== "boolean") {
      throw new Error("Could not verify recent setup history. Retry history.");
    }
    return { rollback_handle: entry.rollback_handle, setup_name: entry.setup_name, kind: entry.kind,
      registry_name: entry.registry_name, version: entry.version, selection_digest: entry.selection_digest,
      ...(entry.rollback_available === undefined ? {} : { rollback_available: entry.rollback_available }) };
  });
}
