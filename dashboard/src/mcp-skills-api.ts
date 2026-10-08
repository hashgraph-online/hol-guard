import { fetchLocalCliApi } from "./guard-api";

export type McpSkillMetadata = {
  uri: string; name: string; description: string; dynamic: boolean;
  manifest_digest: string | null; resource_count: number | null;
};
const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const integer = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export async function fetchMcpSkillMetadata(options: {
  cliId: string; identityHash: string; offset: number; search: string; revision?: number; signal: AbortSignal;
}): Promise<{ entries: McpSkillMetadata[]; revision: number; nextOffset: number | null }> {
  const response = await fetchLocalCliApi("/v1/local-clis/mcp-skills", {
    method: "POST", signal: options.signal, headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cli_id: options.cliId, offset: options.offset, search: options.search,
      ...(options.revision === undefined ? {} : { revision: options.revision }) }),
  });
  const body: unknown = await response.json();
  if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Could not load remote workflow metadata.");
  if (!object(body) || body.cli_id !== options.cliId || body.activation_supported !== false
    || !Array.isArray(body.entries) || body.entries.length > 50 || !integer(body.revision) || body.revision < 1
    || (body.next_offset !== null && body.next_offset !== options.offset + 50)) throw new Error("Invalid remote workflow catalog");
  const entries = body.entries.map((entry): McpSkillMetadata => {
    if (!object(entry) || entry.origin !== "mcp-served-skill" || entry.connection_identity_hash !== options.identityHash
      || entry.activation_supported !== false || entry.permissions_granted !== false
      || typeof entry.uri !== "string" || entry.uri.length > 8192 || !entry.uri.endsWith("/SKILL.md")
      || typeof entry.name !== "string" || entry.name.length > 64 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.name)
      || typeof entry.description !== "string" || entry.description.length > 1024 || typeof entry.dynamic !== "boolean"
      || (entry.dynamic ? entry.manifest_digest !== null || entry.resource_count !== null
        : typeof entry.manifest_digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(entry.manifest_digest)
          || !integer(entry.resource_count) || entry.resource_count < 1 || entry.resource_count > 512)) {
      throw new Error("Invalid remote workflow provenance");
    }
    return { uri: entry.uri, name: entry.name, description: entry.description, dynamic: entry.dynamic,
      manifest_digest: entry.manifest_digest as string | null, resource_count: entry.resource_count as number | null };
  });
  return { entries, revision: body.revision, nextOffset: body.next_offset as number | null };
}
