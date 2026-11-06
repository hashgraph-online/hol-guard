/** Display-only host summaries never enter the extension permission model. */
export type CodexHostToolSummary = {
  name: string;
  title: string | null;
  description: string | null;
};

export type CodexHostAppSummary = {
  app_id: string;
  name: string;
  enabled: boolean;
  callable: boolean;
  metadata_available: boolean;
  tools: CodexHostToolSummary[];
};

export type CodexHostInventory = {
  host: "Codex";
  connection_id: string;
  catalog_coverage: "host-summary";
  account_verified: false;
  schemas_available: false;
  permissions_granted: false;
  snapshot_age: "unknown";
  metadata_complete: boolean;
  expires_at_ms: number;
  apps: CodexHostAppSummary[];
};

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hostMetadataText(value: unknown, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || [...value].length > maximum || value.includes("\0")) {
    throw new Error("Invalid host metadata");
  }
  return value;
}

function optionalText(value: unknown, maximum: number): string | null {
  return value === null || value === undefined ? null : hostMetadataText(value, maximum);
}

export function normalizeCodexHostInventory(value: unknown): CodexHostInventory | undefined {
  if (!record(value) || value.host !== "Codex" || value.catalog_coverage !== "host-summary"
    || value.account_verified !== false || value.schemas_available !== false || value.permissions_granted !== false
    || value.snapshot_age !== "unknown" || typeof value.metadata_complete !== "boolean"
    || typeof value.expires_at_ms !== "number" || !Number.isSafeInteger(value.expires_at_ms) || value.expires_at_ms <= 0
    || typeof value.connection_id !== "string" || !/^[a-f0-9]{64}$/.test(value.connection_id)
    || !Array.isArray(value.apps) || value.apps.length > 1000) return undefined;
  try {
    const appIds = new Set<string>();
    let totalTools = 0;
    const apps = value.apps.map((entry): CodexHostAppSummary => {
      if (!record(entry) || typeof entry.enabled !== "boolean" || typeof entry.callable !== "boolean"
        || typeof entry.metadata_available !== "boolean" || !Array.isArray(entry.tools)) {
        throw new Error("Invalid host app");
      }
      const appId = hostMetadataText(entry.app_id, 256);
      if (appIds.has(appId)) throw new Error("Duplicate host app");
      appIds.add(appId);
      totalTools += entry.tools.length;
      if (totalTools > 10_000) throw new Error("Host summary limit");
      const names = new Set<string>();
      const tools = entry.tools.map((tool): CodexHostToolSummary => {
        if (!record(tool)) throw new Error("Invalid host tool");
        const name = hostMetadataText(tool.name, 256);
        if (names.has(name)) throw new Error("Duplicate host tool");
        names.add(name);
        return { name, title: optionalText(tool.title, 512), description: optionalText(tool.description, 4000) };
      });
      return { app_id: appId, name: hostMetadataText(entry.name, 256), enabled: entry.enabled,
        callable: entry.callable, metadata_available: entry.metadata_available, tools };
    });
    return { host: "Codex", connection_id: value.connection_id, catalog_coverage: "host-summary",
      account_verified: false, schemas_available: false, permissions_granted: false,
      snapshot_age: "unknown", metadata_complete: value.metadata_complete, expires_at_ms: value.expires_at_ms, apps };
  } catch {
    return undefined;
  }
}

export function filterCodexHostApps(apps: CodexHostAppSummary[], query: string): CodexHostAppSummary[] {
  const search = query.trim().toLocaleLowerCase();
  if (!search) return apps;
  return apps.flatMap((app) => {
    if (`${app.name} ${app.app_id}`.toLocaleLowerCase().includes(search)) return [app];
    const tools = app.tools.filter((tool) => `${tool.name} ${tool.title ?? ""} ${tool.description ?? ""}`
      .toLocaleLowerCase().includes(search));
    return tools.length ? [{ ...app, tools }] : [];
  });
}
