/**
 * Bounded catalog reads for the dashboard (ADR 0014).
 *
 * The daemon's native read model owns filtering, paging, cursors and ETags.
 * This module issues requests, revalidates cached pages, verifies that every
 * multi-page traversal is complete and consistent, and falls back to the v1
 * catalog only when the daemon reports that v2 is absent. Catalog metadata is
 * never protection authority: effective state always comes from
 * /v1/extension-controls/effective.
 */
import { fetchExtensionCatalogV2Api, guardApiCacheScope } from "./guard-api";
import {
  ExtensionControlApiError,
  fetchExtensionCatalog,
  type ExtensionCatalogItem,
  type ExtensionCatalogResponse,
  type ExtensionCatalogSummary,
  type ExtensionPermission,
} from "./extension-controls-api";
import {
  ExtensionControlProtocolError,
  normalizeExtensionCatalogItem,
  normalizeExtensionCatalogSummary,
  normalizeExtensionPermission,
} from "./extension-controls-normalize";

const CATALOG_V2_PATH = "/v2/extension-controls/catalog/";
const PAGE_LIMIT = 100;
export const MAX_CATALOG_V2_PAGE_BYTES = 262_144;
// The largest admitted collection (4,096 rules) needs at most 4,096 pages;
// anything beyond these bounds is a daemon fault.
const MAX_TRAVERSAL_PAGES = 4_096;
const MAX_TRAVERSAL_BYTES = 64 * 1024 * 1024;
const MAX_CACHE_ENTRIES = 256;
// Only these answers mean "this daemon has no v2 read model": an older daemon
// answers 404, a newer one without native support answers 501.
const UNSUPPORTED = new Set(["404:", "404:not_found", "501:catalog_read_model_unavailable"]);
export const CATALOG_SNAPSHOT_EXPIRED = "catalog_snapshot_expired";

export class CatalogV2UnsupportedError extends ExtensionControlApiError {}

export type CatalogPermissionHit = { extension: ExtensionCatalogSummary; permission: ExtensionPermission };

export type CatalogReadModel = {
  readonly protocol: "v2" | "v1";
  readonly catalog_digest: string;
  /** Index rows sorted by display name. */
  readonly extensions: readonly ExtensionCatalogSummary[];
  /** Full extension (permissions, rules, MCP tools), read only when needed. */
  detail(extensionId: string): Promise<ExtensionCatalogItem>;
  /** Permissions whose search text contains every whitespace-separated term. */
  searchPermissions(query: string, signal?: AbortSignal): Promise<CatalogPermissionHit[]>;
  /** Present when every permission is already in memory (legacy catalog). */
  localSearch?(query: string): CatalogPermissionHit[];
};

type Page = { snapshot_id: string; digest: string; total: number; items: Record<string, unknown>[]; next: string | null };
type CachedRead = { etag: string; payload: Record<string, unknown>; size: number };
type Read = { status: 200; etag: string | null; payload: Record<string, unknown>; size: number } | { status: 304; etag: string | null };

// Validator cache for v2 representations. Keys bind the daemon origin and
// session, so a different instance or login never reuses another's pages.
const readCache = new Map<string, CachedRead>();

export function clearCatalogReadCache(): void {
  readCache.clear();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function protocolError(message: string, code?: string): ExtensionControlApiError {
  return new ExtensionControlApiError(message, code === CATALOG_SNAPSHOT_EXPIRED ? 409 : 502, code);
}

async function readOnce(path: string, ifNoneMatch: string | null, signal?: AbortSignal): Promise<Read> {
  const headers: Record<string, string> = ifNoneMatch ? { "If-None-Match": ifNoneMatch } : {};
  // The module keeps its own validators, so bypass the HTTP cache and see 304s.
  const response = await fetchExtensionCatalogV2Api(path, { headers, cache: "no-store", signal });
  const etag = response.headers.get("ETag");
  if (response.status === 304) return { status: 304, etag };
  const declared = Number(response.headers.get("Content-Length") ?? "0");
  if (declared > MAX_CATALOG_V2_PAGE_BYTES) throw protocolError("Guard returned an oversized catalog page");
  const text = await response.text();
  const size = new TextEncoder().encode(text).byteLength;
  if (size > MAX_CATALOG_V2_PAGE_BYTES) throw protocolError("Guard returned an oversized catalog page");
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = undefined;
  }
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : undefined;
    if (UNSUPPORTED.has(`${response.status}:${code ?? ""}`)) {
      throw new CatalogV2UnsupportedError("Guard does not serve the v2 catalog", response.status, code);
    }
    throw new ExtensionControlApiError(code ?? `Request failed (${response.status})`, response.status, code);
  }
  if (!isRecord(payload)) throw protocolError(`Guard returned invalid JSON (${response.status})`);
  return { status: 200, etag, payload, size };
}

async function readSized(route: string, query: string, signal?: AbortSignal): Promise<CachedRead> {
  const path = `${CATALOG_V2_PATH}${route}${query ? `?${query}` : ""}`;
  const key = `${guardApiCacheScope()}|${path}`;
  const cached = readCache.get(key);
  let response = await readOnce(path, cached?.etag ?? null, signal);
  if (response.status === 304) {
    if (cached && response.etag === cached.etag) {
      readCache.delete(key);
      readCache.set(key, cached);
      return cached;
    }
    // A 304 that cannot be satisfied locally gets exactly one unconditional retry.
    response = await readOnce(path, null, signal);
    if (response.status !== 200) throw protocolError("Guard answered 304 to an unconditional catalog request");
  }
  if (!response.etag) throw protocolError("Guard catalog response is missing its validator");
  const entry = { etag: response.etag, payload: response.payload, size: response.size };
  readCache.delete(key);
  readCache.set(key, entry);
  while (readCache.size > MAX_CACHE_ENTRIES) {
    const oldest = readCache.keys().next().value;
    if (oldest === undefined) break;
    readCache.delete(oldest);
  }
  return entry;
}

function pageFields(page: Record<string, unknown>): Page {
  const { snapshot_id, native_catalog_digest, total_count, items, next_cursor } = page;
  if (
    typeof snapshot_id !== "string"
    || typeof native_catalog_digest !== "string"
    || !Number.isSafeInteger(total_count)
    || !Array.isArray(items)
    || !items.every(isRecord)
    || !(next_cursor === null || next_cursor === undefined || typeof next_cursor === "string")
  ) {
    throw protocolError("Guard returned an invalid catalog page");
  }
  return { snapshot_id, digest: native_catalog_digest, total: total_count as number, items, next: next_cursor ?? null };
}

type Traversal = { snapshot_id: string; digest: string; items: Record<string, unknown>[] };

async function traverseOnce(
  route: string,
  itemKey: string,
  params: Record<string, string>,
  signal?: AbortSignal,
): Promise<Traversal> {
  const items: Record<string, unknown>[] = [];
  const seenItems = new Set<string>();
  const seenCursors = new Set<string>();
  let first: Page | null = null;
  let cursor: string | null = null;
  let consumed = 0;
  for (let index = 0; index < MAX_TRAVERSAL_PAGES; index += 1) {
    // A superseded read stops between pages instead of walking to the end.
    signal?.throwIfAborted();
    const query: Record<string, string> = { limit: String(PAGE_LIMIT), ...params, ...(cursor ? { cursor } : {}) };
    const encoded = new URLSearchParams(Object.entries(query).sort(([left], [right]) => left.localeCompare(right))).toString();
    const read = await readSized(route, encoded, signal);
    consumed += read.size;
    if (consumed > MAX_TRAVERSAL_BYTES) throw protocolError("Guard catalog traversal exceeded its byte budget");
    const page = pageFields(read.payload);
    if (first === null) {
      first = page;
    } else if (page.snapshot_id !== first.snapshot_id || page.digest !== first.digest || page.total !== first.total) {
      throw protocolError("Guard catalog changed during the read", CATALOG_SNAPSHOT_EXPIRED);
    }
    for (const item of page.items) {
      const identity = item[itemKey];
      if (typeof identity !== "string" || seenItems.has(identity)) throw protocolError("Guard catalog traversal returned a duplicate item");
      seenItems.add(identity);
      items.push(item);
    }
    if (page.next === null) {
      if (items.length !== first.total) throw protocolError("Guard catalog traversal was incomplete");
      return { snapshot_id: first.snapshot_id, digest: first.digest, items };
    }
    if (seenCursors.has(page.next) || page.items.length === 0) throw protocolError("Guard catalog traversal did not advance");
    seenCursors.add(page.next);
    cursor = page.next;
  }
  throw protocolError("Guard catalog traversal exceeded its page budget");
}

async function traverse(
  route: string,
  itemKey: string,
  params: Record<string, string> = {},
  signal?: AbortSignal,
): Promise<Traversal> {
  try {
    return await traverseOnce(route, itemKey, params, signal);
  } catch (error) {
    // A stale cursor means the snapshot was replaced; restart exactly once.
    if (!(error instanceof ExtensionControlApiError) || error.code !== CATALOG_SNAPSHOT_EXPIRED) throw error;
  }
  return traverseOnce(route, itemKey, params, signal);
}

function extensionRoute(extensionId: string, collection?: string): string {
  const route = `extensions/${encodeURIComponent(extensionId)}`;
  return collection ? `${route}/${collection}` : route;
}

function sortedByName<T extends { name: string }>(items: readonly T[]): T[] {
  return [...items].sort((left, right) => left.name.localeCompare(right.name));
}

function requireSnapshot(observed: string, expected: string): void {
  if (observed !== expected) throw protocolError("Guard catalog changed. Reload to continue.", CATALOG_SNAPSHOT_EXPIRED);
}

async function v2Detail(extensionId: string, snapshotId: string): Promise<ExtensionCatalogItem> {
  const detail = (await readSized(extensionRoute(extensionId), "")).payload;
  const { extension, collections } = detail;
  if (typeof detail.snapshot_id !== "string" || !isRecord(extension) || !isRecord(collections) || !isRecord(extension.catalog_defaults)) {
    throw protocolError("Guard returned an invalid catalog detail");
  }
  requireSnapshot(detail.snapshot_id, snapshotId);
  const { catalog_defaults: defaults, content_revision: _revision, ...fields } = extension;
  const reads = await Promise.all([
    traverse(extensionRoute(extensionId, "permissions"), "permission_id"),
    traverse(extensionRoute(extensionId, "rules"), "rule_id"),
    "mcp_tools" in collections ? traverse(extensionRoute(extensionId, "mcp-tools"), "name") : null,
  ]);
  for (const read of reads) if (read) requireSnapshot(read.snapshot_id, snapshotId);
  const [permissions, rules, tools] = reads;
  return normalizeExtensionCatalogItem({
    ...fields,
    enabled: (defaults as Record<string, unknown>).enabled,
    activation: (defaults as Record<string, unknown>).activation,
    permissions: permissions?.items,
    rules: rules?.items,
    ...(tools ? { mcp_tools: tools.items } : {}),
  }, `catalog.extensions.${extensionId}`);
}

function searchTerms(query: string): string[] {
  return query.toLowerCase().split(/\s+/).filter(Boolean);
}

async function loadV2(): Promise<CatalogReadModel> {
  const index = await traverse("index", "extension_id");
  const summaries = index.items.map((item, position) => normalizeExtensionCatalogSummary(item, `catalog.index[${position}]`));
  const byId = new Map(summaries.map((summary) => [summary.extension_id, summary]));
  const details = new Map<string, Promise<ExtensionCatalogItem>>();
  return {
    protocol: "v2",
    catalog_digest: index.digest,
    extensions: sortedByName(summaries),
    detail(extensionId) {
      const summary = byId.get(extensionId);
      if (!summary) return Promise.reject(new ExtensionControlProtocolError(`Unknown extension ${extensionId}`));
      const key = `${extensionId}|${summary.content_revision ?? ""}`;
      let pending = details.get(key);
      if (!pending) {
        pending = v2Detail(extensionId, index.snapshot_id);
        details.set(key, pending);
        // A failed read must not stay cached; the next open retries it.
        pending.catch(() => details.delete(key));
      }
      return pending;
    },
    async searchPermissions(query, signal) {
      const terms = searchTerms(query);
      if (!terms.length) return [];
      const result = await traverse("permissions", "permission_id", { q: terms.join(" ") }, signal);
      requireSnapshot(result.snapshot_id, index.snapshot_id);
      return result.items.map((item, position) => {
        const permission = normalizeExtensionPermission(item, `catalog.permissions[${position}]`);
        const extension = byId.get(permission.extension_id);
        if (!extension) throw protocolError("Guard returned a permission for an unknown extension");
        return { extension, permission };
      });
    },
  };
}

/** A read model over a complete legacy catalog (v1 fallback). */
export function catalogReadModelFromCatalog(catalog: ExtensionCatalogResponse): CatalogReadModel {
  const byId = new Map(catalog.extensions.map((item) => [item.extension_id, item]));
  const localSearch = (query: string): CatalogPermissionHit[] => {
    // Same fields and term rule as the daemon's permissions?q= route.
    const terms = searchTerms(query);
    if (!terms.length) return [];
    return catalog.extensions.flatMap((extension) => extension.permissions
      .filter((permission) => {
        const text = [
          permission.label, permission.example_command ?? "", permission.permission_id, permission.description,
          permission.family ?? "", extension.name, extension.extension_id, ...extension.executables,
        ].join(" ").toLowerCase();
        return terms.every((term) => text.includes(term));
      })
      .map((permission) => ({ extension, permission })));
  };
  return {
    protocol: "v1",
    catalog_digest: catalog.catalog_digest,
    extensions: sortedByName(catalog.extensions),
    detail(extensionId) {
      const item = byId.get(extensionId);
      return item ? Promise.resolve(item) : Promise.reject(new ExtensionControlProtocolError(`Unknown extension ${extensionId}`));
    },
    searchPermissions: (query) => Promise.resolve(localSearch(query)),
    localSearch,
  };
}

/** Read the catalog index, falling back to the legacy catalog only when v2 is absent. */
export async function loadCatalogReadModel(): Promise<CatalogReadModel> {
  try {
    return await loadV2();
  } catch (error) {
    if (error instanceof CatalogV2UnsupportedError) return catalogReadModelFromCatalog(await fetchExtensionCatalog());
    throw error;
  }
}
