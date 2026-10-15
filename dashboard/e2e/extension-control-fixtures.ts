import { expect, type Page } from "@playwright/test";

import {
  defaultSettingsPayload,
  emptyInventoryPayload,
  emptyPoliciesPayload,
  emptyReceiptsPayload,
  freeStateSnapshot,
} from "./fixture-states";

/**
 * Shared route fixtures for extension-control-center e2e specs: one catalog
 * builder, one effective-projection builder, and the mount/initialize pair
 * every scenario drives.
 */
export const DAEMON_ORIGIN = "http://127.0.0.1:4175";
export const DIGEST = "a".repeat(64);

export function extension(id = "command.git", alias = "command.scm") {
  const slug = id.slice("command.".length);
  const ruleId = `${id}.hard-reset`;
  const permissionId = `${id}.permission.hard-reset`;
  return {
    schema_version: 2,
    extension_id: id,
    version: "1.2.3",
    name: slug === "git" ? "Git" : slug.replaceAll("-", " "),
    description: "Canonical extension metadata <script>window.__ecc_xss = true</script>",
    enabled: true,
    required: false,
    trust_class: "first-party",
    activation: "default-on",
    publisher: { id: "hol", displayName: "Hashgraph Online" },
    icon: { kind: "none" },
    source: "built-in",
    aliases: alias ? [alias] : [],
    dependencies: [],
    conflicts: [],
    delegated_protection: null,
    ecosystem_ids: [slug],
    executables: [slug],
    project_markers: [`.${slug}`],
    reference_urls: ["https://example.com/reference"],
    action_classes: [`${slug}.history.rewrite`],
    risk_classes: ["destructive_shell"],
    safer_alternatives: ["Create a checkpoint first."],
    rule_count: 1,
    rules: [{
      rule_id: ruleId,
      rule_version: 1,
      title: "Hard reset",
      description: "Detects destructive reset behavior.",
      severity: "high",
      risk_classes: ["destructive_shell"],
      action_classes: [`${slug}.history.rewrite`],
      safer_alternatives: ["Use a narrower restore operation."],
      default_mode: "review",
      matcher_kind: "ExecutableMatcher",
      safe_variants: [{ variant_id: "status", title: "Status", matcher_kind: "ExecutableMatcher" }],
      compatibility_fallback: false,
    }],
    permission_count: 1,
    permissions: [{
      permission_id: permissionId,
      schema_version: 1,
      extension_id: id,
      implementation_version: "1.2.3",
      label: "Hard reset",
      description: "Controls destructive reset behavior.",
      risk_tier: "high",
      baseline_floor: "review",
      default_enabled: true,
      configurable: true,
      fixed_reason: null,
      typed_capabilities: [],
      action_classes: [`${slug}.history.rewrite`],
      rule_ids: [ruleId],
      dependencies: [],
      conflicts: [],
      implied_permissions: [],
      introduced_version: "1.0.0",
      deprecated: false,
      replacement_permission_id: null,
      safer_guidance: ["Create a checkpoint first."],
    }],
  };
}

export function catalog() {
  return {
    schema_version: "guard.daemon.extension-controls.v1",
    control_schema_version: "1.0.0",
    catalog_digest: DIGEST,
    extensions: [extension(), extension("command.filesystem", ""), extension("command.cloud.aws", "")],
    limits: { max_body_bytes: 8_000_000, max_controls: 4096, max_observations: 2048 },
  };
}

export function effective(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: "guard.daemon.extension-controls.v1",
    health: "protected",
    revision: 7,
    catalog_digest: DIGEST,
    global_lockdown: false,
    controls: [],
    layers: [],
    failures: [],
    ...overrides,
  };
}

export type CatalogFixture = ReturnType<typeof catalog>;
type CatalogFixtureItem = CatalogFixture["extensions"][number];
export type CatalogV2Request = { path: string; search: URLSearchParams };

const SUMMARY_FIELDS = [
  "extension_id", "name", "description", "required", "trust_class", "publisher", "icon", "source", "version",
  "aliases", "ecosystem_ids", "executables", "action_classes", "risk_classes", "rule_count", "permission_count", "surface",
] as const;

function catalogDefaults(item: CatalogFixtureItem) {
  return { enabled: item.enabled, activation: item.activation };
}

function catalogSummary(item: CatalogFixtureItem) {
  const fields = Object.fromEntries(SUMMARY_FIELDS.filter((key) => key in item).map((key) => [key, item[key as keyof CatalogFixtureItem]]));
  return { ...fields, catalog_defaults: catalogDefaults(item), content_revision: `rev-${item.extension_id}-${item.version}` };
}

function catalogPage(items: readonly unknown[], search: URLSearchParams, snapshot: string, digest: string) {
  const limit = Number(search.get("limit") ?? "100");
  const offset = Number(search.get("cursor") ?? "0");
  const end = offset + limit;
  return {
    snapshot_id: snapshot,
    native_catalog_digest: digest,
    total_count: items.length,
    items: items.slice(offset, end),
    next_cursor: end < items.length ? String(end) : null,
  };
}

/**
 * Serves the bounded v2 catalog routes from a v1 catalog fixture, matching the
 * daemon's paging, detail and permission-search contract. A null source
 * answers 404 so the dashboard exercises its legacy fallback.
 */
export async function routeCatalogV2(page: Page, source: () => CatalogFixture | null): Promise<CatalogV2Request[]> {
  const requests: CatalogV2Request[] = [];
  await page.route("**/v2/extension-controls/catalog/**", async (route) => {
    const url = new URL(route.request().url());
    requests.push({ path: url.pathname, search: url.searchParams });
    const current = source();
    const respond = (status: number, body: unknown) => route.fulfill({
      status,
      contentType: "application/json",
      headers: { ETag: `"${status}-${url.pathname}-${url.search}"`, "Cache-Control": "private, no-cache" },
      body: JSON.stringify(body),
    });
    if (!current) return respond(404, { error: "not_found" });
    const snapshot = `snapshot-${current.catalog_digest.slice(0, 16)}`;
    const route_ = url.pathname.slice(url.pathname.indexOf("/catalog/") + "/catalog/".length);
    if (route_ === "index") return respond(200, catalogPage(current.extensions.map(catalogSummary), url.searchParams, snapshot, current.catalog_digest));
    if (route_ === "permissions") {
      const terms = (url.searchParams.get("q") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
      const hits = current.extensions.flatMap((item) => item.permissions.filter((permission) => {
        const text = [
          permission.label, (permission as { example_command?: string }).example_command ?? "", permission.permission_id,
          permission.description, (permission as { family?: string }).family ?? "", item.name, item.extension_id, ...item.executables,
        ].join("\n").toLowerCase();
        return terms.length > 0 && terms.every((term) => text.includes(term));
      }));
      return respond(200, catalogPage(hits, url.searchParams, snapshot, current.catalog_digest));
    }
    const match = /^extensions\/([^/]+)(?:\/(permissions|rules|mcp-tools))?$/.exec(route_);
    const item = match ? current.extensions.find((entry) => entry.extension_id === decodeURIComponent(match[1]!)) : undefined;
    if (!match || !item) return respond(404, { error: "not_found" });
    const { permissions, rules, enabled: _enabled, activation: _activation, ...fields } = item;
    const tools = (item as { mcp_tools?: unknown[] }).mcp_tools;
    if (match[2] === "permissions") return respond(200, catalogPage(permissions, url.searchParams, snapshot, current.catalog_digest));
    if (match[2] === "rules") return respond(200, catalogPage(rules, url.searchParams, snapshot, current.catalog_digest));
    if (match[2] === "mcp-tools") return tools ? respond(200, catalogPage(tools, url.searchParams, snapshot, current.catalog_digest)) : respond(404, { error: "not_found" });
    const { mcp_tools: _tools, ...extension } = fields as typeof fields & { mcp_tools?: unknown };
    return respond(200, {
      snapshot_id: snapshot,
      native_catalog_digest: current.catalog_digest,
      extension: { ...extension, catalog_defaults: catalogDefaults(item), content_revision: catalogSummary(item).content_revision },
      collections: { permissions: permissions.length, rules: rules.length, ...(tools ? { mcp_tools: tools.length } : {}) },
    });
  });
  return requests;
}

export async function mount(page: Page, options: {
  malformedCatalog?: boolean;
  effective?: Record<string, unknown>;
  runtime?: unknown;
  runtimeRefresh?: unknown;
  failEffectiveRefresh?: boolean;
  refreshEffectiveDelayMs?: number;
  /** "v1" makes the daemon answer 404 on v2 routes, as a pre-v2 daemon does. */
  catalogProtocol?: "v1" | "v2";
  catalog?: CatalogFixture;
} = {}): Promise<CatalogV2Request[]> {
  let effectiveCalls = 0;
  let runtimeCalls = 0;
  const catalogV2Requests = await routeCatalogV2(page, () => {
    if (options.catalogProtocol === "v1") return null;
    return options.malformedCatalog ? { ...catalog(), extensions: [{ extension_id: "../../bad" } as CatalogFixtureItem] } : options.catalog ?? catalog();
  });
  await page.route("**/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path.endsWith("/initialize")) body = { auth_token: "fixture-session-token" };
    else if (path.endsWith("/runtime")) { runtimeCalls += 1; body = runtimeCalls > 1 ? options.runtimeRefresh ?? options.runtime ?? freeStateSnapshot : options.runtime ?? freeStateSnapshot; }
    else if (path.endsWith("/requests")) body = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    else if (path.endsWith("/receipts")) body = emptyReceiptsPayload;
    else if (path.endsWith("/policy")) body = emptyPoliciesPayload;
    else if (path.endsWith("/settings")) body = defaultSettingsPayload;
    else if (path.endsWith("/inventory")) body = emptyInventoryPayload;
    else if (path.endsWith("/extension-controls/catalog")) {
      body = options.malformedCatalog ? { ...catalog(), extensions: [{ extension_id: "../../bad" }] } : options.catalog ?? catalog();
    } else if (path.endsWith("/extension-controls/effective")) {
      effectiveCalls += 1;
      if (effectiveCalls > 1 && options.failEffectiveRefresh) {
        await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "unavailable" }) });
        return;
      }
      if (effectiveCalls > 1 && options.refreshEffectiveDelayMs) {
        await new Promise((resolve) => setTimeout(resolve, options.refreshEffectiveDelayMs));
      }
      body = options.effective ?? effective();
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  return catalogV2Requests;
}

export async function initialize(page: Page) {
  await page.goto(`/extensions?guardDaemon=${DAEMON_ORIGIN}`);
  await expect(page.getByRole("heading", { name: "Extensions", exact: true })).toBeVisible();
}
