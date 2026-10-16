import assert from "node:assert/strict";

import {
  CATALOG_SNAPSHOT_EXPIRED,
  clearCatalogReadCache,
  loadCatalogReadModel,
} from "./extension-catalog-v2";
import { ExtensionControlApiError } from "./extension-controls-api";

const DIGEST = "a".repeat(64);
const storage = { getItem: () => null, setItem: () => undefined, removeItem: () => undefined };
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
    sessionStorage: storage,
    localStorage: storage,
  },
});
const realFetch = globalThis.fetch;

type Reply = { status: number; body?: unknown; etag?: string };
type Handler = (path: string, params: URLSearchParams, headers: Headers) => Reply;

let requests: { path: string; params: URLSearchParams; ifNoneMatch: string | null }[] = [];

function serve(handler: Handler): void {
  requests = [];
  clearCatalogReadCache();
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://127.0.0.1:4174");
    const headers = new Headers(init?.headers);
    requests.push({ path: url.pathname, params: url.searchParams, ifNoneMatch: headers.get("If-None-Match") });
    const reply = handler(url.pathname, url.searchParams, headers);
    const responseHeaders: Record<string, string> = { "content-type": "application/json" };
    if (reply.etag) responseHeaders.ETag = reply.etag;
    const body = reply.status === 304 ? null : JSON.stringify(reply.body ?? {});
    return new Response(body, { status: reply.status, headers: responseHeaders });
  }) as typeof fetch;
}

function summary(id: string, name: string, extra: Record<string, unknown> = {}) {
  return {
    extension_id: id,
    name,
    description: `${name} commands`,
    required: false,
    trust_class: "first-party",
    catalog_defaults: { enabled: true, activation: "default-on" },
    publisher: { id: "hol", displayName: "Hashgraph Online" },
    icon: { kind: "none" },
    source: "built-in",
    version: "1.0.0",
    aliases: [],
    ecosystem_ids: [],
    executables: [name.toLowerCase()],
    action_classes: [],
    risk_classes: [],
    rule_count: 1,
    permission_count: 1,
    content_revision: `rev-${id}`,
    ...extra,
  };
}

function permission(extensionId: string, slug: string) {
  return {
    permission_id: `${extensionId}.permission.${slug}`,
    schema_version: 1,
    extension_id: extensionId,
    implementation_version: "1.0.0",
    label: `Allow ${slug}`,
    description: `${slug} access`,
    risk_tier: "high",
    baseline_floor: "review",
    default_enabled: true,
    configurable: true,
    fixed_reason: null,
    typed_capabilities: [],
    action_classes: [],
    rule_ids: [`${extensionId}.${slug}`],
    dependencies: [],
    conflicts: [],
    implied_permissions: [],
    introduced_version: "1.0.0",
    deprecated: false,
    replacement_permission_id: null,
    safer_guidance: [],
    example_command: `tool ${slug}`,
  };
}

function rule(extensionId: string, slug: string) {
  return {
    rule_id: `${extensionId}.${slug}`,
    rule_version: 1,
    title: slug,
    description: slug,
    severity: "high",
    risk_classes: [],
    action_classes: [],
    safer_alternatives: [],
    default_mode: "review",
    matcher_kind: "argv",
    safe_variants: [],
    compatibility_fallback: false,
  };
}

function page(items: unknown[], options: { total?: number; next?: string | null; snapshot?: string } = {}) {
  return {
    snapshot_id: options.snapshot ?? "snap-1",
    native_catalog_digest: DIGEST,
    total_count: options.total ?? items.length,
    items,
    next_cursor: options.next ?? null,
  };
}

const GIT = "command.git";
const NPM = "command.npm";
const INDEX = "/v2/extension-controls/catalog/index";

// Two index pages: one per extension, consistent snapshot.
function indexHandler(path: string, params: URLSearchParams): Reply | null {
  if (path !== INDEX) return null;
  return params.get("cursor") === "c1"
    ? { status: 200, etag: '"i2"', body: page([summary(GIT, "Git")], { total: 2 }) }
    : { status: 200, etag: '"i1"', body: page([summary(NPM, "npm")], { total: 2, next: "c1" }) };
}

try {
  {
    // Index traverses every page, sorts by name and reads no details.
    serve((path, params) => indexHandler(path, params) ?? { status: 500 });
    const model = await loadCatalogReadModel();
    assert.equal(model.protocol, "v2");
    assert.equal(model.catalog_digest, DIGEST);
    assert.deepEqual(model.extensions.map((item) => item.extension_id), [GIT, NPM]);
    assert.equal(model.extensions[0]?.enabled, true);
    assert.equal(model.extensions[0]?.content_revision, `rev-${GIT}`);
    assert.deepEqual(requests.map((entry) => entry.params.get("cursor")), [null, "c1"]);
    assert.ok(requests.every((entry) => entry.path === INDEX && entry.params.get("limit") === "100"));

    // A second read revalidates with the stored validators and reuses 304s.
    serve((path, params, headers) => {
      const reply = indexHandler(path, params) ?? { status: 500 };
      return headers.get("If-None-Match") === reply.etag ? { status: 304, etag: reply.etag } : reply;
    });
    // serve() clears the cache; prime it, then read again.
    await loadCatalogReadModel();
    requests = [];
    const again = await loadCatalogReadModel();
    assert.deepEqual(again.extensions.map((item) => item.extension_id), [GIT, NPM]);
    assert.deepEqual(requests.map((entry) => entry.ifNoneMatch), ['"i1"', '"i2"']);
  }

  {
    // A 304 with an unknown validator is retried once without a condition.
    let calls = 0;
    serve((path, params, headers) => {
      calls += 1;
      if (calls === 1) return { status: 304, etag: '"x"' };
      assert.equal(headers.get("If-None-Match"), null);
      return indexHandler(path, params) ?? { status: 500 };
    });
    const model = await loadCatalogReadModel();
    assert.equal(model.extensions.length, 2);
  }

  {
    // Only 404 and 501 catalog_read_model_unavailable fall back to v1.
    const v1 = {
      schema_version: "1.0.0",
      catalog_digest: DIGEST,
      extensions: [{
        ...summary(GIT, "Git"),
        schema_version: 1,
        enabled: true,
        dependencies: [],
        conflicts: [],
        delegated_protection: null,
        project_markers: [],
        reference_urls: [],
        safer_alternatives: [],
        rules: [rule(GIT, "push")],
        permissions: [permission(GIT, "push")],
      }],
    };
    for (const unsupported of [{ status: 404, body: { error: "not_found" } }, { status: 404, body: {} }, { status: 501, body: { error: "catalog_read_model_unavailable" } }]) {
      serve((path) => (path === "/v1/extension-controls/catalog" ? { status: 200, body: v1 } : unsupported));
      const model = await loadCatalogReadModel();
      assert.equal(model.protocol, "v1");
      assert.deepEqual(model.localSearch?.("git PUSH").map((hit) => hit.permission.permission_id), [`${GIT}.permission.push`]);
      assert.deepEqual(model.localSearch?.("push absent"), []);
    }
    for (const failure of [{ status: 501, body: { error: "other" } }, { status: 500, body: {} }, { status: 401, body: { error: "unauthorized" } }]) {
      serve((path) => (path === "/v1/extension-controls/catalog" ? { status: 200, body: v1 } : failure));
      await assert.rejects(loadCatalogReadModel(), (error: unknown) => error instanceof ExtensionControlApiError && error.status === failure.status);
      assert.ok(requests.every((entry) => entry.path.startsWith("/v2/")));
    }
  }

  {
    // A snapshot change mid-traversal restarts once, then succeeds.
    let snapshot = "snap-old";
    let restarted = false;
    serve((path, params) => {
      if (params.get("cursor") === "c1" && snapshot === "snap-old") {
        snapshot = "snap-new";
        restarted = true;
        return { status: 409, body: { error: CATALOG_SNAPSHOT_EXPIRED } };
      }
      const reply = indexHandler(path, params) ?? { status: 500 };
      return { ...reply, body: { ...(reply.body as object), snapshot_id: snapshot } };
    });
    const model = await loadCatalogReadModel();
    assert.ok(restarted);
    assert.equal(model.extensions.length, 2);

    // A second expiry is surfaced rather than looped on.
    serve(() => ({ status: 409, body: { error: CATALOG_SNAPSHOT_EXPIRED } }));
    await assert.rejects(loadCatalogReadModel(), (error: unknown) => error instanceof ExtensionControlApiError && error.code === CATALOG_SNAPSHOT_EXPIRED);
    assert.equal(requests.length, 2);
  }

  {
    // Integrity: duplicates, short totals, stalled cursors and missing validators fail closed.
    const cases: Handler[] = [
      (_, params) => ({ status: 200, etag: `"${params.get("cursor") ?? "p"}"`, body: page([summary(GIT, "Git")], { total: 2, next: params.get("cursor") ? null : "c1" }) }),
      () => ({ status: 200, etag: '"p"', body: page([summary(GIT, "Git")], { total: 3 }) }),
      () => ({ status: 200, etag: '"p"', body: page([], { total: 1, next: "c1" }) }),
      () => ({ status: 200, body: page([summary(GIT, "Git")]) }),
      () => ({ status: 200, etag: '"p"', body: { ...page([summary(GIT, "Git")]), total_count: "1" } }),
    ];
    for (const handler of cases) {
      serve(handler);
      await assert.rejects(loadCatalogReadModel(), (error: unknown) => error instanceof ExtensionControlApiError && error.status === 502);
    }
  }

  {
    // Details read only on request, from paged collections, and are cached by revision.
    const base = "/v2/extension-controls/catalog/extensions/command.git";
    serve((path, params) => {
      const index = indexHandler(path, params);
      if (index) return index;
      if (path === base) {
        return { status: 200, etag: '"d"', body: { snapshot_id: "snap-1", native_catalog_digest: DIGEST, extension: summary(GIT, "Git", { rule_count: 2, permission_count: 2, dependencies: [], conflicts: [], delegated_protection: null, project_markers: [], reference_urls: [], safer_alternatives: [], schema_version: 1 }), collections: { permissions: 2, rules: 2 } } };
      }
      if (path === `${base}/permissions`) {
        return params.get("cursor")
          ? { status: 200, etag: '"p2"', body: page([permission(GIT, "status")], { total: 2 }) }
          : { status: 200, etag: '"p1"', body: page([permission(GIT, "push")], { total: 2, next: "pc" }) };
      }
      if (path === `${base}/rules`) return { status: 200, etag: '"r"', body: page([rule(GIT, "push"), rule(GIT, "status")]) };
      return { status: 500 };
    });
    const model = await loadCatalogReadModel();
    assert.ok(requests.every((entry) => entry.path === INDEX));
    const detail = await model.detail(GIT);
    assert.deepEqual(detail.permissions.map((entry) => entry.permission_id), [`${GIT}.permission.push`, `${GIT}.permission.status`]);
    assert.equal(detail.rules.length, 2);
    assert.equal(detail.enabled, true);
    assert.equal(detail.activation, "default-on");
    assert.equal("catalog_defaults" in detail, false);
    assert.ok(!requests.some((entry) => entry.path.endsWith("/mcp-tools")));
    const before = requests.length;
    assert.equal(await model.detail(GIT), detail);
    assert.equal(requests.length, before);
    await assert.rejects(model.detail("command.unknown"), /Unknown extension/);
  }

  {
    // Search uses the daemon route and maps hits to their index summaries.
    serve((path, params) => {
      const index = indexHandler(path, params);
      if (index) return index;
      if (path === "/v2/extension-controls/catalog/permissions") {
        assert.equal(params.get("q"), "git push");
        return { status: 200, etag: '"s"', body: page([permission(GIT, "push")]) };
      }
      return { status: 500 };
    });
    const model = await loadCatalogReadModel();
    assert.equal(model.localSearch, undefined);
    assert.deepEqual(await model.searchPermissions("   "), []);
    const hits = await model.searchPermissions("  Git   PUSH ");
    assert.equal(hits.length, 1);
    assert.equal(hits[0]?.extension.extension_id, GIT);
    assert.equal(hits[0]?.permission.permission_id, `${GIT}.permission.push`);
  }

  {
    // Search from a replaced snapshot is reported as stale.
    serve((path, params) => indexHandler(path, params) ?? { status: 200, etag: '"s"', body: page([], { snapshot: "snap-2" }) });
    const model = await loadCatalogReadModel();
    await assert.rejects(model.searchPermissions("git"), (error: unknown) => error instanceof ExtensionControlApiError && error.code === CATALOG_SNAPSHOT_EXPIRED);
  }

  {
    // A superseded search stops before requesting its next page.
    const controller = new AbortController();
    serve((path, params) => {
      const index = indexHandler(path, params);
      if (index) return index;
      controller.abort();
      return { status: 200, etag: '"s1"', body: page([permission(GIT, "push")], { total: 2, next: "c1" }) };
    });
    const model = await loadCatalogReadModel();
    const before = requests.length;
    await assert.rejects(model.searchPermissions("git", controller.signal), (error: unknown) => error instanceof DOMException && error.name === "AbortError");
    assert.equal(requests.length, before + 1);
  }
} finally {
  globalThis.fetch = realFetch;
  Reflect.deleteProperty(globalThis, "window");
}

console.log("extension catalog v2 tests passed");
