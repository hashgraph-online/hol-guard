import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

function installWindow(): void {
  const store = new Map<string, string>();
  const storage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => void store.set(key, value),
    removeItem: (key: string) => void store.delete(key),
  };
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin: "http://127.0.0.1:4174", pathname: "/extensions", search: "", hash: "" },
      localStorage: storage,
      sessionStorage: storage,
    },
  });
}

installWindow();

const { checkPluginUpdates, dismissPluginUpdate, parsePluginUpdate, safeReleasesUrl } = await import(
  "./plugin-updates-api"
);
const { PluginUpdatesSection, runtimeLabel, urgentReasonCopy, withoutDismissed } = await import(
  "./plugin-updates-section"
);
const { fetchPluginUpdatesApi } = await import("../guard-api");

type Seen = { url: string; method: string; body: string | null };
let seen: Seen[] = [];

function installFetch(status: number, body: unknown): void {
  seen = [];
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    seen.push({
      url: input instanceof Request ? input.url : String(input),
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? init.body : null,
    });
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  };
}

const releasesUrl = "https://hol.org/registry/plugins/acme%2Fdeploy-kit/releases";

// The browser may only ask the daemon for the two plugin update routes.
for (const rejected of [
  "https://hol.org/api/guard/plugins/releases/index",
  "/v1/plugins/updates/reset",
  "/v1/plugins/updates?x=1",
  "/v1/settings",
]) {
  await assert.rejects(() => fetchPluginUpdatesApi(rejected), /Invalid plugin updates API path/, rejected);
}

// Release links stay on hol.org over https.
assert.equal(safeReleasesUrl(releasesUrl), releasesUrl);
assert.equal(safeReleasesUrl("http://hol.org/registry/plugins/x/releases"), null);
assert.equal(safeReleasesUrl("https://hol.org.evil.com/x"), null);
assert.equal(safeReleasesUrl("javascript:alert(1)"), null);
assert.equal(safeReleasesUrl("https://user@hol.org/x"), null);

// A malformed entry is dropped rather than rendered half empty.
assert.equal(parsePluginUpdate({ slug: "a", runtime: "codex", installedVersion: "1.0.0" }), null);
assert.equal(parsePluginUpdate("nope"), null);

// The check asks the daemon, puts urgent prompts first and keeps the dismissed count.
{
  installFetch(200, {
    updates: [
      {
        slug: "zeta/plain",
        runtime: "claude-code",
        installedVersion: "1.0.0",
        latestVersion: "1.1.0",
        urgent: false,
        reason: null,
        releasesUrl: "https://example.com/elsewhere",
      },
      {
        slug: "acme/deploy-kit",
        runtime: "codex",
        installedVersion: "0.3.0",
        latestVersion: "0.4.0",
        urgent: true,
        reason: "security_fix",
        releasesUrl,
      },
      { slug: "broken" },
    ],
    dismissed: 2,
  });
  const result = await checkPluginUpdates();
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "/v1/plugins/updates");
  assert.equal(seen[0].method, "GET");
  assert.equal(result.status, "ok");
  if (result.status === "ok") {
    assert.deepEqual(
      result.updates.map((update) => update.slug),
      ["acme/deploy-kit", "zeta/plain"],
    );
    assert.equal(result.updates[0].releasesUrl, releasesUrl);
    assert.equal(result.updates[1].releasesUrl, null);
    assert.equal(result.dismissed, 2);
  }
}

// A daemon failure surfaces its safe message.
{
  installFetch(503, {
    error: "plugin_updates_unavailable",
    message: "This command needs a newer Guard native runtime. Run: pip install -U hol-guard",
  });
  const result = await checkPluginUpdates();
  assert.deepEqual(result, {
    status: "failed",
    message: "This command needs a newer Guard native runtime. Run: pip install -U hol-guard",
  });
}

// Dismissal posts the slug and the version the prompt showed.
{
  installFetch(200, { dismissed: true });
  await dismissPluginUpdate({ slug: "acme/deploy-kit", latestVersion: "0.4.0" });
  assert.equal(seen[0].url, "/v1/plugins/updates/dismiss");
  assert.equal(seen[0].method, "POST");
  assert.deepEqual(JSON.parse(seen[0].body ?? "{}"), { slug: "acme/deploy-kit", version: "0.4.0" });
  installFetch(400, { error: "invalid_plugin_update", message: "Name the listing slug and the version to dismiss." });
  await assert.rejects(
    () => dismissPluginUpdate({ slug: "", latestVersion: "" }),
    /Name the listing slug and the version to dismiss/,
  );
}

// Urgent copy names why, matching the CLI.
assert.equal(
  urgentReasonCopy({
    slug: "a",
    runtime: "codex",
    installedVersion: "1",
    latestVersion: "2",
    urgent: true,
    reason: "installed_high_severity",
    releasesUrl: null,
  }),
  "Urgent: the installed release had a high or critical finding.",
);
assert.equal(runtimeLabel("gemini"), "Gemini CLI");
assert.equal(runtimeLabel("unknown-runtime"), "unknown-runtime");

// A dismissal hides that version in every runtime, counts each hidden prompt,
// and also applies to a check that was already in flight.
{
  const prompt = (slug: string, runtime: string, latestVersion: string) => ({
    slug,
    runtime,
    installedVersion: "1.0.0",
    latestVersion,
    urgent: false,
    reason: null,
    releasesUrl: null,
  });
  const result = withoutDismissed(
    {
      status: "ok",
      updates: [prompt("acme/kit", "codex", "2.0.0"), prompt("acme/kit", "claude-code", "2.0.0"), prompt("b/c", "codex", "1.1.0")],
      dismissed: 1,
    },
    new Set(["acme/kit\u00002.0.0"]),
  );
  assert.deepEqual(result.status === "ok" ? [result.updates.map((u) => u.slug), result.dismissed] : null, [["b/c"], 3]);
  const newer = withoutDismissed(
    { status: "ok", updates: [prompt("acme/kit", "codex", "2.1.0")], dismissed: 0 },
    new Set(["acme/kit\u00002.0.0"]),
  );
  assert.equal(newer.status === "ok" ? newer.updates.length : -1, 1);
}

// Nothing is fetched until the reader asks.
{
  installFetch(200, { updates: [], dismissed: 0 });
  const markup = renderToStaticMarkup(createElement(PluginUpdatesSection));
  assert.match(markup, /Plugin updates/);
  assert.match(markup, /Check for plugin updates/);
  assert.match(markup, /nothing about your plugins is sent/);
  assert.equal(seen.length, 0);
}

console.log("plugin updates tests passed");
