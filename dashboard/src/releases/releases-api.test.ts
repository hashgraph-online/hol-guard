import assert from "node:assert/strict";

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
      location: { origin: "http://127.0.0.1:4174", pathname: "/releases", search: "", hash: "" },
      localStorage: storage,
      sessionStorage: storage,
    },
  });
}

installWindow();

const { fetchReleaseDetail, fetchReleaseIndex, RELEASES_PAGE_SIZE } = await import("./releases-api");
const { fetchReleaseFeedApi } = await import("../guard-api");

type Answer = { status: number; body: unknown } | { throws: true };

let requested: string[] = [];

function installFetch(answer: Answer): void {
  requested = [];
  globalThis.fetch = async (input: RequestInfo | URL): Promise<Response> => {
    requested.push(input instanceof Request ? input.url : String(input));
    if ("throws" in answer) {
      throw new TypeError("Failed to fetch");
    }
    return new Response(JSON.stringify(answer.body), {
      status: answer.status,
      headers: { "Content-Type": "application/json" },
    });
  };
}

const indexBody = {
  kind: "index",
  page: 1,
  pageSize: RELEASES_PAGE_SIZE,
  total: 1,
  totalPages: 1,
  generatedAt: "2026-10-21T00:00:00Z",
  releases: [],
};

// The browser may only ask the daemon for these two documents. Anything else —
// a portal URL, a traversal, a different daemon route — is refused here, before
// it can become a request.
{
  for (const rejected of [
    "https://hol.org/api/guard/releases/v1/index",
    "/v1/releases/index/../../v1/settings",
    "/v1/releases/contributors",
    "/v1/settings",
    "/v1/releases/index?slug=<script>",
  ]) {
    await assert.rejects(
      () => fetchReleaseFeedApi(rejected),
      /Invalid release feed API path/,
      `expected ${rejected} to be refused`,
    );
  }
}

// The index read asks the daemon, not hol.org, and carries bounded paging.
{
  installFetch({ status: 200, body: indexBody });
  const result = await fetchReleaseIndex({ page: 2 });
  assert.equal(result.status, "ok");
  assert.equal(requested.length, 1);
  assert.equal(requested[0], `/v1/releases/index?page=2&pageSize=${RELEASES_PAGE_SIZE}`);
  // An exact path, not a substring check: the browser leaves its own origin
  // for nothing, so anything but the daemon's own release route is a defect.
  assert.ok(requested[0].startsWith("/v1/releases/"), "the request stays on this device");
}

// A page number that is not a whole page falls back to the first page instead
// of forwarding the caller's value.
{
  installFetch({ status: 200, body: indexBody });
  await fetchReleaseIndex({ page: 0 });
  assert.match(requested[0], /page=1&/);
  installFetch({ status: 200, body: indexBody });
  await fetchReleaseIndex({ page: 2.5 });
  assert.match(requested[0], /page=1&/);
}

// Each failure keeps its own meaning, so the screen can say which it was.
{
  for (const [status, failure] of [
    [404, "not-found"],
    [501, "unsupported"],
    [503, "unavailable"],
    [400, "unavailable"],
    [502, "unavailable"],
  ] as const) {
    installFetch({ status, body: { error: "release_feed_transport_failed" } });
    const result = await fetchReleaseIndex();
    assert.equal(result.status, "failed");
    assert.equal(result.status === "failed" ? result.failure : null, failure, `status ${status}`);
  }
}

// The archive switched off on this device answers 503 like an upstream
// failure does. They are not the same answer: one can be retried and is
// hol.org's doing, the other is a setting here.
{
  installFetch({ status: 503, body: { error: "release_feed_capability_unavailable" } });
  const result = await fetchReleaseIndex();
  assert.equal(result.status === "failed" ? result.failure : null, "disabled");

  installFetch({ status: 503, body: { error: "release_feed_transport_failed" } });
  const upstream = await fetchReleaseIndex();
  assert.equal(upstream.status === "failed" ? upstream.failure : null, "unavailable");

  // The same code on another status keeps that status's meaning.
  installFetch({ status: 501, body: { error: "release_feed_capability_unavailable" } });
  const missing = await fetchReleaseIndex();
  assert.equal(missing.status === "failed" ? missing.failure : null, "unsupported");
}

// No answer at all is the daemon being unreachable, not an upstream problem.
{
  installFetch({ throws: true });
  const result = await fetchReleaseIndex();
  assert.equal(result.status === "failed" ? result.failure : null, "offline");
}

// A 200 that is not the document asked for is refused rather than rendered.
{
  installFetch({ status: 200, body: { kind: "detail", slug: "v3-53-0" } });
  const result = await fetchReleaseIndex();
  assert.equal(result.status === "failed" ? result.failure : null, "unavailable");

  installFetch({ status: 200, body: ["not", "a", "document"] });
  assert.equal((await fetchReleaseIndex()).status, "failed");
}

// A slug is a minted key, never a path: a bad one never becomes a request.
{
  installFetch({ status: 200, body: { kind: "detail" } });
  for (const bad of ["../etc/passwd", "V3-53-0", "v3_53_0", "", "v3-53-0/extra", `v${"3".repeat(200)}`]) {
    const result = await fetchReleaseDetail(bad);
    assert.equal(result.status, "failed", `expected ${bad} to be refused`);
    assert.equal(result.status === "failed" ? result.failure : null, "not-found");
  }
  assert.equal(requested.length, 0, "no refused slug reached the daemon");
}

// A published release reads the local detail route.
{
  installFetch({
    status: 200,
    body: { kind: "detail", slug: "v3-53-0", versionLabel: "3.53.0" },
  });
  const result = await fetchReleaseDetail("v3-53-0");
  assert.equal(result.status, "ok");
  assert.equal(requested[0], "/v1/releases/release?slug=v3-53-0");
}

console.log("releases-api.test.ts passed");
