import { createHmac } from "node:crypto";

import {
  canonicalizeGuardDaemonOrigin,
  fetchGuardUpdateStatus,
  prepareGuardDaemonReconnect,
  readGuardDaemonReconnectDiagnostic,
  reconnectGuardDaemonAfterUpdate,
} from "./guard-api";
import type { GuardDaemonReconnectAuthorization } from "./guard-types";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }

  allValues(): string[] {
    return [...this.values.values()];
  }
}

const sessionStorage = new MemoryStorage();
const localStorage = new MemoryStorage();
sessionStorage.setItem("guard-token", "prior-dashboard-session");
sessionStorage.setItem("guardDaemon", "http://127.0.0.1:4781");
const location = {
  origin: "https://hol.org",
  port: "",
  pathname: "/",
  search: "",
  hash: "#guardDaemon=http%3A%2F%2F127.0.0.1%3A60000",
  replace: (_url: string) => undefined,
};

Object.assign(globalThis, {
  window: {
    location,
    sessionStorage,
    localStorage,
    setTimeout,
    clearTimeout,
  },
});

const authorizationRaw = {
  protocol_version: 1,
  reconnect_id: "11".repeat(32),
  verifier: "22".repeat(32),
  surface: "dashboard",
  issued_at_ms: Date.now() - 1_000,
  expires_at_ms: Date.now() + 300_000,
  installation_id: "33".repeat(32),
  guard_home_id: "44".repeat(32),
} as const;

function canonicalPayload(value: Record<string, string | number>): string {
  return JSON.stringify(
    Object.fromEntries(
      Object.entries(value).sort(([left], [right]) => {
        if (left < right) return -1;
        if (left > right) return 1;
        return 0;
      }),
    ),
  );
}

function proof(
  proofContext: "server" | "client",
  challenge: Record<string, string | number>,
): string {
  return createHmac("sha256", Buffer.from(authorizationRaw.verifier, "hex"))
    .update(canonicalPayload({ proof_context: proofContext, ...challenge }))
    .digest("hex");
}

const canonicalFixture = {
  protocol_version: 1,
  reconnect_id: "11".repeat(32),
  client_nonce: "66".repeat(32),
  server_nonce: "55".repeat(32),
  state_id: "state",
  candidate_origin: "http://127.0.0.1:4781",
  installation_id: "33".repeat(32),
  guard_home_id: "44".repeat(32),
  surface: "dashboard",
  issued_at_ms: 1_000,
  expires_at_ms: 2_000,
};
assert(
  proof("server", canonicalFixture) ===
    "40dc0312c6c1e1ddcf80f94216b2a18e01a0e77c4233e904012b8491187c3ceb",
  "browser and daemon must share one canonical server-proof encoding",
);
assert(
  proof("client", canonicalFixture) ===
    "1c5d2ef201d59244f432353caefdff67849c4a0fae0fd9201f185f4e4e04240e",
  "browser and daemon must share one canonical client-proof encoding",
);
for (const rejectedOrigin of [
  "http://localhost:4781",
  "http://127.1:4781",
  "http://2130706433:4781",
  "http://127.0.0.1:04781",
  "https://127.0.0.1:4781",
  "http://user@127.0.0.1:4781",
  "http://127.0.0.1:4781/path",
  "http://127.0.0.1:4781/#fragment",
]) {
  assert(canonicalizeGuardDaemonOrigin(rejectedOrigin) === null, `${rejectedOrigin} must not be a candidate origin`);
}
assert(
  canonicalizeGuardDaemonOrigin("http://127.0.0.1:4781") === "http://127.0.0.1:4781",
  "canonical IPv4 loopback origins should remain available",
);

type FetchMode = "prepare" | "shape-only" | "authenticated";
let mode: FetchMode = "prepare";
const fetchEvents: Array<{ url: string; credentialed: boolean; redirect: RequestRedirect | undefined }> = [];
let clientProofAccepted = false;

globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const url = String(input);
  const headers = new Headers(init?.headers);
  const credentialed = headers.has("X-Guard-Dashboard-Session") || headers.has("Authorization");
  fetchEvents.push({ url, credentialed, redirect: init?.redirect });

  if (url.endsWith("/v1/update/reconnect/prepare")) {
    assert(credentialed, "prepare must use the already authenticated dashboard session");
    assert(
      url === "http://127.0.0.1:4781/v1/update/reconnect/prepare",
      "prepare must ignore a hostile daemon fragment and remain pinned to the established daemon",
    );
    return Response.json(authorizationRaw);
  }
  if (url.endsWith("/healthz")) {
    const expectedCandidate =
      url.startsWith("http://127.0.0.1:4781/") ||
      (mode === "authenticated" && url.startsWith("http://127.0.0.1:4782/"));
    return expectedCandidate
      ? Response.json({ ok: true, compatibility_version: 2 })
      : Response.json({ error: "not_found" }, { status: 404 });
  }
  if (url.endsWith("/v1/update/reconnect/challenge")) {
    assert(!credentialed, "candidate challenge must not receive dashboard credentials");
    if (mode === "shape-only") {
      return Response.json({ error: "not_found" }, { status: 404 });
    }
    if (url.startsWith("http://127.0.0.1:4781/")) {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          init?.signal?.addEventListener(
            "abort",
            () => controller.error(new Error("aborted hostile candidate body")),
            { once: true },
          );
        },
      });
      return new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
    }
    const request = JSON.parse(String(init?.body)) as Record<string, string | number>;
    const challenge = {
      protocol_version: 1,
      reconnect_id: authorizationRaw.reconnect_id,
      client_nonce: request.client_nonce,
      server_nonce: "55".repeat(32),
      state_id: "new-daemon-state",
      candidate_origin: request.candidate_origin,
      installation_id: authorizationRaw.installation_id,
      guard_home_id: authorizationRaw.guard_home_id,
      surface: "dashboard",
      issued_at_ms: Date.now() - 10,
      expires_at_ms: Date.now() + 5_000,
    };
    return Response.json({ ...challenge, proof: proof("server", challenge) });
  }
  if (url.endsWith("/v1/update/reconnect/verify")) {
    assert(!credentialed, "candidate proof verification must not receive dashboard credentials");
    const request = JSON.parse(String(init?.body)) as {
      challenge: Record<string, string | number>;
      proof: string;
    };
    clientProofAccepted = request.proof === proof("client", request.challenge);
    return Response.json(
      clientProofAccepted ? { verified: true } : { error: "daemon_candidate_unavailable" },
      { status: clientProofAccepted ? 200 : 404 },
    );
  }
  if (url.endsWith("/v1/update/status")) {
    if (mode !== "prepare") {
      assert(clientProofAccepted, "status credential was sent before mutual proof completed");
    }
    return Response.json({
      current_version: "9.9.9",
      latest_version: "9.9.9",
      installer: "pipx",
      version_check: {
        source: "pypi",
        status: "current",
        current_version: "9.9.9",
        latest_version: "9.9.9",
        update_available: false,
      },
      auto_updatable: true,
      update_available: false,
    });
  }
  if (url.endsWith("/v1/initialize")) {
    assert(clientProofAccepted, "session initialization credential was sent before mutual proof completed");
    return Response.json({ dashboard_session_token: "legitimate-refreshed-token" });
  }
  return Response.json({ error: "not_found" }, { status: 404 });
}) as typeof fetch;

await fetchGuardUpdateStatus();
assert(
  fetchEvents[0]?.url === "http://127.0.0.1:4781/v1/update/status",
  "a hostile daemon fragment must not replace the origin bound to a stored dashboard credential",
);
const authorization = await prepareGuardDaemonReconnect();
assert(
  authorization.verifier === authorizationRaw.verifier,
  "prepare should return browser-held verifier material without persisting it",
);

mode = "shape-only";
const shapeOnlyStart = fetchEvents.length;
const shapeOnlyResult = await reconnectGuardDaemonAfterUpdate({ authorization });
const shapeOnlyEvents = fetchEvents.slice(shapeOnlyStart);
assert(shapeOnlyResult === null, "shape-only loopback service must not be selected as Guard");
assert(
  shapeOnlyEvents.every((event) => !event.credentialed),
  "shape-only loopback candidate received dashboard credentials before proving identity",
);
assert(
  shapeOnlyEvents.every((event) => event.redirect === "error"),
  "health and failed challenge probes must reject redirects",
);
assert(
  readGuardDaemonReconnectDiagnostic() === "dashboard_reconnect_candidate_unavailable",
  "shape-only failure should retain a stable secret-free diagnostic",
);

mode = "authenticated";
clientProofAccepted = false;
const authenticatedStart = fetchEvents.length;
const authenticatedResult = await reconnectGuardDaemonAfterUpdate({
  authorization: authorization as GuardDaemonReconnectAuthorization,
});
const authenticatedEvents = fetchEvents.slice(authenticatedStart);
assert(
  authenticatedResult?.origin === "http://127.0.0.1:4782",
  "later authenticated candidate must win over the first shape-only match in a concurrent batch",
);
assert(clientProofAccepted, "legitimate daemon and browser proofs should verify");
const firstCredentialed = authenticatedEvents.findIndex((event) => event.credentialed);
const proofVerification = authenticatedEvents.findIndex((event) => event.url.endsWith("/v1/update/reconnect/verify"));
assert(
  firstCredentialed > proofVerification,
  "dashboard credentials must appear only after successful proof verification",
);
for (const event of authenticatedEvents) {
  assert(event.redirect === "error", `${event.url} must reject redirects during reconnect`);
}
assert(
  ![...sessionStorage.allValues(), ...localStorage.allValues()].includes(authorization.verifier),
  "reconnect verifier must remain in memory and out of browser storage",
);
assert(
  !readGuardDaemonReconnectDiagnostic().includes(authorization.verifier),
  "reconnect diagnostics must not include verifier material",
);

console.log("guard-update-reconnect-security.test.ts: all tests passed");
