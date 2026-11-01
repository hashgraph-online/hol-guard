import assert from "node:assert/strict";
import test from "node:test";

import { contextStatus } from "../e2e/integration/context-status";
import type { IntegrationState } from "../e2e/integration/fixtures";

const state = { origin: "http://127.0.0.1:1", daemonToken: "synthetic-fixture-token" } as IntegrationState;

test("read-only polling recovers from explicit busy and generation-stale replies", async () => {
  const original = globalThis.fetch;
  const statuses = ["native_context_assistance_busy", "native_context_assistance_context_busy", "native_context_assistance_context_stale"];
  const ready = { availability: "available", effective_enabled: true };
  let calls = 0;
  globalThis.fetch = async (input, init) => {
    assert.equal(new URL(String(input)).pathname, "/v1/context-assistance");
    assert.equal(init?.method ?? "GET", "GET");
    calls += 1;
    return statuses.length ? Response.json({ code: statuses.shift() }, { status: 409 }) : Response.json(ready);
  };
  try {
    assert.deepEqual(await contextStatus(state), ready);
    assert.equal(calls, 4);
  } finally {
    globalThis.fetch = original;
  }
});

test("real refusals fail immediately and unknown text stays out of errors", async () => {
  const original = globalThis.fetch;
  try {
    for (const code of ["native_context_assistance_disabled", "native_context_assistance_context_conflict", "synthetic private response text"]) {
      let calls = 0;
      globalThis.fetch = async () => {
        calls += 1;
        return Response.json({ code }, { status: 409 });
      };
      await assert.rejects(contextStatus(state), (error: Error) => {
        assert.match(error.message, /non-retryable conflict/);
        assert.ok(!error.message.includes("synthetic private response text"));
        return true;
      });
      assert.equal(calls, 1);
    }
    globalThis.fetch = async () => Response.json({}, { status: 401 });
    await assert.rejects(contextStatus(state), /HTTP 401/);
  } finally {
    globalThis.fetch = original;
  }
});

test("a continuously stale read fails after twelve attempts", async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return Response.json({ code: "native_context_assistance_context_stale" }, { status: 409 });
  };
  try {
    await assert.rejects(contextStatus(state), /bounded read-only retries/);
    assert.equal(calls, 12);
  } finally {
    globalThis.fetch = original;
  }
});
