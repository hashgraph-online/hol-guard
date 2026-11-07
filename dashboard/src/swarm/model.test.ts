import assert from "node:assert/strict";
import test from "node:test";
import { parseAgent, parseSnapshot } from "./api";
import { contextFor, filterAgents, projectsFor } from "./model";
import type { Agent, SwarmSnapshot } from "./types";
import type { ContextWorkspaceScope } from "../context-assistance/workspaces-api";

const agent: Agent = { id: "run-1", harness: "codex", label: "Codex", origin: "managed", state: "running", workspace: "/work/one/app", task: "Review login", model: null,
  pid: 123, started_at_ms: 1000, updated_at_ms: 2000, detail: "Working", activity: null, revision: 1, queued: 0, context_calls: 0, input_tokens: 0, output_tokens: 0,
  controls: { message: true, steer: false, interrupt: true, stop: true } };
const snapshot: SwarmSnapshot = { schema: "guard-swarm-snapshot.v1", epoch: "service-1", observed_at_ms: 2000,
  discovery: { state: "ready", limited: false, detail: "Local processes" }, agents: [agent], adapters: [] };

test("invalid control authority, numeric fields, duplicate identities and oversized payloads are rejected", () => {
  assert.equal(parseSnapshot(snapshot).agents[0].id, agent.id);
  assert.throws(() => parseAgent({ ...agent, origin: "observed" }));
  assert.throws(() => parseAgent({ ...agent, revision: "1" }));
  assert.throws(() => parseAgent({ ...agent, pid: -1 }));
  assert.throws(() => parseSnapshot({ ...snapshot, epoch: "" }));
  assert.throws(() => parseSnapshot({ ...snapshot, agents: [agent, agent] }));
  assert.throws(() => parseSnapshot({ ...snapshot, agents: Array(321).fill(agent) }));
});

test("projects with identical folder names stay separate; search and attention are composable", () => {
  const other = { ...agent, id: "run-2", workspace: "/work/two/app", state: "failed" as const };
  assert.equal(projectsFor([agent, other]).length, 2);
  assert.deepEqual(filterAgents([agent, other], "/work/one/app", "login", false), [agent]);
  assert.deepEqual(filterAgents([agent, other], null, "codex", true), [other]);
  assert.deepEqual(filterAgents([agent, other], "/work/one/app", "login", true), []);
});

test("context matches exact projects and app grants or every-app picks without claiming agent use", () => {
  const scope = { scope_id: "s", workspace: agent.workspace, app: "codex", sources: [], revoked: false } as unknown as ContextWorkspaceScope;
  assert.equal(contextFor(agent, true, [scope]).available, true);
  assert.match(contextFor(agent, true, [scope]).detail, /does not confirm/);
  assert.equal(contextFor({ ...agent, workspace: "/other/app" }, true, [scope]).available, false);
  assert.equal(contextFor({ ...agent, harness: "claude-code" }, true, [scope]).available, false);
  assert.equal(contextFor(agent, true, [{ ...scope, revoked: true }]).available, false);
  assert.equal(contextFor(agent, false, [scope]).label, "CIGAR off");
  assert.equal(contextFor(agent, true, null).label, "Context unknown");
  const picked = { ...scope, app: "dashboard" };
  assert.equal(contextFor(agent, true, [picked]).available, true);
  assert.equal(contextFor({ ...agent, harness: "claude-code" }, true, [picked]).available, true);
  assert.equal(contextFor({ ...agent, workspace: "/other/app" }, true, [picked]).available, false);
  assert.equal(contextFor(agent, true, [{ ...picked, revoked: true }]).available, false);
  assert.match(contextFor(agent, true, [picked]).detail, /new prompts/);
  assert.doesNotMatch(contextFor(agent, true, [picked]).detail, /needs pairing/);
  assert.match(contextFor({ ...agent, harness: "gemini" }, true, [picked]).detail, /needs pairing/);
});
