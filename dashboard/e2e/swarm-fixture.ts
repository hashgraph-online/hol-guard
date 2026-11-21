import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { defaultSettingsPayload, emptyInventoryPayload, emptyPoliciesPayload, emptyReceiptsPayload, freeStateSnapshot } from "./fixture-states";
import type { Agent, SwarmSnapshot } from "../src/swarm/types";

export function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return { id: "run-codex", harness: "codex", label: "Codex", origin: "managed", state: "running", workspace: "/Projects/guard-dashboard",
    task: "Build the Swarm workspace and connect live agent activity", model: "Configured model", pid: 4102,
    started_at_ms: Date.now() - 240_000, updated_at_ms: Date.now() - 10_000, detail: "Working on the current turn. New instructions run after this turn.",
    activity: "cargo test -p guard-swarm", revision: 1, queued: 0, context_calls: 3, input_tokens: 12480, output_tokens: 1860,
    controls: { message: true, steer: false, interrupt: true, stop: true }, ...overrides };
}

export async function swarmFixture(page: Page, agents?: Agent[]) {
  const state = { offline: false, loseLaunchReply: false, launches: 0, calls: [] as { path: string; body: any }[],
    snapshot: { schema: "guard-swarm-snapshot.v1", epoch: "service-1", observed_at_ms: Date.now(),
      discovery: { state: "ready", limited: false, detail: "Recognized CLI processes visible to your account. Apps may share a process across sessions; private or unsupported agents may be missing." },
      agents: agents ?? [makeAgent(), makeAgent({ id: "run-claude", harness: "claude-code", label: "Claude Code", task: "Review the API contracts and identify edge cases", state: "awaiting_input", pid: null, context_calls: 1,
        activity: "Review complete. Two edge cases need a decision.", controls: { message: true, steer: false, interrupt: false, stop: true } }),
        makeAgent({ id: "process-gemini", harness: "gemini", label: "Gemini CLI", workspace: "/Projects/docs-site", task: null, origin: "observed", state: "observed", model: null,
          activity: null, context_calls: 0, input_tokens: 0, output_tokens: 0, controls: { message: false, steer: false, interrupt: false, stop: false } }),
        makeAgent({ id: "run-review", workspace: "/Projects/docs-site", task: "Check examples against the published API", state: "failed", context_calls: 0,
          activity: "The CLI could not complete this turn.", controls: { message: true, steer: false, interrupt: false, stop: false } })],
      adapters: [{ id: "codex", label: "Codex", installed: true, launch_supported: true, detail: "Tasks and follow-ups" },
        { id: "claude-code", label: "Claude Code", installed: true, launch_supported: true, detail: "Tasks and follow-ups" }],
    } as SwarmSnapshot };
  const ready = JSON.parse(readFileSync(new URL("../src/context-assistance/fixtures/intent-state.json", import.meta.url), "utf8")).native_test.ready_observation;
  const receipts = new Map<string, Agent>();
  await page.route("**/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const body = req.postDataJSON();
    state.calls.push({ path, body });
    let result: unknown = {};
    if (path.startsWith("/v1/swarm") && state.offline) { await route.fulfill({ status: 503, json: { error: "swarm_unavailable" } }); return; }
    if (path === "/v1/swarm") result = { ...state.snapshot, observed_at_ms: Date.now() };
    else if (path === "/v1/swarm/events") result = { events: [
      { sequence: 1, at_ms: Date.now() - 60000, kind: "lifecycle", text: "CLI started." },
      { sequence: 2, at_ms: Date.now() - 40000, kind: "context", text: "CIGAR response reported: get_guard_context" },
      { sequence: 3, at_ms: Date.now() - 10000, kind: "command", text: "cargo test -p guard-swarm" },
      { sequence: 4, at_ms: Date.now() - 3000, kind: "message", text: "The lifecycle checks pass. Now checking the project view on small screens." },
    ] };
    else if (path === "/v1/swarm/launch") {
      let agent = receipts.get(body.request_id);
      if (!agent) { state.launches++; agent = makeAgent({ id: `new-${state.launches}`, harness: body.harness, label: body.harness === "codex" ? "Codex" : "Claude Code", workspace: body.workspace, task: body.task, context_calls: 0 }); receipts.set(body.request_id, agent); state.snapshot.agents.push(agent); }
      if (state.loseLaunchReply) { state.loseLaunchReply = false; await route.abort("failed"); return; }
      result = { agent };
    } else if (path === "/v1/swarm/action") {
      const agent = state.snapshot.agents.find((a) => a.id === body.run_id)!;
      if (!receipts.has(body.request_id)) {
        if (body.action === "message") agent.queued++;
        if (body.action === "stop") { agent.state = "stopped"; agent.controls = { message: false, steer: false, interrupt: false, stop: false }; }
        agent.revision++; receipts.set(body.request_id, { ...agent });
      }
      result = { agent: receipts.get(body.request_id) };
    } else if (path === "/v1/context-assistance") result = ready;
    else if (path === "/v1/context-assistance/workspace") result = { schema: "guard-cigar-workspace-result.v1", data_role: true, result: { scopes: ["codex", "claude-code"].map((app) => ({ scope_id: `scope-${app}`, workspace: "/Projects/guard-dashboard", app, policy_revision: "a".repeat(64), sources: [], retained_contexts: 0, revoked: false })) } };
    else if (path.endsWith("/initialize")) result = { auth_token: "swarm-fixture-session" };
    else if (path === "/v1/runtime") result = freeStateSnapshot;
    else if (path === "/v1/settings") result = defaultSettingsPayload;
    else if (path === "/v1/requests") result = { items: [], next_cursor: null, total_pending_count: 0, total_count: 0, status: "pending" };
    else if (path === "/v1/receipts") result = emptyReceiptsPayload;
    else if (path === "/v1/policy") result = emptyPoliciesPayload;
    else if (path === "/v1/inventory") result = emptyInventoryPayload;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(result) });
  });
  return state;
}

export const swarmUrl = "/swarm?guardDaemon=http://127.0.0.1:4175";
