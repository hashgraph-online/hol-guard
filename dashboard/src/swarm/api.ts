import { fetchWithGuardAuth } from "../guard-api";
import { AGENT_STATES, type Agent, type AgentAction, type LaunchDraft, type SwarmEvent, type SwarmSnapshot } from "./types";

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max = 4096): v is string => typeof v === "string" && v.length <= max;
const optionalText = (v: unknown) => v === null || text(v, 16_384);
const count = (v: unknown) => Number.isSafeInteger(v) && (v as number) >= 0;
const failure = () => new Error("Guard returned agent information this version of Swarm cannot read. Update Guard and try again.");

export function parseAgent(value: unknown): Agent {
  if (!object(value) || !text(value.id, 128) || !value.id || !text(value.harness, 128) || !text(value.label, 160)
    || !["managed", "observed"].includes(String(value.origin)) || !AGENT_STATES.includes(value.state as Agent["state"])
    || !optionalText(value.workspace) || !optionalText(value.task) || !optionalText(value.model) || !optionalText(value.activity)
    || !(value.pid === null || count(value.pid)) || !count(value.started_at_ms) || !count(value.updated_at_ms)
    || !text(value.detail) || !object(value.controls) || ![value.revision, value.queued, value.context_calls, value.input_tokens, value.output_tokens].every(count)
    || !["message", "steer", "interrupt", "stop"].every((key) => typeof (value.controls as Record<string, unknown>)[key] === "boolean")) throw failure();
  if (value.origin === "observed" && Object.values(value.controls).some(Boolean)) throw failure();
  return value as Agent;
}

export function parseSnapshot(body: unknown): SwarmSnapshot {
  if (!object(body) || body.schema !== "guard-swarm-snapshot.v1" || !text(body.epoch, 128) || !body.epoch || !count(body.observed_at_ms)
    || !object(body.discovery) || !["ready", "unavailable"].includes(String(body.discovery.state))
    || typeof body.discovery.limited !== "boolean" || !text(body.discovery.detail)
    || !Array.isArray(body.agents) || body.agents.length > 320 || !Array.isArray(body.adapters) || body.adapters.length > 64
    || !body.adapters.every((a) => object(a) && text(a.id, 128) && text(a.label, 160) && typeof a.installed === "boolean"
      && typeof a.launch_supported === "boolean" && text(a.detail))) throw failure();
  const agents = body.agents.map(parseAgent);
  if (new Set(agents.map((a) => a.id)).size !== agents.length) throw failure();
  return { ...body, agents } as SwarmSnapshot;
}

async function request(path: string, init: RequestInit, signal?: AbortSignal): Promise<unknown> {
  const timeout = AbortSignal.timeout(10_000);
  const response = await fetchWithGuardAuth(path, { ...init, cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new Error("Open Swarm from your local Guard dashboard to manage agents.");
    if (response.status === 409) throw new RejectedAction("The agent or service changed. Refresh its status before trying again.");
    const known: Record<string, string> = {
      swarm_cli_missing: "This CLI is not available to Guard. Install it and restart Guard to refresh its PATH.",
      swarm_workspace_invalid: "Choose an existing project directory using its full path.",
      swarm_run_limit: "Swarm has 16 active runs. Stop or finish one before launching another.",
      swarm_request_limit: "This Swarm service has reached its action limit. Finish active work before restarting Guard.",
      swarm_unknown_run: "This managed session is no longer available. Refresh Swarm.",
      swarm_action_unavailable: "This action is no longer available for the agent. Refresh its status.",
      swarm_launch_invalid: "Check the project, task, and model. One of the launch fields is invalid.",
      swarm_action_invalid: "The instruction is invalid or too large. Shorten it and try again.",
    };
    if (response.status === 400 && object(body) && typeof body.error === "string" && known[body.error]) throw new RejectedAction(known[body.error]);
    if (response.status === 404) throw new Error("Swarm needs a newer native Guard runtime. Update Guard, then reconnect.");
    throw new Error(init.method === "GET" ? "Swarm could not reach the local agent service. Your agents may still be working." :
      "Guard could not confirm this action. Refresh the agent before trying again.");
  }
  return body;
}

export class RejectedAction extends Error {}

export async function readSwarm(signal?: AbortSignal) {
  return parseSnapshot(await request("/v1/swarm", { method: "GET" }, signal));
}
export async function launchAgent(draft: LaunchDraft, signal?: AbortSignal) {
  const body = await request("/v1/swarm/launch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(draft) }, signal);
  if (!object(body)) throw failure();
  return parseAgent(body.agent);
}
export async function directAgent(agent: Agent, epoch: string, action: AgentAction, text: string | null, requestId: string, signal?: AbortSignal) {
  const body = await request("/v1/swarm/action", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: agent.id, epoch, expected_revision: agent.revision, action, text, request_id: requestId }) }, signal);
  if (!object(body)) throw failure();
  return parseAgent(body.agent);
}

export async function readEvents(id: string, signal?: AbortSignal): Promise<SwarmEvent[]> {
  const body = await request("/v1/swarm/events", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ run_id: id }) }, signal);
  if (!object(body) || !Array.isArray(body.events) || body.events.length > 200
    || !body.events.every((e) => object(e) && count(e.sequence) && count(e.at_ms) && text(e.kind, 128) && text(e.text, 16384))) throw failure();
  return body.events as SwarmEvent[];
}
