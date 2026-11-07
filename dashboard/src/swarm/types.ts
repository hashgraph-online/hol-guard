export const AGENT_STATES = ["starting", "running", "observed", "awaiting_input", "needs_attention", "completed", "failed", "stopping", "stopped", "interrupted"] as const;
export type AgentState = typeof AGENT_STATES[number];
export type Agent = {
  id: string; harness: string; label: string; origin: "managed" | "observed"; state: AgentState;
  workspace: string | null; task: string | null; model: string | null; pid: number | null;
  started_at_ms: number; updated_at_ms: number; detail: string;
  activity: string | null;
  revision: number; queued: number; context_calls: number; input_tokens: number; output_tokens: number;
  controls: { message: boolean; steer: boolean; interrupt: boolean; stop: boolean };
};
export type Adapter = { id: string; label: string; installed: boolean; launch_supported: boolean; detail: string };
export type SwarmSnapshot = {
  schema: "guard-swarm-snapshot.v1"; epoch: string; observed_at_ms: number;
  discovery: { state: "ready" | "unavailable"; limited: boolean; detail: string };
  agents: Agent[]; adapters: Adapter[];
};
export type SwarmEvent = { sequence: number; at_ms: number; kind: string; text: string };
export type LaunchDraft = { request_id: string; epoch: string; harness: string; workspace: string; task: string; model: string | null };
export type AgentAction = "message" | "interrupt" | "stop";
