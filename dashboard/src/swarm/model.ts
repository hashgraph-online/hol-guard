import type { ContextWorkspaceScope } from "../context-assistance/workspaces-api";
import { usesPromptContext } from "../context-assistance/swarm-handoff";
import type { Agent, AgentState } from "./types";

export const UNKNOWN_PROJECT = "@unknown";
export type Project = { id: string; name: string; path: string | null; agents: Agent[] };
export const stateLabel: Record<AgentState, string> = {
  starting: "Starting", running: "Working", observed: "App running", awaiting_input: "Ready for direction",
  needs_attention: "Needs attention", completed: "Completed", failed: "Failed", stopping: "Stopping", stopped: "Stopped", interrupted: "Interrupted",
};
export function isLive(agent: Agent) { return ["starting", "running", "observed", "awaiting_input", "needs_attention", "stopping"].includes(agent.state); }
export function folderName(path: string) { return path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || path; }
export function projectsFor(agents: Agent[]): Project[] {
  const projects = new Map<string, Project>();
  for (const agent of agents) {
    const key = agent.workspace || UNKNOWN_PROJECT;
    if (!projects.has(key)) projects.set(key, { id: key, name: agent.workspace ? folderName(agent.workspace) : "Unassigned", path: agent.workspace, agents: [] });
    projects.get(key)!.agents.push(agent);
  }
  return [...projects.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}
export function filterAgents(agents: Agent[], project: string | null, search: string, attentionOnly: boolean) {
  const query = search.trim().toLocaleLowerCase();
  return agents.filter((agent) => (!project || (agent.workspace || UNKNOWN_PROJECT) === project)
    && (!attentionOnly || ["needs_attention", "failed", "interrupted"].includes(agent.state))
    && (!query || [agent.label, agent.task, agent.workspace, agent.harness].some((s) => s?.toLocaleLowerCase().includes(query))));
}
export function contextFor(agent: Agent, enabled: boolean | null, scopes: ContextWorkspaceScope[] | null) {
  if (enabled === null || (enabled && scopes === null)) return { label: "Context unknown", detail: "CIGAR could not be checked. Refresh or open Context.", available: false };
  if (!enabled) return { label: "CIGAR off", detail: "CIGAR is off. Agents can still work using their own context.", available: false };
  const matches = scopes?.filter((s) => !s.revoked && s.workspace === agent.workspace);
  const scope = matches?.find((s) => s.app === "dashboard") ?? matches?.find((s) => s.app === agent.harness);
  if (!scope) return { label: "Choose project context", detail: "No files have been picked for this project. Connected prompt hooks can still find matching project files automatically. Add the project to choose its files and preview the context.", available: false };
  const connection = usesPromptContext(agent.harness)
    ? "With Guard connected in App setup, new prompts receive project context. A running turn keeps its existing context."
    : "Each MCP connection still needs pairing in CIGAR.";
  return { label: "Project context ready", detail: `${scope.sources.length} approved ${scope.sources.length === 1 ? "source" : "sources"}${scope.sharing?.notes.read ? "; shared notes enabled" : ""}. ${connection} A project grant does not confirm this agent has used it.`, available: true };
}
export function relativeTime(at: number, now = Date.now()) {
  const seconds = Math.max(0, Math.floor((now - at) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}
