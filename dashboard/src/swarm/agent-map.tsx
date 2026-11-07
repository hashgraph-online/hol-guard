import { HiMiniCircleStack, HiMiniCommandLine, HiMiniFolder, HiMiniArrowUpRight } from "react-icons/hi2";
import type { ContextWorkspaceScope } from "../context-assistance/workspaces-api";
import { contextFor, projectsFor, stateLabel } from "./model";
import type { Agent } from "./types";

export type AgentMapProps = { agents: Agent[]; selected: string | null; onSelect: (id: string) => void;
  context: { enabled: boolean | null; scopes: ContextWorkspaceScope[] | null }; mode: "map" | "list" };

export function AgentMap({ agents, selected, onSelect, context, mode }: AgentMapProps) {
  return <div className={`swarm-stage swarm-stage--${mode}`} aria-label={mode === "map" ? "Agent map by project" : "Agent list by project"}>
    {projectsFor(agents).map((project) => <section className="swarm-lane" key={project.id} aria-label={`${project.name} agents`}>
      <div className="swarm-project-anchor"><span className="swarm-project-symbol"><HiMiniFolder aria-hidden="true" /></span>
        <div><h2>{project.name}</h2><p title={project.path ?? undefined}>{project.path ?? "Project not reported"}</p></div>
        <span className="swarm-project-count">{project.agents.length}</span>
      </div>
      <div className="swarm-node-grid">{project.agents.map((agent) => {
        const cigar = contextFor(agent, context.enabled, context.scopes);
        return <button type="button" className={`swarm-node ${selected === agent.id ? "is-selected" : ""}`} key={agent.id}
          aria-pressed={selected === agent.id} aria-label={`${agent.label}: ${agent.task ?? "Observed app"}, ${stateLabel[agent.state]}`}
          aria-describedby={agent.activity ? `swarm-latest-${agent.id}` : undefined}
          onClick={() => onSelect(agent.id)}>
          <div className="swarm-node-top"><span className={`swarm-agent-icon swarm-agent-icon--${agent.harness}`}><HiMiniCommandLine aria-hidden="true" /></span>
            <strong>{agent.label}</strong><span className={`swarm-status swarm-status--${agent.state}`}><i aria-hidden="true" />{stateLabel[agent.state]}</span></div>
          <p className="swarm-task">{agent.task ?? "Work is happening in its app"}</p>
          {agent.activity ? <p id={`swarm-latest-${agent.id}`} className="swarm-latest" title={agent.activity}><HiMiniCommandLine aria-hidden="true" /><span>{agent.activity}</span></p> : null}
          <div className="swarm-node-foot"><span className={cigar.available || agent.context_calls > 0 ? "swarm-context-ready" : ""}><HiMiniCircleStack aria-hidden="true" />{agent.context_calls > 0 ? `${agent.context_calls} CIGAR calls` : cigar.label}</span>
            <span>{agent.origin === "managed" ? "Managed" : "Observed"}<HiMiniArrowUpRight aria-hidden="true" /></span></div>
        </button>;
      })}</div>
    </section>)}
  </div>;
}
