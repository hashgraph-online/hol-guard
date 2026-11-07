import { useEffect, useMemo, useRef, useState } from "react";
import { HiMiniArrowPath, HiMiniCircleStack, HiMiniFolder, HiMiniListBullet, HiMiniMagnifyingGlass, HiMiniPlus, HiMiniSquares2X2, HiMiniComputerDesktop, HiMiniCommandLine } from "react-icons/hi2";
import type { GuardApprovalRequest } from "../guard-types";
import { AgentMap } from "./agent-map";
import { AgentComposer } from "./composer";
import { AgentInspector } from "./inspector";
import { filterAgents, isLive, projectsFor, UNKNOWN_PROJECT } from "./model";
import { useSwarm } from "./use-swarm";
import "./swarm.css";

type Props = { onNavigate: (path: string) => void; reviews?: GuardApprovalRequest[] | null; onOpenRequest: (id: string) => void };

export function SwarmWorkspace({ onNavigate, reviews = null, onOpenRequest }: Props) {
  const { snapshot, loading, error, stale, context, refresh, acceptAgent } = useSwarm();
  const [selected, setSelected] = useState<string | null>(null);
  const [project, setProject] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [attention, setAttention] = useState(false);
  const [mode, setMode] = useState<"map" | "list">("map");
  const [composing, setComposing] = useState(false);
  const stageRef = useRef<HTMLDivElement>(null);
  const previousEpoch = useRef<string | null>(null);
  const [restarted, setRestarted] = useState(false);
  const agents = snapshot?.agents ?? [];
  const projects = useMemo(() => projectsFor(agents), [agents]);
  const visible = useMemo(() => filterAgents(agents, project, search, attention), [agents, project, search, attention]);
  const active = agents.filter(isLive).length;
  const needsAttention = agents.filter((a) => ["needs_attention", "failed", "interrupted"].includes(a.state)).length;
  const chosen = agents.find((a) => a.id === selected);
  const chosenReviews = chosen?.workspace ? (reviews ?? []).filter((r) => r.workspace === chosen.workspace && r.harness === chosen.harness && r.status === "pending") : [];
  useEffect(() => {
    if (snapshot && previousEpoch.current && previousEpoch.current !== snapshot.epoch) { setRestarted(true); setSelected(null); }
    if (snapshot) previousEpoch.current = snapshot.epoch;
  }, [snapshot?.epoch]);
  function closeDetails() {
    const button = stageRef.current?.querySelector<HTMLButtonElement>("button[aria-pressed=true]");
    setSelected(null); button?.focus();
  }
  return <div className="swarm-workspace">
    <header className="swarm-header"><div><div className="swarm-eyebrow"><span className="swarm-mark" aria-hidden="true"><i /><i /><i /></span>LOCAL AGENT WORKSPACE</div><h1>Swarm<span className="swarm-heading-dot">.</span></h1><p>One place to follow the work. Every agent, every project.</p></div>
      <div className="swarm-header-actions"><span className={`swarm-connection ${stale ? "is-stale" : ""}`}><i aria-hidden="true" />{stale ? "Reconnecting" : loading ? "Connecting" : "Live on this computer"}</span><button type="button" className="swarm-button swarm-button--primary" disabled={!snapshot || stale} onClick={() => setComposing(true)}><HiMiniPlus aria-hidden="true" />New agent</button></div>
    </header>
    <div className="swarm-overview"><div className="swarm-stat"><HiMiniCommandLine aria-hidden="true" /><strong>{snapshot ? active : "—"}</strong><span>Active agents</span></div>
      <button type="button" className={`swarm-stat ${attention ? "is-selected" : ""}`} aria-pressed={attention} onClick={() => setAttention(!attention)}><span className="swarm-attention-symbol" aria-hidden="true">!</span><strong>{snapshot ? needsAttention : "—"}</strong><span>Need attention</span></button>
      <div className="swarm-stat"><HiMiniFolder aria-hidden="true" /><strong>{snapshot ? projects.filter((p) => p.path && p.agents.some(isLive)).length : "—"}</strong><span>Active projects</span></div>
      <button type="button" className="swarm-context-summary" onClick={() => onNavigate("/cigar")}><HiMiniCircleStack aria-hidden="true" /><span><strong>CIGAR context</strong><small>{context.enabled === null ? "Checking availability" : context.enabled ? "Runtime enabled · access by project" : "Off · set up shared context"}</small></span><span aria-hidden="true">↗</span></button>
    </div>
    {error ? <div className="swarm-banner swarm-banner--error" role="status"><span>{error}{snapshot ? " Showing the last confirmed agents." : ""}</span><button type="button" onClick={refresh}>Reconnect</button></div> : null}
    {restarted ? <div className="swarm-banner" role="status"><span>Guard restarted. Previous tasks have not been relaunched. Check each agent before sending new work.</span><button type="button" onClick={() => setRestarted(false)}>Dismiss</button></div> : null}
    <div className={`swarm-body ${chosen ? "has-inspector" : ""}`}>
      <nav className="swarm-project-rail" aria-label="Swarm projects"><div className="swarm-rail-heading">PROJECTS<span>{projects.length}</span></div><button type="button" className={!project ? "is-selected" : ""} aria-pressed={!project} onClick={() => setProject(null)}><HiMiniSquares2X2 aria-hidden="true" /><span>All projects</span><b>{agents.length}</b></button>
        {projects.map((p) => <button type="button" key={p.id} className={project === p.id ? "is-selected" : ""} aria-pressed={project === p.id} onClick={() => setProject(p.id)} title={p.path ?? "Project not reported"}><HiMiniFolder aria-hidden="true" /><span>{p.name}</span><b>{p.agents.length}</b></button>)}
        <div className="swarm-rail-note"><HiMiniComputerDesktop aria-hidden="true" /><strong>Your computer</strong><p>CLI processes visible to your account. Agents started here include task output and controls.</p><button type="button" className="swarm-text-button" onClick={() => onNavigate("/protect")}>Manage apps ↗</button></div>
      </nav>
      <section className="swarm-canvas" aria-label="Swarm agents"><div className="swarm-toolbar"><label className="swarm-search"><HiMiniMagnifyingGlass aria-hidden="true" /><input aria-label="Search agents and projects" placeholder="Find an agent or task…" value={search} onChange={(e) => setSearch(e.target.value)} /></label>
        <div className="swarm-view-toggle" role="group" aria-label="Agent view"><button type="button" aria-pressed={mode === "map"} onClick={() => setMode("map")} aria-label="Map view"><HiMiniSquares2X2 aria-hidden="true" /><span>Map</span></button><button type="button" aria-pressed={mode === "list"} onClick={() => setMode("list")} aria-label="List view"><HiMiniListBullet aria-hidden="true" /><span>List</span></button></div><button type="button" className="swarm-icon-button" onClick={refresh} aria-label="Refresh agents"><HiMiniArrowPath /></button>
      </div>
      {attention ? <div className="swarm-filter-note">Showing agents that need attention<button type="button" onClick={() => setAttention(false)}>Show all</button></div> : null}
      <div ref={stageRef}>
        {loading && !snapshot ? <div className="swarm-empty" role="status"><div className="swarm-empty-icon"><HiMiniArrowPath aria-hidden="true" /></div><h2>Finding your agents</h2><p>Checking recognized CLIs on this computer…</p></div> : visible.length ? <AgentMap agents={visible} selected={selected} onSelect={setSelected} context={context} mode={mode} /> : <div className="swarm-empty"><div className="swarm-empty-icon"><HiMiniCommandLine aria-hidden="true" /></div><span className="swarm-eyebrow">ROOM FOR YOUR NEXT IDEA</span><h2>{!snapshot ? "Connect to your local Guard" : agents.length ? "No agents in this view" : "Your next project starts here"}</h2><p>{!snapshot ? "Swarm needs the local agent service to show what is running." : agents.length ? "Try another project or clear your search and attention filter." : "Give an agent a task, follow its progress, and bring in more agents when the work grows."}</p>{snapshot ? agents.length ? <button type="button" className="swarm-button" onClick={() => { setSearch(""); setProject(null); setAttention(false); }}>Clear filters</button> : <button type="button" className="swarm-button swarm-button--primary" disabled={stale} onClick={() => setComposing(true)}><HiMiniPlus />Start your first agent</button> : <button type="button" className="swarm-button" onClick={refresh}>Reconnect</button>}</div>}
      </div>
      {snapshot ? <footer className="swarm-coverage"><span><i aria-hidden="true" />{snapshot.discovery.detail}{snapshot.discovery.limited ? " Discovery is limited to the first 256 processes." : ""}</span><span>{visible.length} shown</span></footer> : null}
      </section>
      {chosen && snapshot ? <AgentInspector key={`${snapshot.epoch}:${chosen.id}`} agent={chosen} epoch={snapshot.epoch} stale={stale} onClose={closeDetails} onRefresh={refresh} onNavigate={onNavigate} context={context} reviews={chosenReviews} onOpenRequest={onOpenRequest} /> : null}
    </div>
    <div className="swarm-bottom-note"><span>Managed agents accept instructions here. Observed agents stay in their own apps.</span><button className="swarm-text-button" type="button" onClick={() => onNavigate("/inbox")}>{reviews === null ? "Open Guard reviews" : `${reviews.length} Guard reviews`} ↗</button></div>
    {composing && snapshot ? <AgentComposer snapshot={snapshot} stale={stale} initialProject={project && project !== UNKNOWN_PROJECT ? project : ""} onClose={() => setComposing(false)} onNavigate={onNavigate} onLaunched={(agent) => { acceptAgent(agent); setSelected(agent.id); setComposing(false); setProject(null); setSearch(""); setAttention(false); refresh(); }} /> : null}
  </div>;
}
