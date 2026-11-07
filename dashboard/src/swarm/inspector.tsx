import { useEffect, useRef, useState } from "react";
import { HiMiniArrowUp, HiMiniCircleStack, HiMiniCommandLine, HiMiniXMark } from "react-icons/hi2";
import type { ContextWorkspaceScope } from "../context-assistance/workspaces-api";
import type { GuardApprovalRequest } from "../guard-types";
import { directAgent, RejectedAction } from "./api";
import { Activity } from "./activity";
import { contextFor, stateLabel } from "./model";
import type { Agent, AgentAction } from "./types";

type Props = { agent: Agent; epoch: string; stale: boolean; onClose: () => void; onRefresh: () => void; onNavigate: (path: string) => void;
  reviews: GuardApprovalRequest[]; onOpenRequest: (id: string) => void;
  context: { enabled: boolean | null; scopes: ContextWorkspaceScope[] | null } };

export function AgentInspector({ agent, epoch, stale, onClose, onRefresh, onNavigate, context, reviews, onOpenRequest }: Props) {
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmStop, setConfirmStop] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState("Activity");
  const panel = useRef<HTMLElement>(null);
  const alive = useRef(true);
  const pending = useRef<{ agent: Agent; epoch: string; action: AgentAction; text: string | null; id: string } | null>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    if (window.matchMedia("(max-width: 1050px)").matches) panel.current?.scrollIntoView({ block: "start", behavior: "instant" });
  }, []);
  useEffect(() => { setDraft(""); setNotice(null); setError(null); setConfirmStop(false); }, [agent.id]);
  const cigar = contextFor(agent, context.enabled, context.scopes);
  async function act(action: AgentAction) {
    if (busy || stale) return;
    setBusy(true); setError(null); setNotice(null);
    const request = pending.current ?? { agent, epoch, action, text: action === "message" ? draft : null, id: crypto.randomUUID() };
    pending.current = request;
    try {
      await directAgent(request.agent, request.epoch, request.action, request.text, request.id);
      if (!alive.current) return;
      pending.current = null;
      if (action === "message") setDraft("");
      setNotice(action === "stop" ? "Stop requested. Waiting for the process to exit." : action === "interrupt" ? "Interruption requested." : "Instruction accepted by the agent service.");
      setConfirmStop(false); onRefresh();
    } catch (e) { if (alive.current) { if (e instanceof RejectedAction) pending.current = null; setError(e instanceof Error ? e.message : "The action could not be confirmed."); onRefresh(); } }
    finally { if (alive.current) setBusy(false); }
  }
  return <aside ref={panel} className="swarm-inspector" aria-label="Agent details">
    <div className="swarm-inspector-heading"><span>AGENT DETAILS</span><button className="swarm-icon-button" type="button" onClick={onClose} aria-label="Close agent details"><HiMiniXMark /></button></div>
    <div className="swarm-inspector-identity"><span className="swarm-agent-icon"><HiMiniCommandLine aria-hidden="true" /></span><div><h2>{agent.label}</h2><span className={`swarm-status swarm-status--${agent.state}`}><i aria-hidden="true" />{stateLabel[agent.state]}</span></div></div>
    <p className="swarm-inspector-task">{agent.task ?? (agent.origin === "observed" ? "This agent was started outside Swarm." : "Previous managed session")}</p>
    <p className="swarm-muted">{agent.detail}</p>
    <div className="swarm-detail-tabs" role="tablist" aria-label="Agent information" onKeyDown={(e) => {
      const names = ["Activity", "Context", "Details"];
      const index = names.indexOf(tab);
      const next = e.key === "ArrowRight" ? (index + 1) % 3 : e.key === "ArrowLeft" ? (index + 2) % 3 : e.key === "Home" ? 0 : e.key === "End" ? 2 : -1;
      if (next >= 0) { e.preventDefault(); setTab(names[next]); e.currentTarget.querySelectorAll<HTMLButtonElement>("button")[next]?.focus(); }
    }}>{["Activity", "Context", "Details"].map((name) => <button key={name} id={`swarm-tab-${name}`} aria-controls={`swarm-panel-${name}`} type="button" role="tab" aria-selected={tab === name} tabIndex={tab === name ? 0 : -1} onClick={() => setTab(name)}>{name}{name === "Context" && agent.context_calls > 0 ? <span>{agent.context_calls}</span> : null}</button>)}</div>
    <div role="tabpanel" id="swarm-panel-Details" aria-labelledby="swarm-tab-Details" hidden={tab !== "Details"}>
    <dl className="swarm-facts"><div><dt>Project</dt><dd>{agent.workspace ?? "Not reported"}</dd></div>
      <div><dt>Control</dt><dd>{agent.origin === "managed" ? "Managed by Swarm" : "In its own app"}</dd></div>
      {agent.model ? <div><dt>Model</dt><dd>{agent.model}</dd></div> : null}
      {agent.pid ? <div><dt>Process</dt><dd>{agent.pid}</dd></div> : null}</dl>
    </div>
    <div role="tabpanel" id="swarm-panel-Activity" aria-labelledby="swarm-tab-Activity" hidden={tab !== "Activity"}>
    {reviews.length ? <section className="swarm-reviews"><h3>{reviews.length} project {reviews.length === 1 ? "review" : "reviews"}</h3><p>Pending Guard actions for this project and app. They may belong to another agent.</p>{reviews.slice(0, 3).map((review) => <button type="button" key={review.request_id} onClick={() => onOpenRequest(review.request_id)}>{review.artifact_name || "Review action"} <span aria-hidden="true">↗</span></button>)}</section> : null}
    <Activity key={agent.id} agent={agent} stale={stale} />
    </div>
    <div role="tabpanel" id="swarm-panel-Context" aria-labelledby="swarm-tab-Context" hidden={tab !== "Context"}>
    <section className="swarm-context-panel"><h3><HiMiniCircleStack aria-hidden="true" />{cigar.label}</h3><p>{cigar.detail}</p>
      {agent.context_calls > 0 ? <p className="swarm-context-count">{agent.context_calls} completed context {agent.context_calls === 1 ? "call" : "calls"} reported by this CLI.</p> : <p>Context use has not been reported for this agent. Hook-injected context is not counted here.</p>}
      <button className="swarm-text-button" type="button" onClick={() => onNavigate("/cigar?section=access")}>Manage context access <span aria-hidden="true">↗</span></button></section>
    {agent.input_tokens + agent.output_tokens > 0 ? <><dl className="swarm-token-facts"><div><dt>Input tokens</dt><dd>{agent.input_tokens.toLocaleString()}</dd></div><div><dt>Output tokens</dt><dd>{agent.output_tokens.toLocaleString()}</dd></div></dl><p className="swarm-muted">Reported by the CLI for completed turns. These are model tokens, not CIGAR savings.</p></> : null}
    </div>
    {agent.controls.message ? <form className="swarm-direct" onSubmit={(e) => { e.preventDefault(); void act("message"); }}>
      <label htmlFor="swarm-direction">Next instruction</label>
      <textarea id="swarm-direction" value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={16384} rows={3} placeholder="What should it focus on?" disabled={stale || busy || pending.current !== null} />
      <p className="swarm-field-help">{agent.state === "running" || agent.state === "starting" ? "Queued after the current turn. Interrupt first to change focus now." : "Continues this agent’s conversation in the same project."}{agent.queued ? ` ${agent.queued} queued.` : ""}</p>
      <button className="swarm-button swarm-button--primary" disabled={!draft.trim() || stale || busy || (pending.current !== null && pending.current.action !== "message")} type="submit"><HiMiniArrowUp aria-hidden="true" />{busy ? "Sending…" : pending.current ? "Check instruction" : "Send instruction"}</button>
    </form> : agent.origin === "observed" ? <p className="swarm-handoff">Continue in your {agent.label} window to send instructions. Swarm has observation access to this process.</p> : null}
    {error ? <p className="swarm-error" role="alert">{error}</p> : null}
    {notice ? <p className="swarm-muted" role="status">{notice}</p> : null}
    <div className="swarm-inspector-actions">
      {agent.controls.interrupt ? <button className="swarm-button" type="button" disabled={stale || busy || pending.current !== null} onClick={() => void act("interrupt")}>Interrupt turn</button> : null}
      {agent.controls.stop ? <button className="swarm-button swarm-button--danger" type="button" disabled={stale || busy || pending.current !== null} onClick={() => setConfirmStop(true)}>Stop agent</button> : null}
      {agent.origin === "observed" ? <button className="swarm-button" type="button" onClick={() => onNavigate(`/apps/${encodeURIComponent(agent.harness)}`)}>App setup</button> : null}
    </div>
    {pending.current && !busy ? <button className="swarm-text-button" disabled={stale} type="button" onClick={() => void act(pending.current!.action)}>Check unconfirmed action</button> : null}
    {confirmStop ? <div className="swarm-stop-confirm" role="group" aria-label="Confirm stop"><p>Stop this agent and the work it is running? Changes already made to files will remain.</p><button className="swarm-button swarm-button--danger" disabled={stale || busy} type="button" onClick={() => void act("stop")}>Stop this agent</button><button className="swarm-text-button" type="button" disabled={busy} onClick={() => setConfirmStop(false)}>Keep working</button></div> : null}
  </aside>;
}
