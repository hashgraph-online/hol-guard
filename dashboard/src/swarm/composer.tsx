import { useRef, useState } from "react";
import { HiMiniArrowRight, HiMiniCommandLine, HiMiniFolder, HiMiniXMark } from "react-icons/hi2";
import { GuardModalLayer } from "../guard-modal-layer";
import { launchAgent, RejectedAction } from "./api";
import { isLive, projectsFor } from "./model";
import type { Agent, LaunchDraft, SwarmSnapshot } from "./types";

export function AgentComposer({ snapshot, stale, initialProject, onClose, onLaunched, onNavigate }: {
  snapshot: SwarmSnapshot; stale: boolean; initialProject: string; onClose: () => void;
  onLaunched: (agent: Agent) => void; onNavigate: (path: string) => void;
}) {
  const available = snapshot.adapters.filter((a) => a.installed && a.launch_supported);
  const [harness, setHarness] = useState(available[0]?.id ?? "");
  const [workspace, setWorkspace] = useState(initialProject);
  const [task, setTask] = useState("");
  const [model, setModel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const pending = useRef<LaunchDraft | null>(null);
  const peers = snapshot.agents.filter((a) => a.workspace === workspace && isLive(a));
  async function launch() {
    if (busy || stale) return;
    const draft = pending.current ?? { request_id: crypto.randomUUID(), epoch: snapshot.epoch, harness, workspace: workspace.trim(), task, model: model.trim() || null };
    pending.current = draft;
    setBusy(true); setError(null);
    try { onLaunched(await launchAgent(draft)); }
    catch (e) {
      if (e instanceof RejectedAction) { pending.current = null; setUncertain(false); }
      else setUncertain(true);
      setError(e instanceof Error ? e.message : "Launch could not be confirmed.");
    } finally { setBusy(false); }
  }
  return <GuardModalLayer ariaLabel="Start a new agent" onClose={() => { if (!busy) onClose(); }} panelClassName="swarm-composer">
    <div className="swarm-composer-heading"><div><span className="swarm-eyebrow">GIVE WORK A PLACE TO START</span><h2>New agent</h2></div><button type="button" className="swarm-icon-button" aria-label="Close new agent" disabled={busy} onClick={onClose}><HiMiniXMark /></button></div>
    {available.length === 0 ? <div className="swarm-composer-empty"><HiMiniCommandLine aria-hidden="true" /><h3>Connect a CLI to get started</h3><p>Swarm can launch Codex and Claude Code. Install and sign in to one of them, then restart Guard so it can find the CLI.</p><button className="swarm-button swarm-button--primary" onClick={() => onNavigate("/protect")} type="button">Open app setup <HiMiniArrowRight /></button></div> : <form onSubmit={(e) => { e.preventDefault(); void launch(); }}>
      <fieldset disabled={busy || uncertain}>
        <legend className="sr-only">Agent configuration</legend>
        <label htmlFor="swarm-harness">Agent</label><div className="swarm-harness-choices" role="group" aria-label="Choose an agent">{available.map((a) => <button key={a.id} id={a.id === available[0].id ? "swarm-harness" : undefined} type="button" aria-pressed={harness === a.id} className={harness === a.id ? "is-selected" : ""} onClick={() => setHarness(a.id)}><HiMiniCommandLine aria-hidden="true" /><strong>{a.label}</strong><span>Installed</span></button>)}</div>
        <label htmlFor="swarm-project">Project directory</label><div className="swarm-input-icon"><HiMiniFolder aria-hidden="true" /><input id="swarm-project" value={workspace} onChange={(e) => setWorkspace(e.target.value)} placeholder="/path/to/your/project" maxLength={4096} list="swarm-known-projects" required autoComplete="off" /></div>
        <datalist id="swarm-known-projects">{projectsFor(snapshot.agents).filter((p) => p.path).map((p) => <option key={p.id} value={p.path!} />)}</datalist>
        {peers.length ? <p className="swarm-project-note">{peers.length} {peers.length === 1 ? "agent is" : "agents are"} already working here. Use a separate worktree if tasks may edit the same files.</p> : <p className="swarm-field-help">Use an existing project or worktree you trust. Its CLI settings and hooks will load.</p>}
        <label htmlFor="swarm-task">What should it do?</label><textarea id="swarm-task" rows={5} value={task} onChange={(e) => setTask(e.target.value)} maxLength={16384} required placeholder="Describe the outcome, relevant files, and what success looks like…" />
        <label htmlFor="swarm-model">Model <span className="swarm-optional">Optional</span></label><input id="swarm-model" value={model} onChange={(e) => setModel(e.target.value)} maxLength={128} placeholder="Use the CLI’s configured model" autoComplete="off" />
      </fieldset>
      <div className="swarm-launch-summary"><HiMiniCommandLine aria-hidden="true" /><p>Runs locally with your existing CLI account, hooks, and permissions. Provider usage may apply. CIGAR still requires its own context access and connection pairing.</p></div>
      {error ? <p className="swarm-error" role="alert">{error}</p> : null}
      {uncertain ? <p className="swarm-muted">The launch may have succeeded. Check its status with the same request before creating another agent.</p> : null}
      {stale ? <p className="swarm-error">Reconnect to Guard before launching.</p> : null}
      <div className="swarm-composer-footer"><button type="button" className="swarm-text-button" onClick={onClose} disabled={busy}>Cancel</button><button type="submit" className="swarm-button swarm-button--primary" disabled={busy || stale || !harness || !workspace.trim() || !task.trim()}>{busy ? "Starting…" : uncertain ? "Check launch" : "Start agent"}<HiMiniArrowRight aria-hidden="true" /></button></div>
    </form>}
  </GuardModalLayer>;
}
