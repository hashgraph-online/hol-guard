import { useRef, useState } from "react";
import { HiMiniArrowRight, HiMiniCommandLine, HiMiniFolder, HiMiniLockClosed, HiMiniXMark } from "react-icons/hi2";
import { GuardModalLayer } from "../guard-modal-layer";
import { launchAgent, RejectedAction } from "./api";
import { isLive, projectsFor } from "./model";
import type { Agent, LaunchDraft, SwarmSnapshot } from "./types";
import { blockedPaths, goalOf, MAX_BLOCKED, parseCommand, workText, type WorkDefinition } from "./work";

const pendingLaunches = new Map<string, LaunchDraft>();
/** The form behind each pending launch, so a reopened composer shows the fields, not the built prompt. */
const pendingForms = new Map<string, WorkDefinition & { blockedText: string; secrets: boolean }>();
const COMMANDS: Record<string, string> = { codex: "codex", "claude-code": "claude" };
const MAX_TASK_BYTES = 16384;

export function AgentComposer({ snapshot, stale, initialProject, onClose, onLaunched, onNavigate }: {
  snapshot: SwarmSnapshot; stale: boolean; initialProject: string; onClose: () => void;
  onLaunched: (agent: Agent) => void; onNavigate: (path: string) => void;
}) {
  const available = snapshot.adapters.filter((a) => a.installed && a.launch_supported);
  const retained = [...pendingLaunches.values()].find((draft) => draft.epoch === snapshot.epoch
    && (!initialProject || draft.workspace === initialProject));
  const firstHarness = retained?.harness ?? available[0]?.id ?? "";
  const [command, setCommand] = useState(() => {
    const program = COMMANDS[firstHarness] ?? "";
    return retained?.model ? `${program} --model ${retained.model}` : program;
  });
  const [workspace, setWorkspace] = useState(retained?.workspace ?? initialProject);
  const form = retained ? pendingForms.get(retained.request_id) : undefined;
  const [goal, setGoal] = useState(form?.goal ?? goalOf(retained?.task ?? null) ?? "");
  const [scope, setScope] = useState(form?.scope ?? "");
  const [done, setDone] = useState(form?.done ?? "");
  const [avoid, setAvoid] = useState(form?.avoid ?? "");
  const [blockedText, setBlockedText] = useState(form?.blockedText ?? retained?.blocked?.join("\n") ?? "");
  const [secrets, setSecrets] = useState(form?.secrets ?? !retained);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uncertain, setUncertain] = useState(retained !== undefined);
  const pending = useRef<LaunchDraft | null>(retained ?? null);
  const peers = snapshot.agents.filter((a) => a.workspace === workspace && isLive(a));
  const parsed = parseCommand(command, available.map((a) => a.id));
  const harness = "harness" in parsed ? parsed.harness : "";
  const limits = harness === "claude-code" ? blockedPaths(blockedText, secrets) : { paths: [], bad: [] };
  let limitError: string | null = null;
  if (limits.bad.length) limitError = `These paths are not inside the project: ${limits.bad.join(", ")}`;
  else if (limits.paths.length > MAX_BLOCKED) limitError = `List at most ${MAX_BLOCKED} paths.`;
  else if (limits.paths.length && /[()*?[\]{}]/.test(workspace)) limitError = "The project folder's name has brackets or wildcards, so Claude Code can't be kept out of paths in it. Use a folder without them, or clear the list.";
  const task = workText({ goal, scope, done, avoid }, limits.paths);
  const extraBytes = new TextEncoder().encode(task).length - MAX_TASK_BYTES;
  const sizeError = extraBytes > 0 ? `The work and paths are too long together. Shorten them by ${extraBytes} characters or more.` : null;
  let launchLabel = "Start agent";
  if (busy) launchLabel = "Starting…";
  else if (uncertain) launchLabel = "Check launch";
  async function launch() {
    if (busy || stale || "error" in parsed || limitError || sizeError) return;
    const fresh: LaunchDraft = { request_id: crypto.randomUUID(), epoch: snapshot.epoch, harness: parsed.harness, workspace: workspace.trim(),
      task, model: parsed.model };
    if (limits.paths.length) fresh.blocked = limits.paths;
    const draft = pending.current ?? fresh;
    pending.current = draft;
    pendingLaunches.set(draft.request_id, draft);
    if (!pendingForms.has(draft.request_id)) pendingForms.set(draft.request_id, { goal, scope, done, avoid, blockedText, secrets });
    setBusy(true); setError(null);
    const forget = () => { pendingLaunches.delete(draft.request_id); pendingForms.delete(draft.request_id); };
    try { const agent = await launchAgent(draft); forget(); onLaunched(agent); }
    catch (e) {
      if (e instanceof RejectedAction) { pending.current = null; forget(); setUncertain(false); }
      else setUncertain(true);
      setError(e instanceof Error ? e.message : "Launch could not be confirmed.");
    } finally { setBusy(false); }
  }
  return <GuardModalLayer ariaLabel="Start a new agent" onClose={() => { if (!busy) onClose(); }} panelClassName="swarm-composer">
    <div className="swarm-composer-heading"><div><span className="swarm-eyebrow">GIVE WORK A PLACE TO START</span><h2>New agent</h2></div><button type="button" className="swarm-icon-button" aria-label="Close new agent" disabled={busy} onClick={onClose}><HiMiniXMark /></button></div>
    {available.length === 0 ? <div className="swarm-composer-empty"><HiMiniCommandLine aria-hidden="true" /><h3>Connect a CLI to get started</h3><p>Swarm can launch Codex and Claude Code. Install and sign in to one of them, then restart Guard so it can find the CLI.</p><button className="swarm-button swarm-button--primary" onClick={() => onNavigate("/protect")} type="button">Open app setup <HiMiniArrowRight /></button></div> : <form onSubmit={(e) => { e.preventDefault(); void launch(); }}>
      <fieldset disabled={busy || uncertain}>
        <legend className="sr-only">Agent configuration</legend>
        <label htmlFor="swarm-command">Command</label>
        <div className="swarm-input-icon swarm-command"><HiMiniCommandLine aria-hidden="true" /><input id="swarm-command" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="codex" maxLength={256} required autoComplete="off" spellCheck={false} aria-describedby="swarm-command-help" /></div>
        <div className="swarm-command-picks" role="group" aria-label="Installed CLIs">{available.map((a) => <button key={a.id} type="button" aria-pressed={harness === a.id} className={harness === a.id ? "is-selected" : ""} onClick={() => setCommand(COMMANDS[a.id] ?? a.id)}>{COMMANDS[a.id] ?? a.id}</button>)}</div>
        <p id="swarm-command-help" className={"error" in parsed && command.trim() ? "swarm-error" : "swarm-field-help"}>{"error" in parsed && command.trim() ? parsed.error : "Runs in the background in the project folder, then shows up on the map. Add --model to pick a model."}</p>
        <label htmlFor="swarm-project">Project directory</label><div className="swarm-input-icon"><HiMiniFolder aria-hidden="true" /><input id="swarm-project" value={workspace} onChange={(e) => setWorkspace(e.target.value)} placeholder="/path/to/your/project" maxLength={4096} list="swarm-known-projects" required autoComplete="off" /></div>
        <datalist id="swarm-known-projects">{projectsFor(snapshot.agents).filter((p) => p.path).map((p) => <option key={p.id} value={p.path!} />)}</datalist>
        {peers.length ? <p className="swarm-project-note">{peers.length} {peers.length === 1 ? "agent is" : "agents are"} already working here. Use a separate worktree if tasks may edit the same files.</p> : <p className="swarm-field-help">Use an existing project or worktree you trust. Its CLI settings and hooks will load.</p>}
      </fieldset>
      <fieldset className="swarm-composer-section" disabled={busy || uncertain}>
        <legend>Work for this agent</legend>
        <label htmlFor="swarm-task">Goal</label><textarea id="swarm-task" rows={3} value={goal} onChange={(e) => setGoal(e.target.value)} maxLength={8192} required placeholder="Fix the login timeout on slow networks" />
        <label htmlFor="swarm-scope">Files in scope <span className="swarm-optional">Optional</span></label><input id="swarm-scope" value={scope} onChange={(e) => setScope(e.target.value)} maxLength={2048} placeholder="src/auth, tests/auth" autoComplete="off" />
        <label htmlFor="swarm-done">Done when <span className="swarm-optional">Optional</span></label><input id="swarm-done" value={done} onChange={(e) => setDone(e.target.value)} maxLength={2048} placeholder="The auth tests pass and the change is explained" autoComplete="off" />
        <label htmlFor="swarm-avoid">Not allowed <span className="swarm-optional">Optional</span></label><input id="swarm-avoid" value={avoid} onChange={(e) => setAvoid(e.target.value)} maxLength={2048} placeholder="Don’t change the database schema" autoComplete="off" />
        {sizeError ? <p className="swarm-error">{sizeError}</p> : null}
      </fieldset>
      <fieldset className="swarm-composer-section" disabled={busy || uncertain}>
        <legend>What it can open</legend>
        {harness === "claude-code" ? <>
          <label htmlFor="swarm-blocked">Folders or files it can’t open <span className="swarm-optional">Optional</span></label>
          <textarea id="swarm-blocked" rows={2} value={blockedText} onChange={(e) => setBlockedText(e.target.value)} placeholder={"customer-data/\nnotes/private.md"} spellCheck={false} />
          <label className="swarm-check"><input type="checkbox" checked={secrets} onChange={(e) => setSecrets(e.target.checked)} />Keep secret files closed (.env, .pem, .key)</label>
          {limitError ? <p className="swarm-error">{limitError}</p> : <p className="swarm-field-help">Claude Code’s file tools won’t read or change these. Shell commands are still checked by Guard’s usual rules.</p>}
        </> : <p className="swarm-field-help"><HiMiniLockClosed aria-hidden="true" /> Codex can’t be kept out of folders yet. It can open what your Codex settings allow, and Guard’s usual checks still apply. Use claude to set limits, or a worktree without those files.</p>}
      </fieldset>
      <div className="swarm-launch-summary"><HiMiniCommandLine aria-hidden="true" /><p>Runs locally with your existing CLI account, hooks, and permissions. Provider usage may apply. CIGAR still requires its own context access and connection pairing.</p></div>
      {error ? <p className="swarm-error" role="alert">{error}</p> : null}
      {uncertain ? <p className="swarm-muted">The launch may have succeeded. Check its status with the same request before creating another agent.</p> : null}
      {stale ? <p className="swarm-error">Reconnect to Guard before launching.</p> : null}
      <div className="swarm-composer-footer"><button type="button" className="swarm-text-button" onClick={onClose} disabled={busy}>Cancel</button><button type="submit" className="swarm-button swarm-button--primary" disabled={busy || stale || !harness || !workspace.trim() || !goal.trim() || limitError !== null || sizeError !== null}>{launchLabel}<HiMiniArrowRight aria-hidden="true" /></button></div>
    </form>}
  </GuardModalLayer>;
}
