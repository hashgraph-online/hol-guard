import { j as jsxRuntimeExports, H as HiMiniFolder, a as HiMiniCommandLine, b as HiMiniCircleStack, c as HiMiniArrowUpRight, f as fetchWithGuardAuth, r as reactExports, G as GuardModalLayer, d as HiMiniXMark, e as HiMiniArrowRight, g as HiMiniArrowUp, h as fetchContextAssistance, l as listContextWorkspaces, i as HiMiniPlus, k as HiMiniSquares2X2, m as HiMiniComputerDesktop, n as HiMiniMagnifyingGlass, o as HiMiniListBullet, p as HiMiniArrowPath } from "../guard-dashboard.js";
const UNKNOWN_PROJECT = "@unknown";
const stateLabel = {
  starting: "Starting",
  running: "Working",
  observed: "App running",
  awaiting_input: "Ready for direction",
  needs_attention: "Needs attention",
  completed: "Completed",
  failed: "Failed",
  stopping: "Stopping",
  stopped: "Stopped",
  interrupted: "Interrupted"
};
function isLive(agent) {
  return ["starting", "running", "observed", "awaiting_input", "needs_attention", "stopping"].includes(agent.state);
}
function folderName(path) {
  return path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || path;
}
function projectsFor(agents) {
  const projects = /* @__PURE__ */ new Map();
  for (const agent of agents) {
    const key = agent.workspace || UNKNOWN_PROJECT;
    if (!projects.has(key)) projects.set(key, { id: key, name: agent.workspace ? folderName(agent.workspace) : "Unassigned", path: agent.workspace, agents: [] });
    projects.get(key).agents.push(agent);
  }
  return [...projects.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}
function filterAgents(agents, project, search, attentionOnly) {
  const query = search.trim().toLocaleLowerCase();
  return agents.filter((agent) => (!project || (agent.workspace || UNKNOWN_PROJECT) === project) && (!attentionOnly || ["needs_attention", "failed", "interrupted"].includes(agent.state)) && (!query || [agent.label, agent.task, agent.workspace, agent.harness].some((s) => s?.toLocaleLowerCase().includes(query))));
}
function contextFor(agent, enabled, scopes) {
  if (enabled === null || enabled && scopes === null) return { label: "Context unknown", detail: "CIGAR could not be checked. Refresh or open Context.", available: false };
  if (!enabled) return { label: "CIGAR off", detail: "CIGAR is off. Agents can still work using their own context.", available: false };
  const scope = scopes?.find((s) => !s.revoked && s.workspace === agent.workspace && s.app === agent.harness);
  if (!scope) return { label: "No context grant", detail: "This project and app do not have a matching CIGAR grant.", available: false };
  return { label: "CIGAR available", detail: `${scope.sources.length} approved ${scope.sources.length === 1 ? "source" : "sources"}${scope.sharing?.notes.read ? "; shared notes enabled" : ""}. Each MCP connection still needs pairing in Context. A project grant does not confirm this agent has access or has used it.`, available: true };
}
function relativeTime(at, now = Date.now()) {
  const seconds = Math.max(0, Math.floor((now - at) / 1e3));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}
function AgentMap({ agents, selected, onSelect, context, mode }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `swarm-stage swarm-stage--${mode}`, "aria-label": mode === "map" ? "Agent map by project" : "Agent list by project", children: projectsFor(agents).map((project) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "swarm-lane", "aria-label": `${project.name} agents`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-project-anchor", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-project-symbol", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: project.name }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { title: project.path ?? void 0, children: project.path ?? "Project not reported" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-project-count", children: project.agents.length })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-node-grid", children: project.agents.map((agent) => {
      const cigar = contextFor(agent, context.enabled, context.scopes);
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          className: `swarm-node ${selected === agent.id ? "is-selected" : ""}`,
          "aria-pressed": selected === agent.id,
          "aria-label": `${agent.label}: ${agent.task ?? "Observed app"}, ${stateLabel[agent.state]}`,
          "aria-describedby": agent.activity ? `swarm-latest-${agent.id}` : void 0,
          onClick: () => onSelect(agent.id),
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-node-top", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `swarm-agent-icon swarm-agent-icon--${agent.harness}`, children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: agent.label }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: `swarm-status swarm-status--${agent.state}`, children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("i", { "aria-hidden": "true" }),
                stateLabel[agent.state]
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-task", children: agent.task ?? "Work is happening in its app" }),
            agent.activity ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { id: `swarm-latest-${agent.id}`, className: "swarm-latest", title: agent.activity, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: agent.activity })
            ] }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-node-foot", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: cigar.available || agent.context_calls > 0 ? "swarm-context-ready" : "", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { "aria-hidden": "true" }),
                agent.context_calls > 0 ? `${agent.context_calls} CIGAR calls` : cigar.label
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                agent.origin === "managed" ? "Managed" : "Observed",
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowUpRight, { "aria-hidden": "true" })
              ] })
            ] })
          ]
        },
        agent.id
      );
    }) })
  ] }, project.id)) });
}
const AGENT_STATES = ["starting", "running", "observed", "awaiting_input", "needs_attention", "completed", "failed", "stopping", "stopped", "interrupted"];
const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v, max = 4096) => typeof v === "string" && v.length <= max;
const optionalText = (v) => v === null || text(v, 16384);
const count = (v) => Number.isSafeInteger(v) && v >= 0;
const failure = () => new Error("Guard returned agent information this version of Swarm cannot read. Update Guard and try again.");
function parseAgent(value) {
  if (!object(value) || !text(value.id, 128) || !value.id || !text(value.harness, 128) || !text(value.label, 160) || !["managed", "observed"].includes(String(value.origin)) || !AGENT_STATES.includes(value.state) || !optionalText(value.workspace) || !optionalText(value.task) || !optionalText(value.model) || !optionalText(value.activity) || !(value.pid === null || count(value.pid)) || !count(value.started_at_ms) || !count(value.updated_at_ms) || !text(value.detail) || !object(value.controls) || ![value.revision, value.queued, value.context_calls, value.input_tokens, value.output_tokens].every(count) || !["message", "steer", "interrupt", "stop"].every((key) => typeof value.controls[key] === "boolean")) throw failure();
  if (value.origin === "observed" && Object.values(value.controls).some(Boolean)) throw failure();
  return value;
}
function parseSnapshot(body) {
  if (!object(body) || body.schema !== "guard-swarm-snapshot.v1" || !text(body.epoch, 128) || !body.epoch || !count(body.observed_at_ms) || !object(body.discovery) || !["ready", "unavailable"].includes(String(body.discovery.state)) || typeof body.discovery.limited !== "boolean" || !text(body.discovery.detail) || !Array.isArray(body.agents) || body.agents.length > 320 || !Array.isArray(body.adapters) || body.adapters.length > 64 || !body.adapters.every((a) => object(a) && text(a.id, 128) && text(a.label, 160) && typeof a.installed === "boolean" && typeof a.launch_supported === "boolean" && text(a.detail))) throw failure();
  const agents = body.agents.map(parseAgent);
  if (new Set(agents.map((a) => a.id)).size !== agents.length) throw failure();
  return { ...body, agents };
}
async function request(path, init, signal) {
  const timeout = AbortSignal.timeout(1e4);
  const response = await fetchWithGuardAuth(path, {
    ...init,
    cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new Error("Open Swarm from your local Guard dashboard to manage agents.");
    if (response.status === 409) throw new RejectedAction("The agent or service changed. Refresh its status before trying again.");
    const known = {
      swarm_cli_missing: "This CLI is not available to Guard. Install it and restart Guard to refresh its PATH.",
      swarm_workspace_invalid: "Choose an existing project directory using its full path.",
      swarm_run_limit: "Swarm has 16 active runs. Stop or finish one before launching another.",
      swarm_request_limit: "This Swarm service has reached its action limit. Finish active work before restarting Guard.",
      swarm_unknown_run: "This managed session is no longer available. Refresh Swarm.",
      swarm_action_unavailable: "This action is no longer available for the agent. Refresh its status.",
      swarm_launch_invalid: "Check the project, task, and model. One of the launch fields is invalid.",
      swarm_action_invalid: "The instruction is invalid or too large. Shorten it and try again."
    };
    if (response.status === 400 && object(body) && typeof body.error === "string" && known[body.error]) throw new RejectedAction(known[body.error]);
    if (response.status === 404) throw new Error("Swarm needs a newer native Guard runtime. Update Guard, then reconnect.");
    throw new Error(init.method === "GET" ? "Swarm could not reach the local agent service. Your agents may still be working." : "Guard could not confirm this action. Refresh the agent before trying again.");
  }
  return body;
}
class RejectedAction extends Error {
}
async function readSwarm(signal) {
  return parseSnapshot(await request("/v1/swarm", { method: "GET" }, signal));
}
async function launchAgent(draft, signal) {
  const body = await request("/v1/swarm/launch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(draft) }, signal);
  if (!object(body)) throw failure();
  return parseAgent(body.agent);
}
async function directAgent(agent, epoch, action, text2, requestId, signal) {
  const body = await request("/v1/swarm/action", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: agent.id, epoch, expected_revision: agent.revision, action, text: text2, request_id: requestId })
  }, signal);
  if (!object(body)) throw failure();
  return parseAgent(body.agent);
}
async function readEvents(id, signal) {
  const body = await request("/v1/swarm/events", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ run_id: id }) }, signal);
  if (!object(body) || !Array.isArray(body.events) || body.events.length > 200 || !body.events.every((e) => object(e) && count(e.sequence) && count(e.at_ms) && text(e.kind, 128) && text(e.text, 16384))) throw failure();
  return body.events;
}
function AgentComposer({ snapshot, stale, initialProject, onClose, onLaunched, onNavigate }) {
  const available = snapshot.adapters.filter((a) => a.installed && a.launch_supported);
  const [harness, setHarness] = reactExports.useState(available[0]?.id ?? "");
  const [workspace, setWorkspace] = reactExports.useState(initialProject);
  const [task, setTask] = reactExports.useState("");
  const [model, setModel] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [uncertain, setUncertain] = reactExports.useState(false);
  const pending = reactExports.useRef(null);
  const peers = snapshot.agents.filter((a) => a.workspace === workspace && isLive(a));
  async function launch() {
    if (busy || stale) return;
    const draft = pending.current ?? { request_id: crypto.randomUUID(), epoch: snapshot.epoch, harness, workspace: workspace.trim(), task, model: model.trim() || null };
    pending.current = draft;
    setBusy(true);
    setError(null);
    try {
      onLaunched(await launchAgent(draft));
    } catch (e) {
      if (e instanceof RejectedAction) {
        pending.current = null;
        setUncertain(false);
      } else setUncertain(true);
      setError(e instanceof Error ? e.message : "Launch could not be confirmed.");
    } finally {
      setBusy(false);
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(GuardModalLayer, { ariaLabel: "Start a new agent", onClose: () => {
    if (!busy) onClose();
  }, panelClassName: "swarm-composer", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-composer-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-eyebrow", children: "GIVE WORK A PLACE TO START" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "New agent" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-icon-button", "aria-label": "Close new agent", disabled: busy, onClick: onClose, children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, {}) })
    ] }),
    available.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-composer-empty", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Connect a CLI to get started" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Swarm can launch Codex and Claude Code. Install and sign in to one of them, then restart Guard so it can find the CLI." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "swarm-button swarm-button--primary", onClick: () => onNavigate("/protect"), type: "button", children: [
        "Open app setup ",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, {})
      ] })
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit: (e) => {
      e.preventDefault();
      void launch();
    }, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { disabled: busy || uncertain, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Agent configuration" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "swarm-harness", children: "Agent" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-harness-choices", role: "group", "aria-label": "Choose an agent", children: available.map((a) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { id: a.id === available[0].id ? "swarm-harness" : void 0, type: "button", "aria-pressed": harness === a.id, className: harness === a.id ? "is-selected" : "", onClick: () => setHarness(a.id), children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: a.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Installed" })
        ] }, a.id)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "swarm-project", children: "Project directory" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-input-icon", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "swarm-project", value: workspace, onChange: (e) => setWorkspace(e.target.value), placeholder: "/path/to/your/project", maxLength: 4096, list: "swarm-known-projects", required: true, autoComplete: "off" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("datalist", { id: "swarm-known-projects", children: projectsFor(snapshot.agents).filter((p) => p.path).map((p) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: p.path }, p.id)) }),
        peers.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "swarm-project-note", children: [
          peers.length,
          " ",
          peers.length === 1 ? "agent is" : "agents are",
          " already working here. Use a separate worktree if tasks may edit the same files."
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-field-help", children: "Use an existing project or worktree you trust. Its CLI settings and hooks will load." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "swarm-task", children: "What should it do?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("textarea", { id: "swarm-task", rows: 5, value: task, onChange: (e) => setTask(e.target.value), maxLength: 16384, required: true, placeholder: "Describe the outcome, relevant files, and what success looks like…" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: "swarm-model", children: [
          "Model ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-optional", children: "Optional" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "swarm-model", value: model, onChange: (e) => setModel(e.target.value), maxLength: 128, placeholder: "Use the CLI’s configured model", autoComplete: "off" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-launch-summary", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Runs locally with your existing CLI account, hooks, and permissions. Provider usage may apply. CIGAR still requires its own context access and connection pairing." })
      ] }),
      error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-error", role: "alert", children: error }) : null,
      uncertain ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-muted", children: "The launch may have succeeded. Check its status with the same request before creating another agent." }) : null,
      stale ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-error", children: "Reconnect to Guard before launching." }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-composer-footer", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-text-button", onClick: onClose, disabled: busy, children: "Cancel" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "submit", className: "swarm-button swarm-button--primary", disabled: busy || stale || !harness || !workspace.trim() || !task.trim(), children: [
          busy ? "Starting…" : uncertain ? "Check launch" : "Start agent",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
        ] })
      ] })
    ] })
  ] });
}
function Activity({ agent, stale }) {
  const [events, setEvents] = reactExports.useState([]);
  const [error, setError] = reactExports.useState(false);
  reactExports.useEffect(() => {
    if (agent.origin !== "managed") return;
    const abort = new AbortController();
    let timer;
    async function poll() {
      try {
        if (!document.hidden) {
          const next = await readEvents(agent.id, abort.signal);
          if (!abort.signal.aborted) {
            setEvents(next);
            setError(false);
          }
        }
      } catch {
        if (!abort.signal.aborted) setError(true);
      } finally {
        if (!abort.signal.aborted) timer = setTimeout(poll, 2e3);
      }
    }
    void poll();
    return () => {
      abort.abort();
      clearTimeout(timer);
    };
  }, [agent.id, agent.origin]);
  const entries = agent.origin === "observed" ? [
    { sequence: 1, kind: "lifecycle", text: "Observed on this computer", at_ms: agent.updated_at_ms }
  ] : [...events].reverse();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "swarm-activity", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-section-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Activity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: entries.length ? `${entries.length} recent` : "Waiting for output" })
    ] }),
    error || stale ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-muted", role: "status", children: "Activity may be out of date. Reconnecting…" }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { "aria-label": "Recent agent activity", children: entries.map((event) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: `swarm-event--${event.kind}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("i", { "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-event-meta", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: event.kind }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("time", { dateTime: new Date(event.at_ms).toISOString(), children: relativeTime(event.at_ms) })
        ] }),
        event.kind === "command" ? /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: event.text }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: event.text })
      ] })
    ] }, event.sequence)) }),
    agent.origin === "observed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-muted", children: "Task output stays in this agent’s app. Start an agent here to follow its activity." }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-muted", children: "Latest 200 events; long output is shortened for this view. CLI transcripts stay in the harness." })
  ] });
}
function AgentInspector({ agent, epoch, stale, onClose, onRefresh, onNavigate, context, reviews, onOpenRequest }) {
  const [draft, setDraft] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [confirmStop, setConfirmStop] = reactExports.useState(false);
  const [notice, setNotice] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [tab, setTab] = reactExports.useState("Activity");
  const panel = reactExports.useRef(null);
  const alive = reactExports.useRef(true);
  const pending = reactExports.useRef(null);
  reactExports.useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  reactExports.useEffect(() => {
    if (window.matchMedia("(max-width: 1050px)").matches) panel.current?.scrollIntoView({ block: "start", behavior: "instant" });
  }, []);
  reactExports.useEffect(() => {
    setDraft("");
    setNotice(null);
    setError(null);
    setConfirmStop(false);
  }, [agent.id]);
  const cigar = contextFor(agent, context.enabled, context.scopes);
  async function act(action) {
    if (busy || stale) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    const request2 = pending.current ?? { agent, epoch, action, text: action === "message" ? draft : null, id: crypto.randomUUID() };
    pending.current = request2;
    try {
      await directAgent(request2.agent, request2.epoch, request2.action, request2.text, request2.id);
      if (!alive.current) return;
      pending.current = null;
      if (action === "message") setDraft("");
      setNotice(action === "stop" ? "Stop requested. Waiting for the process to exit." : action === "interrupt" ? "Interruption requested." : "Instruction accepted by the agent service.");
      setConfirmStop(false);
      onRefresh();
    } catch (e) {
      if (alive.current) {
        if (e instanceof RejectedAction) pending.current = null;
        setError(e instanceof Error ? e.message : "The action could not be confirmed.");
        onRefresh();
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref: panel, className: "swarm-inspector", "aria-label": "Agent details", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-inspector-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "AGENT DETAILS" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-icon-button", type: "button", onClick: onClose, "aria-label": "Close agent details", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, {}) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-inspector-identity", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-agent-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: agent.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: `swarm-status swarm-status--${agent.state}`, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("i", { "aria-hidden": "true" }),
          stateLabel[agent.state]
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-inspector-task", children: agent.task ?? (agent.origin === "observed" ? "This agent was started outside Swarm." : "Previous managed session") }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-muted", children: agent.detail }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-detail-tabs", role: "tablist", "aria-label": "Agent information", onKeyDown: (e) => {
      const names = ["Activity", "Context", "Details"];
      const index = names.indexOf(tab);
      const next = e.key === "ArrowRight" ? (index + 1) % 3 : e.key === "ArrowLeft" ? (index + 2) % 3 : e.key === "Home" ? 0 : e.key === "End" ? 2 : -1;
      if (next >= 0) {
        e.preventDefault();
        setTab(names[next]);
        e.currentTarget.querySelectorAll("button")[next]?.focus();
      }
    }, children: ["Activity", "Context", "Details"].map((name) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { id: `swarm-tab-${name}`, "aria-controls": `swarm-panel-${name}`, type: "button", role: "tab", "aria-selected": tab === name, tabIndex: tab === name ? 0 : -1, onClick: () => setTab(name), children: [
      name,
      name === "Context" && agent.context_calls > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: agent.context_calls }) : null
    ] }, name)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "tabpanel", id: "swarm-panel-Details", "aria-labelledby": "swarm-tab-Details", hidden: tab !== "Details", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "swarm-facts", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Project" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: agent.workspace ?? "Not reported" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Control" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: agent.origin === "managed" ? "Managed by Swarm" : "In its own app" })
      ] }),
      agent.model ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Model" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: agent.model })
      ] }) : null,
      agent.pid ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Process" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: agent.pid })
      ] }) : null
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "tabpanel", id: "swarm-panel-Activity", "aria-labelledby": "swarm-tab-Activity", hidden: tab !== "Activity", children: [
      reviews.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "swarm-reviews", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { children: [
          reviews.length,
          " project ",
          reviews.length === 1 ? "review" : "reviews"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Pending Guard actions for this project and app. They may belong to another agent." }),
        reviews.slice(0, 3).map((review) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => onOpenRequest(review.request_id), children: [
          review.artifact_name || "Review action",
          " ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "↗" })
        ] }, review.request_id))
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx(Activity, { agent, stale }, agent.id)
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "tabpanel", id: "swarm-panel-Context", "aria-labelledby": "swarm-tab-Context", hidden: tab !== "Context", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "swarm-context-panel", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { "aria-hidden": "true" }),
          cigar.label
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: cigar.detail }),
        agent.context_calls > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "swarm-context-count", children: [
          agent.context_calls,
          " completed context ",
          agent.context_calls === 1 ? "call" : "calls",
          " reported by this CLI."
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Context use has not been reported for this agent. Hook-injected context is not counted here." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "swarm-text-button", type: "button", onClick: () => onNavigate("/cigar?section=access"), children: [
          "Manage context access ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "↗" })
        ] })
      ] }),
      agent.input_tokens + agent.output_tokens > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "swarm-token-facts", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Input tokens" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: agent.input_tokens.toLocaleString() })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Output tokens" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: agent.output_tokens.toLocaleString() })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-muted", children: "Reported by the CLI for completed turns. These are model tokens, not CIGAR savings." })
      ] }) : null
    ] }),
    agent.controls.message ? /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { className: "swarm-direct", onSubmit: (e) => {
      e.preventDefault();
      void act("message");
    }, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "swarm-direction", children: "Next instruction" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("textarea", { id: "swarm-direction", value: draft, onChange: (e) => setDraft(e.target.value), maxLength: 16384, rows: 3, placeholder: "What should it focus on?", disabled: stale || busy || pending.current !== null }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "swarm-field-help", children: [
        agent.state === "running" || agent.state === "starting" ? "Queued after the current turn. Interrupt first to change focus now." : "Continues this agent’s conversation in the same project.",
        agent.queued ? ` ${agent.queued} queued.` : ""
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "swarm-button swarm-button--primary", disabled: !draft.trim() || stale || busy || pending.current !== null && pending.current.action !== "message", type: "submit", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowUp, { "aria-hidden": "true" }),
        busy ? "Sending…" : pending.current ? "Check instruction" : "Send instruction"
      ] })
    ] }) : agent.origin === "observed" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "swarm-handoff", children: [
      "Continue in your ",
      agent.label,
      " window to send instructions. Swarm has observation access to this process."
    ] }) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-error", role: "alert", children: error }) : null,
    notice ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-muted", role: "status", children: notice }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-inspector-actions", children: [
      agent.controls.interrupt ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-button", type: "button", disabled: stale || busy || pending.current !== null, onClick: () => void act("interrupt"), children: "Interrupt turn" }) : null,
      agent.controls.stop ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-button swarm-button--danger", type: "button", disabled: stale || busy || pending.current !== null, onClick: () => setConfirmStop(true), children: "Stop agent" }) : null,
      agent.origin === "observed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-button", type: "button", onClick: () => onNavigate(`/apps/${encodeURIComponent(agent.harness)}`), children: "App setup" }) : null
    ] }),
    pending.current && !busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-text-button", disabled: stale, type: "button", onClick: () => void act(pending.current.action), children: "Check unconfirmed action" }) : null,
    confirmStop ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-stop-confirm", role: "group", "aria-label": "Confirm stop", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Stop this agent and the work it is running? Changes already made to files will remain." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-button swarm-button--danger", disabled: stale || busy, type: "button", onClick: () => void act("stop"), children: "Stop this agent" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-text-button", type: "button", disabled: busy, onClick: () => setConfirmStop(false), children: "Keep working" })
    ] }) : null
  ] });
}
function useSwarm() {
  const [snapshot, setSnapshot] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  const [refresh, setRefresh] = reactExports.useState(0);
  const [context, setContext] = reactExports.useState({ enabled: null, scopes: null });
  const generation = reactExports.useRef(0);
  const refreshNow = reactExports.useCallback(() => setRefresh((n) => n + 1), []);
  const acceptAgent = reactExports.useCallback((agent) => setSnapshot((old) => old ? { ...old, agents: [...old.agents.filter((a) => a.id !== agent.id), agent] } : old), []);
  reactExports.useEffect(() => {
    const current = ++generation.current;
    const abort = new AbortController();
    let timer;
    let inFlight = false;
    async function poll() {
      if (abort.signal.aborted || inFlight) return;
      if (document.hidden) {
        timer = setTimeout(poll, 3e3);
        return;
      }
      inFlight = true;
      try {
        const next = await readSwarm(abort.signal);
        if (generation.current === current && !abort.signal.aborted) {
          setSnapshot((old) => old && old.epoch === next.epoch && old.observed_at_ms > next.observed_at_ms ? old : next);
          setError(null);
        }
      } catch (e) {
        if (!abort.signal.aborted && generation.current === current) setError(e instanceof Error ? e.message : "Swarm is unavailable.");
      } finally {
        inFlight = false;
        if (!abort.signal.aborted) {
          setLoading(false);
          timer = setTimeout(poll, 3e3);
        }
      }
    }
    function visible() {
      if (!document.hidden) {
        clearTimeout(timer);
        void poll();
      }
    }
    void poll();
    document.addEventListener("visibilitychange", visible);
    return () => {
      abort.abort();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [refresh]);
  reactExports.useEffect(() => {
    const abort = new AbortController();
    let timer;
    async function poll() {
      if (abort.signal.aborted) return;
      try {
        if (!document.hidden) {
          const status = await fetchContextAssistance(abort.signal);
          const scopes = status.effective_enabled ? await listContextWorkspaces(abort.signal) : [];
          if (!abort.signal.aborted) setContext({ enabled: status.effective_enabled, scopes });
        }
      } catch {
        if (!abort.signal.aborted) setContext({ enabled: null, scopes: null });
      } finally {
        if (!abort.signal.aborted) timer = setTimeout(poll, 15e3);
      }
    }
    void poll();
    return () => {
      abort.abort();
      clearTimeout(timer);
    };
  }, [refresh]);
  return { snapshot, loading, error, stale: error !== null, context, refresh: refreshNow, acceptAgent };
}
function SwarmWorkspace({ onNavigate, reviews = null, onOpenRequest }) {
  const { snapshot, loading, error, stale, context, refresh, acceptAgent } = useSwarm();
  const [selected, setSelected] = reactExports.useState(null);
  const [project, setProject] = reactExports.useState(null);
  const [search, setSearch] = reactExports.useState("");
  const [attention, setAttention] = reactExports.useState(false);
  const [mode, setMode] = reactExports.useState("map");
  const [composing, setComposing] = reactExports.useState(false);
  const stageRef = reactExports.useRef(null);
  const previousEpoch = reactExports.useRef(null);
  const [restarted, setRestarted] = reactExports.useState(false);
  const agents = snapshot?.agents ?? [];
  const projects = reactExports.useMemo(() => projectsFor(agents), [agents]);
  const visible = reactExports.useMemo(() => filterAgents(agents, project, search, attention), [agents, project, search, attention]);
  const active = agents.filter(isLive).length;
  const needsAttention = agents.filter((a) => ["needs_attention", "failed", "interrupted"].includes(a.state)).length;
  const chosen = agents.find((a) => a.id === selected);
  const chosenReviews = chosen?.workspace ? (reviews ?? []).filter((r) => r.workspace === chosen.workspace && r.harness === chosen.harness && r.status === "pending") : [];
  reactExports.useEffect(() => {
    if (snapshot && previousEpoch.current && previousEpoch.current !== snapshot.epoch) {
      setRestarted(true);
      setSelected(null);
    }
    if (snapshot) previousEpoch.current = snapshot.epoch;
  }, [snapshot?.epoch]);
  function closeDetails() {
    const button = stageRef.current?.querySelector("button[aria-pressed=true]");
    setSelected(null);
    button?.focus();
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-workspace", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "swarm-header", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-eyebrow", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "swarm-mark", "aria-hidden": "true", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("i", {}),
            /* @__PURE__ */ jsxRuntimeExports.jsx("i", {}),
            /* @__PURE__ */ jsxRuntimeExports.jsx("i", {})
          ] }),
          "LOCAL AGENT WORKSPACE"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h1", { children: [
          "Swarm",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-heading-dot", children: "." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "One place to follow the work. Every agent, every project." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-header-actions", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: `swarm-connection ${stale ? "is-stale" : ""}`, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("i", { "aria-hidden": "true" }),
          stale ? "Reconnecting" : loading ? "Connecting" : "Live on this computer"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "swarm-button swarm-button--primary", disabled: !snapshot || stale, onClick: () => setComposing(true), children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { "aria-hidden": "true" }),
          "New agent"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-overview", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-stat", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: snapshot ? active : "—" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Active agents" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: `swarm-stat ${attention ? "is-selected" : ""}`, "aria-pressed": attention, onClick: () => setAttention(!attention), children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-attention-symbol", "aria-hidden": "true", children: "!" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: snapshot ? needsAttention : "—" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Need attention" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-stat", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: snapshot ? projects.filter((p) => p.path && p.agents.some(isLive)).length : "—" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Active projects" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "swarm-context-summary", onClick: () => onNavigate("/cigar"), children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR context" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("small", { children: context.enabled === null ? "Checking availability" : context.enabled ? "Runtime enabled · access by project" : "Off · set up shared context" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "↗" })
      ] })
    ] }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-banner swarm-banner--error", role: "status", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        error,
        snapshot ? " Showing the last confirmed agents." : ""
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: refresh, children: "Reconnect" })
    ] }) : null,
    restarted ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-banner", role: "status", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Guard restarted. Previous tasks have not been relaunched. Check each agent before sending new work." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => setRestarted(false), children: "Dismiss" })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `swarm-body ${chosen ? "has-inspector" : ""}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { className: "swarm-project-rail", "aria-label": "Swarm projects", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-rail-heading", children: [
          "PROJECTS",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: projects.length })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: !project ? "is-selected" : "", "aria-pressed": !project, onClick: () => setProject(null), children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSquares2X2, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "All projects" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("b", { children: agents.length })
        ] }),
        projects.map((p) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: project === p.id ? "is-selected" : "", "aria-pressed": project === p.id, onClick: () => setProject(p.id), title: p.path ?? "Project not reported", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: p.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("b", { children: p.agents.length })
        ] }, p.id)),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-rail-note", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniComputerDesktop, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Your computer" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "CLI processes visible to your account. Agents started here include task output and controls." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-text-button", onClick: () => onNavigate("/protect"), children: "Manage apps ↗" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "swarm-canvas", "aria-label": "Swarm agents", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-toolbar", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "swarm-search", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("input", { "aria-label": "Search agents and projects", placeholder: "Find an agent or task…", value: search, onChange: (e) => setSearch(e.target.value) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-view-toggle", role: "group", "aria-label": "Agent view", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-pressed": mode === "map", onClick: () => setMode("map"), "aria-label": "Map view", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSquares2X2, { "aria-hidden": "true" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Map" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-pressed": mode === "list", onClick: () => setMode("list"), "aria-label": "List view", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniListBullet, { "aria-hidden": "true" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "List" })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-icon-button", onClick: refresh, "aria-label": "Refresh agents", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, {}) })
        ] }),
        attention ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-filter-note", children: [
          "Showing agents that need attention",
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => setAttention(false), children: "Show all" })
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: stageRef, children: loading && !snapshot ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-empty", role: "status", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-empty-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Finding your agents" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Checking recognized CLIs on this computer…" })
        ] }) : visible.length ? /* @__PURE__ */ jsxRuntimeExports.jsx(AgentMap, { agents: visible, selected, onSelect: setSelected, context, mode }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-empty", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-empty-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-eyebrow", children: "ROOM FOR YOUR NEXT IDEA" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: !snapshot ? "Connect to your local Guard" : agents.length ? "No agents in this view" : "Your next project starts here" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: !snapshot ? "Swarm needs the local agent service to show what is running." : agents.length ? "Try another project or clear your search and attention filter." : "Give an agent a task, follow its progress, and bring in more agents when the work grows." }),
          snapshot ? agents.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-button", onClick: () => {
            setSearch("");
            setProject(null);
            setAttention(false);
          }, children: "Clear filters" }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "swarm-button swarm-button--primary", disabled: stale, onClick: () => setComposing(true), children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, {}),
            "Start your first agent"
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-button", onClick: refresh, children: "Reconnect" })
        ] }) }),
        snapshot ? /* @__PURE__ */ jsxRuntimeExports.jsxs("footer", { className: "swarm-coverage", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("i", { "aria-hidden": "true" }),
            snapshot.discovery.detail,
            snapshot.discovery.limited ? " Discovery is limited to the first 256 processes." : ""
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            visible.length,
            " shown"
          ] })
        ] }) : null
      ] }),
      chosen && snapshot ? /* @__PURE__ */ jsxRuntimeExports.jsx(AgentInspector, { agent: chosen, epoch: snapshot.epoch, stale, onClose: closeDetails, onRefresh: refresh, onNavigate, context, reviews: chosenReviews, onOpenRequest }, `${snapshot.epoch}:${chosen.id}`) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-bottom-note", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Managed agents accept instructions here. Observed agents stay in their own apps." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "swarm-text-button", type: "button", onClick: () => onNavigate("/inbox"), children: [
        reviews === null ? "Open Guard reviews" : `${reviews.length} Guard reviews`,
        " ↗"
      ] })
    ] }),
    composing && snapshot ? /* @__PURE__ */ jsxRuntimeExports.jsx(AgentComposer, { snapshot, stale, initialProject: project && project !== UNKNOWN_PROJECT ? project : "", onClose: () => setComposing(false), onNavigate, onLaunched: (agent) => {
      acceptAgent(agent);
      setSelected(agent.id);
      setComposing(false);
      setProject(null);
      setSearch("");
      setAttention(false);
      refresh();
    } }) : null
  ] });
}
export {
  SwarmWorkspace
};
