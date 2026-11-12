const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunks/agent-map-C09p6Yow.js","assets/guard-dashboard.js","assets/index.css","assets/chunks/swarm-handoff-CPWKavP3.js","assets/chunks/composer-DW8UFbQG.js","assets/chunks/inspector-7BblDByV.js"])))=>i.map(i=>d[i]);
import { f as fetchWithGuardAuth, r as reactExports, a as fetchContextAssistance, l as listContextWorkspaces, j as jsxRuntimeExports, H as HiMiniPlus, b as HiMiniCommandLine, c as HiMiniFolder, d as HiMiniCircleStack, e as HiMiniSquares2X2, g as HiMiniComputerDesktop, h as HiMiniMagnifyingGlass, i as HiMiniListBullet, k as HiMiniArrowPath, m as loadWorkspaceModule, n as browserSessionStorage, _ as __vitePreload } from "../guard-dashboard.js";
import { w as workspaceForSwarmAgent, u as usesPromptContext } from "./swarm-handoff-CPWKavP3.js";
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
  const workspace = workspaceForSwarmAgent(agent.id, agent.workspace);
  const matches = scopes?.filter((s) => !s.revoked && s.workspace === workspace);
  const scope = matches?.find((s) => s.app === "dashboard") ?? matches?.find((s) => s.app === agent.harness);
  if (!scope) return { label: "Choose project context", detail: "No files have been picked for this project. Connected prompt hooks can still find matching project files automatically. Add the project to choose its files and preview the context.", available: false };
  const connection = usesPromptContext(agent.harness) ? "With Guard connected in App setup, new prompts receive project context. A running turn keeps its existing context." : "Each MCP connection still needs pairing in CIGAR.";
  return { label: "Project context ready", detail: `${scope.sources.length} approved ${scope.sources.length === 1 ? "source" : "sources"}${scope.sharing?.notes.read ? "; shared notes enabled" : ""}. ${connection} A project grant does not confirm this agent has used it.`, available: true };
}
function relativeTime(at, now = Date.now()) {
  const seconds = Math.max(0, Math.floor((now - at) / 1e3));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
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
const load = (id, loader) => loadWorkspaceModule(loader, { moduleId: id, storage: browserSessionStorage() });
const AgentMap = reactExports.lazy(() => load("swarm-agent-map", () => __vitePreload(() => import("./agent-map-C09p6Yow.js"), true ? __vite__mapDeps([0,1,2,3]) : void 0)).then((module) => ({ default: module.AgentMap })));
const AgentComposer = reactExports.lazy(() => load("swarm-composer", () => __vitePreload(() => import("./composer-DW8UFbQG.js"), true ? __vite__mapDeps([4,1,2,3]) : void 0)).then((module) => ({ default: module.AgentComposer })));
const AgentInspector = reactExports.lazy(() => load("swarm-inspector", () => __vitePreload(() => import("./inspector-7BblDByV.js"), true ? __vite__mapDeps([5,1,2,3]) : void 0)).then((module) => ({ default: module.AgentInspector })));
function SwarmWorkspace({ onNavigate, reviews = null, onOpenRequest }) {
  const { snapshot, loading, error, stale, context, refresh, acceptAgent } = useSwarm();
  const [selected, setSelected] = reactExports.useState(() => new URLSearchParams(window.location.search).get("agent"));
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
  let connection = "Live on this computer";
  if (loading) connection = "Connecting";
  if (stale) connection = "Reconnecting";
  let contextStatus = "Off · set up shared context";
  if (context.enabled === null) contextStatus = "Checking availability";
  else if (context.enabled) contextStatus = "Runtime enabled · access by project";
  let emptyHeading = "Your next project starts here";
  let emptyCopy = "Give an agent a task, follow its progress, and bring in more agents when the work grows.";
  if (!snapshot) {
    emptyHeading = "Connect to your local Guard";
    emptyCopy = "Swarm needs the local agent service to show what is running.";
  } else if (agents.length) {
    emptyHeading = "No agents in this view";
    emptyCopy = "Try another project or clear your search and attention filter.";
  }
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
          connection
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
          /* @__PURE__ */ jsxRuntimeExports.jsx("small", { children: contextStatus })
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: stageRef, children: /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-empty", role: "status", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Loading Swarm…" }) }), children: loading && !snapshot ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-empty", role: "status", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-empty-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Finding your agents" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Checking recognized CLIs on this computer…" })
        ] }) : visible.length ? /* @__PURE__ */ jsxRuntimeExports.jsx(AgentMap, { agents: visible, selected, onSelect: setSelected, context, mode }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-empty", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-empty-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-eyebrow", children: "ROOM FOR YOUR NEXT IDEA" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: emptyHeading }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: emptyCopy }),
          snapshot ? agents.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-button", onClick: () => {
            setSearch("");
            setProject(null);
            setAttention(false);
          }, children: "Clear filters" }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "swarm-button swarm-button--primary", disabled: stale, onClick: () => setComposing(true), children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, {}),
            "Start your first agent"
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "swarm-button", onClick: refresh, children: "Reconnect" })
        ] }) }) }),
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
      chosen && snapshot ? /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx("aside", { className: "swarm-inspector", "aria-label": "Agent details", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Loading agent details…" }) }), children: /* @__PURE__ */ jsxRuntimeExports.jsx(AgentInspector, { agent: chosen, epoch: snapshot.epoch, stale, onClose: closeDetails, onRefresh: refresh, onNavigate, context, reviews: chosenReviews, onOpenRequest }, `${snapshot.epoch}:${chosen.id}`) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-bottom-note", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Managed agents accept instructions here. Observed agents stay in their own apps." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "swarm-text-button", type: "button", onClick: () => onNavigate("/inbox"), children: [
        reviews === null ? "Open Guard reviews" : `${reviews.length} Guard reviews`,
        " ↗"
      ] })
    ] }),
    composing && snapshot ? /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: null, children: /* @__PURE__ */ jsxRuntimeExports.jsx(AgentComposer, { snapshot, stale, initialProject: project && project !== UNKNOWN_PROJECT ? project : "", onClose: () => setComposing(false), onNavigate, onLaunched: (agent) => {
      acceptAgent(agent);
      setSelected(agent.id);
      setComposing(false);
      setProject(null);
      setSearch("");
      setAttention(false);
      refresh();
    } }) }) : null
  ] });
}
const swarmWorkspace = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  SwarmWorkspace
}, Symbol.toStringTag, { value: "Module" }));
export {
  RejectedAction as R,
  readEvents as a,
  swarmWorkspace as b,
  contextFor as c,
  directAgent as d,
  isLive as i,
  launchAgent as l,
  projectsFor as p,
  relativeTime as r,
  stateLabel as s
};
