import { r as reactExports, j as jsxRuntimeExports, ak as HiMiniXMark, b as HiMiniCommandLine, d as HiMiniCircleStack, fp as HiMiniArrowUp } from "../guard-dashboard.js";
import { s as setSwarmContextTarget } from "./swarm-handoff-BIqKreGh.js";
import { r as relativeTime, a as readEvents, c as contextFor, s as stateLabel, d as directAgent, R as RejectedAction } from "./swarm-workspace-B04u026b.js";
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
const pendingActions = /* @__PURE__ */ new Map();
function AgentInspector({ agent, epoch, stale, onClose, onRefresh, onNavigate, context, reviews, onOpenRequest }) {
  const [draft, setDraft] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [confirmStop, setConfirmStop] = reactExports.useState(false);
  const [notice, setNotice] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [tab, setTab] = reactExports.useState(() => new URLSearchParams(window.location.search).get("panel") === "context" ? "Context" : "Activity");
  const panel = reactExports.useRef(null);
  const alive = reactExports.useRef(true);
  const pendingKey = `${epoch}:${agent.id}`;
  const pending = reactExports.useRef(pendingActions.get(pendingKey) ?? null);
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
    if (pending.current && pending.current.action !== action) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    const request = pending.current ?? { agent, epoch, action, text: action === "message" ? draft : null, id: crypto.randomUUID() };
    pending.current = request;
    pendingActions.set(pendingKey, request);
    try {
      await directAgent(request.agent, request.epoch, request.action, request.text, request.id);
      if (!alive.current) return;
      pending.current = null;
      pendingActions.delete(pendingKey);
      if (action === "message") setDraft("");
      let message = "Instruction accepted by the agent service.";
      if (action === "stop") message = "Stop requested. Waiting for the process to exit.";
      else if (action === "interrupt") message = "Interruption requested.";
      setNotice(message);
      setConfirmStop(false);
      onRefresh();
    } catch (e) {
      if (alive.current) {
        if (e instanceof RejectedAction) {
          pending.current = null;
          pendingActions.delete(pendingKey);
        }
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
      let next = -1;
      if (e.key === "ArrowRight") next = (index + 1) % 3;
      else if (e.key === "ArrowLeft") next = (index + 2) % 3;
      else if (e.key === "Home") next = 0;
      else if (e.key === "End") next = 2;
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
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: "swarm-button swarm-button--primary", type: "button", onClick: () => {
          setSwarmContextTarget(agent);
          onNavigate("/cigar?section=access");
        }, children: [
          cigar.available ? "Manage CIGAR context" : "Add to CIGAR",
          " ",
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-button swarm-button--danger", disabled: stale || busy || pending.current !== null && pending.current.action !== "stop", type: "button", onClick: () => void act("stop"), children: "Stop this agent" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "swarm-text-button", type: "button", disabled: busy, onClick: () => setConfirmStop(false), children: "Keep working" })
    ] }) : null
  ] });
}
export {
  AgentInspector
};
