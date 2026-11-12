import { r as reactExports, j as jsxRuntimeExports, ed as GuardModalLayer, ak as HiMiniXMark, b as HiMiniCommandLine, I as HiMiniArrowRight, c as HiMiniFolder } from "../guard-dashboard.js";
import { i as isLive, p as projectsFor, l as launchAgent, R as RejectedAction } from "./swarm-workspace-B04u026b.js";
import "./swarm-handoff-BIqKreGh.js";
const pendingLaunches = /* @__PURE__ */ new Map();
function AgentComposer({ snapshot, stale, initialProject, onClose, onLaunched, onNavigate }) {
  const available = snapshot.adapters.filter((a) => a.installed && a.launch_supported);
  const [harness, setHarness] = reactExports.useState(available[0]?.id ?? "");
  const [workspace, setWorkspace] = reactExports.useState(initialProject);
  const [task, setTask] = reactExports.useState("");
  const [model, setModel] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [uncertain, setUncertain] = reactExports.useState(false);
  const pendingKey = `${snapshot.epoch}:${initialProject}:${available[0]?.id ?? ""}`;
  const pending = reactExports.useRef(pendingLaunches.get(pendingKey) ?? null);
  const peers = snapshot.agents.filter((a) => a.workspace === workspace && isLive(a));
  let launchLabel = "Start agent";
  if (busy) launchLabel = "Starting…";
  else if (uncertain) launchLabel = "Check launch";
  async function launch() {
    if (busy || stale) return;
    const draft = pending.current ?? { request_id: crypto.randomUUID(), epoch: snapshot.epoch, harness, workspace: workspace.trim(), task, model: model.trim() || null };
    pending.current = draft;
    pendingLaunches.set(pendingKey, draft);
    setBusy(true);
    setError(null);
    try {
      const agent = await launchAgent(draft);
      pendingLaunches.delete(pendingKey);
      onLaunched(agent);
    } catch (e) {
      if (e instanceof RejectedAction) {
        pending.current = null;
        pendingLaunches.delete(pendingKey);
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
          launchLabel,
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
        ] })
      ] })
    ] })
  ] });
}
export {
  AgentComposer
};
