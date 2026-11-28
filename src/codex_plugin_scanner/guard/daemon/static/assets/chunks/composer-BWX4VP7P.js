import { r as reactExports, j as jsxRuntimeExports, bh as GuardModalLayer, ak as HiMiniXMark, b as HiMiniCommandLine, I as HiMiniArrowRight, c as HiMiniFolder, K as HiMiniLockClosed } from "../guard-dashboard.js";
import { i as isLive, p as projectsFor, l as launchAgent, R as RejectedAction } from "./swarm-workspace-DpTtZDf_.js";
import { g as goalOf, p as parseCommand, b as blockedPaths, w as workText, M as MAX_BLOCKED } from "./work-DPWaZlHI.js";
import "./swarm-handoff-BIqKreGh.js";
const pendingLaunches = /* @__PURE__ */ new Map();
const pendingForms = /* @__PURE__ */ new Map();
const COMMANDS = { codex: "codex", "claude-code": "claude" };
const MAX_TASK_BYTES = 16384;
function AgentComposer({ snapshot, stale, initialProject, onClose, onLaunched, onNavigate }) {
  const available = snapshot.adapters.filter((a) => a.installed && a.launch_supported);
  const retained = [...pendingLaunches.values()].find((draft) => draft.epoch === snapshot.epoch && (!initialProject || draft.workspace === initialProject));
  const firstHarness = retained?.harness ?? available[0]?.id ?? "";
  const [command, setCommand] = reactExports.useState(() => {
    const program = COMMANDS[firstHarness] ?? "";
    return retained?.model ? `${program} --model ${retained.model}` : program;
  });
  const [workspace, setWorkspace] = reactExports.useState(retained?.workspace ?? initialProject);
  const form = retained ? pendingForms.get(retained.request_id) : void 0;
  const [goal, setGoal] = reactExports.useState(form?.goal ?? goalOf(retained?.task ?? null) ?? "");
  const [scope, setScope] = reactExports.useState(form?.scope ?? "");
  const [done, setDone] = reactExports.useState(form?.done ?? "");
  const [avoid, setAvoid] = reactExports.useState(form?.avoid ?? "");
  const [blockedText, setBlockedText] = reactExports.useState(form?.blockedText ?? retained?.blocked?.join("\n") ?? "");
  const [secrets, setSecrets] = reactExports.useState(form?.secrets ?? !retained);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [uncertain, setUncertain] = reactExports.useState(retained !== void 0);
  const pending = reactExports.useRef(retained ?? null);
  const peers = snapshot.agents.filter((a) => a.workspace === workspace && isLive(a));
  const parsed = parseCommand(command, available.map((a) => a.id));
  const harness = "harness" in parsed ? parsed.harness : "";
  const limits = harness === "claude-code" ? blockedPaths(blockedText, secrets) : { paths: [], bad: [] };
  let limitError = null;
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
    const fresh = {
      request_id: crypto.randomUUID(),
      epoch: snapshot.epoch,
      harness: parsed.harness,
      workspace: workspace.trim(),
      task,
      model: parsed.model
    };
    if (limits.paths.length) fresh.blocked = limits.paths;
    const draft = pending.current ?? fresh;
    pending.current = draft;
    pendingLaunches.set(draft.request_id, draft);
    if (!pendingForms.has(draft.request_id)) pendingForms.set(draft.request_id, { goal, scope, done, avoid, blockedText, secrets });
    setBusy(true);
    setError(null);
    const forget = () => {
      pendingLaunches.delete(draft.request_id);
      pendingForms.delete(draft.request_id);
    };
    try {
      const agent = await launchAgent(draft);
      forget();
      onLaunched(agent);
    } catch (e) {
      if (e instanceof RejectedAction) {
        pending.current = null;
        forget();
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "swarm-command", children: "Command" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "swarm-input-icon swarm-command", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "swarm-command", value: command, onChange: (e) => setCommand(e.target.value), placeholder: "codex", maxLength: 256, required: true, autoComplete: "off", spellCheck: false, "aria-describedby": "swarm-command-help" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "swarm-command-picks", role: "group", "aria-label": "Installed CLIs", children: available.map((a) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", "aria-pressed": harness === a.id, className: harness === a.id ? "is-selected" : "", onClick: () => setCommand(COMMANDS[a.id] ?? a.id), children: COMMANDS[a.id] ?? a.id }, a.id)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: "swarm-command-help", className: "error" in parsed && command.trim() ? "swarm-error" : "swarm-field-help", children: "error" in parsed && command.trim() ? parsed.error : "Runs in the background in the project folder, then shows up on the map. Add --model to pick a model." }),
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
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-field-help", children: "Use an existing project or worktree you trust. Its CLI settings and hooks will load." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "swarm-composer-section", disabled: busy || uncertain, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { children: "Work for this agent" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "swarm-task", children: "Goal" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("textarea", { id: "swarm-task", rows: 3, value: goal, onChange: (e) => setGoal(e.target.value), maxLength: 8192, required: true, placeholder: "Fix the login timeout on slow networks" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: "swarm-scope", children: [
          "Files in scope ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-optional", children: "Optional" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "swarm-scope", value: scope, onChange: (e) => setScope(e.target.value), maxLength: 2048, placeholder: "src/auth, tests/auth", autoComplete: "off" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: "swarm-done", children: [
          "Done when ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-optional", children: "Optional" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "swarm-done", value: done, onChange: (e) => setDone(e.target.value), maxLength: 2048, placeholder: "The auth tests pass and the change is explained", autoComplete: "off" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: "swarm-avoid", children: [
          "Not allowed ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-optional", children: "Optional" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "swarm-avoid", value: avoid, onChange: (e) => setAvoid(e.target.value), maxLength: 2048, placeholder: "Don’t change the database schema", autoComplete: "off" }),
        sizeError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-error", children: sizeError }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "swarm-composer-section", disabled: busy || uncertain, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { children: "What it can open" }),
        harness === "claude-code" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: "swarm-blocked", children: [
            "Folders or files it can’t open ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "swarm-optional", children: "Optional" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("textarea", { id: "swarm-blocked", rows: 2, value: blockedText, onChange: (e) => setBlockedText(e.target.value), placeholder: "customer-data/\nnotes/private.md", spellCheck: false }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "swarm-check", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "checkbox", checked: secrets, onChange: (e) => setSecrets(e.target.checked) }),
            "Keep secret files closed (.env, .pem, .key)"
          ] }),
          limitError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-error", children: limitError }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "swarm-field-help", children: "Claude Code’s file tools won’t read or change these. Shell commands are still checked by Guard’s usual rules." })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "swarm-field-help", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { "aria-hidden": "true" }),
          " Codex can’t be kept out of folders yet. It can open what your Codex settings allow, and Guard’s usual checks still apply. Use claude to set limits, or a worktree without those files."
        ] })
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
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "submit", className: "swarm-button swarm-button--primary", disabled: busy || stale || !harness || !workspace.trim() || !goal.trim() || limitError !== null || sizeError !== null, children: [
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
