import { j as jsxRuntimeExports, c as HiMiniFolder, b as HiMiniCommandLine, d as HiMiniCircleStack, fo as HiMiniArrowUpRight } from "../guard-dashboard.js";
import { p as projectsFor, c as contextFor, s as stateLabel } from "./swarm-workspace-CVGgULVl.js";
import "./swarm-handoff-BIqKreGh.js";
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
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: cigar.available ? "swarm-context-ready" : "", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { "aria-hidden": "true" }),
                cigar.label,
                agent.context_calls > 0 ? ` · ${agent.context_calls} past calls` : ""
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
export {
  AgentMap
};
