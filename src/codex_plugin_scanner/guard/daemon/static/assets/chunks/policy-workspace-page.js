const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunks/policy-workspace.js","assets/guard-dashboard.js","assets/index.css"])))=>i.map(i=>d[i]);
import { j as jsxRuntimeExports, r as reactExports, aC as __vitePreload } from "../guard-dashboard.js";
import { S as SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS } from "./supply-chain-workspace-layout.js";
const PolicyWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./policy-workspace.js"), true ? __vite__mapDeps([0,1,2]) : void 0).then((module) => ({ default: module.PolicyWorkspace }))
);
function LazyFallback() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-[200px] items-center justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-48" }) });
}
function PolicyWorkspacePage(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS} space-y-6`, "data-testid": "policy-workspace-page", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Guard" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-2xl font-semibold tracking-tight text-brand-dark", children: "Policy" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-2xl text-sm text-slate-500", children: "Remembered decisions, Guard Cloud bundle rules, and strict-mode posture for this device." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyWorkspace,
      {
        policies: props.policies,
        snapshot: props.snapshot,
        onClearPolicy: props.onClearPolicy,
        onOpenSettings: props.onOpenSettings,
        onOpenInbox: props.onOpenInbox
      }
    ) })
  ] });
}
export {
  PolicyWorkspacePage
};
