const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunks/policy-workspace.js","assets/guard-dashboard.js","assets/index.css"])))=>i.map(i=>d[i]);
import { r as reactExports, j as jsxRuntimeExports, aB as WorkspacePageHeader, aC as __vitePreload } from "../guard-dashboard.js";
const PolicyWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./policy-workspace.js"), true ? __vite__mapDeps([0,1,2]) : void 0).then((module) => ({ default: module.PolicyWorkspace }))
);
function PolicyFallback() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-40 w-full rounded-2xl", "aria-busy": "true", "aria-live": "polite" });
}
function PolicyWorkspacePage(props) {
  const handleOpenSettings = reactExports.useCallback(() => props.onOpenSettings(), [props]);
  const handleOpenInbox = reactExports.useCallback(() => props.onOpenInbox(), [props]);
  const handleRefresh = reactExports.useCallback(() => props.onRefreshPolicies(), [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "Policy",
        title: "Remembered rules and exceptions",
        description: "See what Guard will do next time, in plain language. Remove local rules or add custom exceptions here."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyWorkspace,
      {
        policies: props.policies,
        snapshot: props.snapshot,
        onClearPolicy: props.onClearPolicy,
        onOpenSettings: handleOpenSettings,
        onOpenInbox: handleOpenInbox,
        onRefreshPolicies: handleRefresh
      }
    ) })
  ] });
}
export {
  PolicyWorkspacePage
};
