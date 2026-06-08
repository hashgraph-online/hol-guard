const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunks/supply-chain-workspace.js","assets/guard-dashboard.js","assets/index.css","assets/chunks/use-resolved-approval-gate.js","assets/chunks/runtime-overview.js","assets/chunks/audit-workspace.js","assets/chunks/policy-workspace.js","assets/chunks/feed-health-workspace.js"])))=>i.map(i=>d[i]);
import { r as reactExports, j as jsxRuntimeExports, aq as WorkspacePageHeader, ar as __vitePreload } from "../guard-dashboard.js";
const SupplyChainWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./supply-chain-workspace.js"), true ? __vite__mapDeps([0,1,2,3,4]) : void 0).then((m) => ({ default: m.SupplyChainWorkspace }))
);
const AuditWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./audit-workspace.js"), true ? __vite__mapDeps([5,1,2,3]) : void 0).then((m) => ({ default: m.AuditWorkspace }))
);
const PolicyWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./policy-workspace.js"), true ? __vite__mapDeps([6,1,2]) : void 0).then((m) => ({ default: m.PolicyWorkspace }))
);
const FeedHealthWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./feed-health-workspace.js"), true ? __vite__mapDeps([7,1,2]) : void 0).then((m) => ({ default: m.FeedHealthWorkspace }))
);
const hubTabs = [
  { value: "supply-chain", label: "Supply Chain" },
  { value: "audit", label: "Audit" },
  { value: "policy", label: "Policy" },
  { value: "feed-health", label: "Feed Health" }
];
function hubTitleForTab(tab) {
  return hubTabs.find((item) => item.value === tab)?.label ?? "Supply Chain";
}
function viewToTab(view) {
  if (view === "supply-chain" || view === "audit" || view === "policy" || view === "feed-health") {
    return view;
  }
  return "supply-chain";
}
function SupplyChainHubWorkspace(props) {
  const tab = viewToTab(props.activeView);
  const handleTabChange = reactExports.useCallback(
    (value) => {
      const path = value === "supply-chain" ? "/supply-chain" : `/${value}`;
      props.onNavigate(path);
    },
    [props.onNavigate]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "Supply chain",
        title: hubTitleForTab(tab),
        tabs: hubTabs,
        activeTab: tab,
        onTabChange: handleTabChange
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: [
      tab === "supply-chain" && /* @__PURE__ */ jsxRuntimeExports.jsx(
        SupplyChainWorkspace,
        {
          snapshot: props.snapshot,
          approvalGate: props.approvalGate,
          onGoHome: props.onGoHome,
          onRuntimeRefresh: props.onRuntimeRefresh
        }
      ),
      tab === "audit" && /* @__PURE__ */ jsxRuntimeExports.jsx(AuditWorkspace, { snapshot: props.snapshot, receipts: props.receipts, approvalGate: props.approvalGate }),
      tab === "policy" && /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyWorkspace,
        {
          policies: props.policies,
          snapshot: props.snapshot,
          onClearPolicy: props.onClearPolicy,
          onOpenSettings: props.onOpenSettings
        }
      ),
      tab === "feed-health" && /* @__PURE__ */ jsxRuntimeExports.jsx(FeedHealthWorkspace, { snapshot: props.snapshot, onOpenSettings: props.onOpenSettings })
    ] })
  ] });
}
function LazyFallback() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-[200px] items-center justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-48" }) });
}
export {
  SupplyChainHubWorkspace,
  hubTitleForTab
};
