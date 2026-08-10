import { r as reactExports, j as jsxRuntimeExports, an as HiMiniArrowLeft, Z as HiMiniLockClosed, o as HiMiniShieldCheck, ao as HiMiniArrowTopRightOnSquare, c as HiMiniChevronRight, ap as HiMiniInformationCircle, w as HiMiniXMark, J as HiMiniExclamationTriangle, aq as fetchExtensionControlApi, ar as HiMiniArrowPath, $ as HiMiniAdjustmentsHorizontal, ak as HiMiniMagnifyingGlass, l as HiMiniCheckCircle, y as HiMiniChevronDown, B as HiMiniCloud, as as commandReasonLabel, at as DEFAULT_COMMAND_ACTIVITY_FILTERS, a4 as fetchRuntimeSnapshot, d as createCommandActivityClient, f as fetchCommandActivityApi, U as HiMiniClipboardDocumentCheck, V as HiMiniClipboard, x as HiMiniChevronUp, au as buildApprovalProofCredentials, av as isApprovalProofSubmitDisabled, aw as ApprovalProofFieldInputs } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal } from "./use-resolved-approval-gate.js";
const EXTENSION_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DEFAULT_EXTENSION_DETAIL_URL_STATE = {
  tab: "overview",
  query: "",
  risk: "all",
  state: "all",
  configurable: "all",
  source: "all",
  deprecated: "all",
  type: "all",
  sort: "name",
  ruleId: null
};
function oneOf(value, allowed, fallback) {
  return value !== null && allowed.includes(value) ? value : fallback;
}
function parseExtensionRoute(pathname) {
  if (pathname === "/extensions" || pathname === "/extensions/") return { kind: "overview" };
  if (!pathname.startsWith("/extensions/")) return { kind: "invalid" };
  const encoded = pathname.slice("/extensions/".length);
  if (!encoded || encoded.includes("/")) return { kind: "invalid" };
  try {
    const decoded = decodeURIComponent(encoded).trim().toLowerCase();
    if (!EXTENSION_ID_PATTERN.test(decoded)) return { kind: "invalid" };
    return { kind: "detail", extensionId: decoded };
  } catch {
    return { kind: "invalid" };
  }
}
function readExtensionDetailUrlState(search) {
  const params = new URLSearchParams(search);
  const rawQuery = params.get("q") ?? "";
  const query = rawQuery.slice(0, 160);
  const rawRule = params.get("rule")?.trim().toLowerCase() ?? null;
  const ruleId = rawRule && RULE_ID_PATTERN.test(rawRule) ? rawRule : null;
  return {
    tab: oneOf(params.get("tab"), ["overview", "commands", "policy", "test-lab", "activity"], "overview"),
    query,
    risk: oneOf(params.get("risk"), ["all", "low", "medium", "high", "critical"], "all"),
    state: oneOf(params.get("state"), ["all", "allowed", "blocked"], "all"),
    configurable: oneOf(params.get("configurable"), ["all", "yes", "no"], "all"),
    source: oneOf(params.get("source"), ["all", "built-in", "local-admin", "signed-cloud"], "all"),
    deprecated: oneOf(params.get("deprecated"), ["all", "yes", "no"], "all"),
    type: oneOf(params.get("type"), ["all", "permission", "rule"], "all"),
    sort: oneOf(params.get("sort"), ["name", "risk", "id"], "name"),
    ruleId
  };
}
function extensionDetailSearch(state) {
  const params = new URLSearchParams();
  if (state.tab !== "overview") params.set("tab", state.tab);
  if (state.query.trim()) params.set("q", state.query.trim().slice(0, 160));
  if (state.risk !== "all") params.set("risk", state.risk);
  if (state.state !== "all") params.set("state", state.state);
  if (state.configurable !== "all") params.set("configurable", state.configurable);
  if (state.source !== "all") params.set("source", state.source);
  if (state.deprecated !== "all") params.set("deprecated", state.deprecated);
  if (state.type !== "all") params.set("type", state.type);
  if (state.sort !== "name") params.set("sort", state.sort);
  if (state.ruleId && RULE_ID_PATTERN.test(state.ruleId)) params.set("rule", state.ruleId);
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}
function extensionDetailHref(extensionId, state = DEFAULT_EXTENSION_DETAIL_URL_STATE) {
  const canonical = extensionId.trim().toLowerCase();
  if (!EXTENSION_ID_PATTERN.test(canonical)) return "/extensions";
  return `/extensions/${encodeURIComponent(canonical)}${extensionDetailSearch(state)}`;
}
function canonicalExtensionId(catalog, candidate) {
  if (!candidate) return null;
  const normalized = candidate.trim().toLowerCase();
  const direct = catalog.find((extension2) => extension2.extension_id === normalized);
  if (direct) return direct.extension_id;
  return catalog.find((extension2) => extension2.aliases.includes(normalized))?.extension_id ?? null;
}
function explicitControlState(effective, kind, targetId2) {
  const projected = kind === "extension" ? effective.projection?.extensions.find((item) => item.extension_id === targetId2)?.local_state : effective.projection?.permissions.find((item) => item.permission_id === targetId2)?.local_state;
  if (projected) return projected === "inherited" ? null : projected;
  return effective.controls.find(
    (control) => control.target.kind === kind && control.target.target_id === targetId2
  )?.state ?? null;
}
function managedExplicitControlState(effective, kind, targetId2) {
  const projected = kind === "extension" ? effective.projection?.extensions.find((item) => item.extension_id === targetId2)?.managed_state : effective.projection?.permissions.find((item) => item.permission_id === targetId2)?.managed_state;
  if (projected) return projected === "inherited" ? null : projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === kind && item.target_id === targetId2);
    if (control) return control.state;
  }
  return null;
}
function extensionEffectiveState(effective, extension2) {
  const projected = effective.projection?.extensions.find((item) => item.extension_id === extension2.extension_id);
  if (projected) return projected.effective_state === "allowed" ? "enabled" : "disabled";
  if (effective.health !== "protected") return "disabled";
  if (effective.global_lockdown) return "disabled";
  if (extension2.required) return "enabled";
  return explicitControlState(effective, "extension", extension2.extension_id) ?? "enabled";
}
function permissionEffectiveState(effective, extension2, permission2) {
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permission2.permission_id);
  if (projected) return projected.effective_state === "allowed" ? "enabled" : "disabled";
  if (extensionEffectiveState(effective, extension2) === "disabled") return "disabled";
  if (!permission2.configurable) return permission2.default_enabled ? "enabled" : "disabled";
  return explicitControlState(effective, "permission", permission2.permission_id) ?? (permission2.default_enabled ? "enabled" : "disabled");
}
function extensionStateLabel(effective, extension2) {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  if (managedExplicitControlState(effective, "extension", extension2.extension_id) !== null) return "Managed";
  if (extension2.required) return "Required";
  return extensionEffectiveState(effective, extension2) === "enabled" ? "Allowed" : "Blocked";
}
function permissionStateLabel(effective, extension2, permission2) {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  if (extensionEffectiveState(effective, extension2) === "disabled") return "Blocked";
  if (managedExplicitControlState(effective, "permission", permission2.permission_id) !== null) return "Managed";
  if (!permission2.configurable) return "Required";
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permission2.permission_id);
  const localState = projected?.local_state ?? (explicitControlState(effective, "permission", permission2.permission_id) ?? "inherited");
  const effectiveState = permissionEffectiveState(effective, extension2, permission2);
  if (localState === "inherited") return effectiveState === "enabled" ? "Inherited" : "Blocked";
  return effectiveState === "enabled" ? "Allowed" : "Blocked";
}
function controlProvenance(effective, kind, targetId2) {
  const projected = kind === "extension" ? effective.projection?.extensions.find((item) => item.extension_id === targetId2) : effective.projection?.permissions.find((item) => item.permission_id === targetId2);
  if (projected) {
    const sources2 = [];
    if (effective.global_lockdown) sources2.push("Global lockdown");
    if (projected.managed_state !== "inherited") sources2.push("Signed cloud policy");
    if (projected.local_state !== "inherited") sources2.push("Local administrator");
    if (sources2.length === 0) sources2.push("Built-in default");
    return sources2;
  }
  const sources = [];
  if (effective.global_lockdown) sources.push("Global lockdown");
  for (const layer of effective.layers) {
    if (layer.controls.some((control) => control.target_kind === kind && control.target_id === targetId2)) {
      sources.push(layer.kind === "signed-cloud" ? "Signed cloud policy" : "Local administrator");
    }
  }
  if (sources.length === 0) sources.push("Built-in default");
  return sources;
}
function permissionForRule(extension2, rule2) {
  return extension2.permissions.find((permission2) => permission2.rule_ids.includes(rule2.rule_id)) ?? null;
}
function permissionRelations(extension2, permission2) {
  const byId = new Map(extension2.permissions.map((item) => [item.permission_id, item]));
  const resolve = (ids) => ids.map((id2) => byId.get(id2)).filter((item) => Boolean(item));
  const referenced = [...permission2.dependencies, ...permission2.conflicts, ...permission2.implied_permissions];
  return {
    dependencies: resolve(permission2.dependencies),
    conflicts: resolve(permission2.conflicts),
    implied: resolve(permission2.implied_permissions),
    missing: referenced.filter((id2) => !byId.has(id2))
  };
}
const RISK_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
function queryMatch(values, query) {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;
  const haystack = values.join(" ").toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}
function filterDetailPermissions(extension2, effective, state) {
  if (state.type === "rule") return [];
  const items = extension2.permissions.filter((permission2) => {
    if (!queryMatch([permission2.label, permission2.permission_id, permission2.description, ...permission2.action_classes, ...permission2.typed_capabilities, ...permission2.rule_ids], state.query)) return false;
    if (state.risk !== "all" && permission2.risk_tier !== state.risk) return false;
    const enabled = permissionEffectiveState(effective, extension2, permission2) === "enabled";
    if (state.state === "allowed" && !enabled) return false;
    if (state.state === "blocked" && enabled) return false;
    if (state.configurable === "yes" && !permission2.configurable) return false;
    if (state.configurable === "no" && permission2.configurable) return false;
    if (state.source !== "all" && extension2.source !== state.source) return false;
    if (state.deprecated === "yes" && !permission2.deprecated) return false;
    if (state.deprecated === "no" && permission2.deprecated) return false;
    return true;
  });
  return items.sort((left, right) => {
    if (state.sort === "id") return left.permission_id.localeCompare(right.permission_id);
    if (state.sort === "risk") return RISK_RANK[right.risk_tier] - RISK_RANK[left.risk_tier] || left.label.localeCompare(right.label);
    return left.label.localeCompare(right.label);
  });
}
function filterDetailRules(extension2, effective, state) {
  if (state.type === "permission") return [];
  const permissionByRule = /* @__PURE__ */ new Map();
  for (const permission2 of extension2.permissions) {
    for (const ruleId of permission2.rule_ids) {
      if (!permissionByRule.has(ruleId)) permissionByRule.set(ruleId, permission2);
    }
  }
  const items = extension2.rules.filter((rule2) => {
    const permission2 = permissionByRule.get(rule2.rule_id) ?? null;
    if (!queryMatch([rule2.title, rule2.rule_id, rule2.description, rule2.matcher_kind, ...rule2.action_classes, ...rule2.risk_classes, ...permission2 ? [permission2.label, permission2.permission_id] : []], state.query)) return false;
    if (state.risk !== "all" && rule2.severity !== state.risk) return false;
    const enabled = permission2 ? permissionEffectiveState(effective, extension2, permission2) === "enabled" : extensionEffectiveState(effective, extension2) === "enabled";
    if (state.state === "allowed" && !enabled) return false;
    if (state.state === "blocked" && enabled) return false;
    if (state.configurable !== "all" && permission2) {
      if (state.configurable === "yes" && !permission2.configurable) return false;
      if (state.configurable === "no" && permission2.configurable) return false;
    }
    if (state.source !== "all" && extension2.source !== state.source) return false;
    const deprecated = permission2?.deprecated ?? false;
    if (state.deprecated === "yes" && !deprecated) return false;
    if (state.deprecated === "no" && deprecated) return false;
    return true;
  });
  return items.sort((left, right) => {
    if (state.sort === "id") return left.rule_id.localeCompare(right.rule_id);
    if (state.sort === "risk") return RISK_RANK[right.severity] - RISK_RANK[left.severity] || left.title.localeCompare(right.title);
    return left.title.localeCompare(right.title);
  });
}
function treatmentLabel(value) {
  const labels = {
    allow: "Allow",
    warn: "Warn",
    review: "Review",
    "require-reapproval": "Require reapproval",
    "sandbox-required": "Require sandbox",
    block: "Block",
    required: "Required",
    enforce: "Enforce",
    monitor: "Monitor",
    disabled: "Disabled"
  };
  return labels[value] ?? value.replaceAll("-", " ");
}
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])"
].join(",");
function focusableElements(root) {
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true"
  );
}
function useModalDialog(onClose, canClose = true) {
  const dialogRef = reactExports.useRef(null);
  const closeRef = reactExports.useRef(onClose);
  const canCloseRef = reactExports.useRef(canClose);
  closeRef.current = onClose;
  canCloseRef.current = canClose;
  reactExports.useEffect(() => {
    const root = dialogRef.current;
    if (!root) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const initial = focusableElements(root)[0] ?? root;
    initial.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && canCloseRef.current) {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements(root);
      if (focusable.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return dialogRef;
}
const RISK_TONE$1 = {
  critical: "border-red-200 bg-red-50 text-red-800",
  high: "border-orange-200 bg-orange-50 text-orange-800",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  low: "border-slate-200 bg-slate-50 text-slate-700"
};
const TABS = [
  { id: "overview", label: "Overview" },
  { id: "commands", label: "Commands & rules" },
  { id: "policy", label: "Policy" }
];
function Pill$1({ children, tone = "border-slate-200 bg-slate-50 text-slate-700" }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`, children });
}
function Definition({ label, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-words text-sm text-slate-900", children })
  ] });
}
function ListValue({ values, empty = "None" }) {
  return values.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: values.join(", ") }) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: empty });
}
function safeReferenceUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}
function DetailFilters(props) {
  const patch = (key, value) => props.onChange({ ...props.state, [key]: value, ruleId: null });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4", "aria-label": "Command and permission filters", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-xs font-semibold uppercase tracking-wide text-slate-500", children: [
      "Search",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { value: props.state.query, onChange: (event) => patch("query", event.target.value.slice(0, 160)), placeholder: "Rule, permission, capability…", className: "mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 text-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Risk",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.risk, onChange: (event) => patch("risk", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All risk" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "critical", children: "Critical" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "high", children: "High" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "medium", children: "Medium" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "low", children: "Low" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Effective state",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.state, onChange: (event) => patch("state", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All states" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "allowed", children: "Allowed" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "blocked", children: "Blocked" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Configurable",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.configurable, onChange: (event) => patch("configurable", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "yes", children: "Configurable" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "no", children: "Fixed" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Source",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.source, onChange: (event) => patch("source", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All sources" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "built-in", children: "Built in" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "local-admin", children: "Local admin" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "signed-cloud", children: "Signed cloud" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Deprecation",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.deprecated, onChange: (event) => patch("deprecated", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "no", children: "Current" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "yes", children: "Deprecated" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Type",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.type, onChange: (event) => patch("type", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "Rules & permissions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "rule", children: "Rules only" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "permission", children: "Permissions only" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-xs font-semibold text-slate-600", children: [
        "Sort",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { value: props.state.sort, onChange: (event) => patch("sort", event.target.value), className: "mt-1 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "name", children: "Name" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "risk", children: "Risk" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "id", children: "Canonical ID" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => props.onChange({ ...props.state, query: "", risk: "all", state: "all", configurable: "all", source: "all", deprecated: "all", type: "all", sort: "name", ruleId: null }), className: "min-h-11 self-end rounded-xl border border-slate-300 bg-white px-3 text-sm font-semibold text-slate-700 hover:bg-slate-50", children: "Clear filters" })
    ] })
  ] });
}
function PermissionInspector(props) {
  const dialogRef = useModalDialog(props.onClose);
  const relations = permissionRelations(props.extension, props.permission);
  const effectiveState = permissionEffectiveState(props.effective, props.extension, props.permission);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "permission-inspector-title", className: "fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-5 shadow-2xl focus:outline-none sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Permission" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "permission-inspector-title", className: "mt-2 text-2xl font-semibold text-slate-950", children: props.permission.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.permission.permission_id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onClose, "aria-label": "Close permission details", className: "grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-slate-600", children: props.permission.description }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill$1, { tone: RISK_TONE$1[props.permission.risk_tier], children: [
        props.permission.risk_tier,
        " baseline risk"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: permissionStateLabel(props.effective, props.extension, props.permission) }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: "Fixed" }) : null,
      props.permission.deprecated ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { tone: "border-amber-200 bg-amber-50 text-amber-800", children: "Deprecated" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7 rounded-2xl border border-slate-200 bg-slate-50 p-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Baseline and effective behavior" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Baseline floor", children: treatmentLabel(props.permission.baseline_floor) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Default", children: props.permission.default_enabled ? "Allowed" : "Blocked" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Effective", children: effectiveState === "enabled" ? "Allowed" : "Blocked" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Provenance", children: controlProvenance(props.effective, "permission", props.permission.permission_id).join(" · ") })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Capabilities and ownership" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Action classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.permission.action_classes }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Typed capabilities", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.permission.typed_capabilities, empty: "Rule-derived" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Governed rule IDs", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.permission.rule_ids }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Introduced", children: props.permission.introduced_version })
      ] }),
      props.permission.rule_ids.length > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 rounded-xl bg-blue-50 p-3 text-sm text-slate-700", children: [
        "This permission governs ",
        props.permission.rule_ids.length,
        " rules. A future policy change to this permission affects every governed rule."
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Relationships" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Depends on", children: relations.dependencies.length ? relations.dependencies.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Conflicts with", children: relations.conflicts.length ? relations.conflicts.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Implies", children: relations.implied.length ? relations.implied.map((item) => item.label).join(", ") : "None" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Replacement", children: props.permission.replacement_permission_id ?? "None" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Safer guidance" }),
      props.permission.safer_guidance.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.permission.safer_guidance.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: item }, item)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No alternate workflow is registered." }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Why this cannot be changed:" }),
        " ",
        props.permission.fixed_reason ?? "Guard marks this capability as fixed."
      ] }) : null
    ] })
  ] });
}
function RuleInspector(props) {
  const dialogRef = useModalDialog(props.onClose);
  const permission2 = permissionForRule(props.extension, props.rule);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "rule-inspector-title", className: "fixed inset-y-0 right-0 z-50 w-full max-w-xl overflow-y-auto border-l border-slate-200 bg-white p-5 shadow-2xl focus:outline-none sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Command rule" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "rule-inspector-title", className: "mt-2 text-2xl font-semibold text-slate-950", children: props.rule.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.rule.rule_id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onClose, "aria-label": "Close rule details", className: "grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-slate-600", children: props.rule.description }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill$1, { tone: RISK_TONE$1[props.rule.severity], children: [
        props.rule.severity,
        " detector severity"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill$1, { children: [
        treatmentLabel(props.rule.default_mode),
        " default"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: props.rule.matcher_kind })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-7 grid gap-5 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Governing permission", children: permission2?.label ?? "Compatibility mapping" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Permission ID", children: permission2?.permission_id ?? "None" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Rule version", children: String(props.rule.rule_version) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Risk classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.rule.risk_classes }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Action classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.rule.action_classes }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Matcher kind", children: props.rule.matcher_kind })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Safe variants" }),
      props.rule.safe_variants.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: props.rule.safe_variants.map((variant) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 p-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-slate-900", children: variant.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 text-xs text-slate-500", children: [
          variant.matcher_kind,
          " · ",
          variant.variant_id
        ] })
      ] }, variant.variant_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No explicit safe variants are registered." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-7", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: "Safer alternatives" }),
      props.rule.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.rule.safer_alternatives.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: item }, item)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No alternate workflow is registered." })
    ] }),
    props.rule.compatibility_fallback ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-7 flex gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "This compatibility fallback is still a canonical detector rule and retains its baseline facts." })
    ] }) : null
  ] });
}
function ExtensionControlCenterDetail$1(props) {
  const extensionState = extensionEffectiveState(props.effective, props.extension);
  const stateLabel = extensionStateLabel(props.effective, props.extension);
  const provenance = controlProvenance(props.effective, "extension", props.extension.extension_id);
  const permissions = reactExports.useMemo(() => filterDetailPermissions(props.extension, props.effective, props.urlState), [props.extension, props.effective, props.urlState]);
  const rules = reactExports.useMemo(() => filterDetailRules(props.extension, props.effective, props.urlState), [props.extension, props.effective, props.urlState]);
  const selectedRule = props.urlState.ruleId ? props.extension.rules.find((item) => item.rule_id === props.urlState.ruleId) ?? null : null;
  const selectedPermission = props.urlState.ruleId?.includes(".permission.") ? props.extension.permissions.find((item) => item.permission_id === props.urlState.ruleId) ?? null : null;
  const activeTab = TABS.some((item) => item.id === props.urlState.tab) ? props.urlState.tab : "overview";
  const setTab = (tab) => props.onUrlState({ ...props.urlState, tab, ruleId: tab === "commands" ? props.urlState.ruleId : null });
  const handleTabKey = (event, tab) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight" && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    const current = TABS.findIndex((item) => item.id === tab);
    const next = event.key === "Home" ? 0 : event.key === "End" ? TABS.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + TABS.length) % TABS.length;
    setTab(TABS[next].id);
    requestAnimationFrame(() => document.getElementById(`extension-tab-${TABS[next].id}`)?.focus());
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { "data-testid": "extension-control-center-detail", className: "mx-auto w-full max-w-7xl px-4 pb-10 pt-5 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { "aria-label": "Breadcrumb", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onBack, className: "inline-flex min-h-11 items-center gap-2 rounded-lg px-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 hover:text-brand-blue", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4" }),
      "Protections"
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-3 rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] sm:p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.2em] text-brand-blue", children: "Extension control center" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-3xl font-semibold tracking-tight text-slate-950", children: props.extension.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-xs text-slate-500", children: props.extension.extension_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 max-w-3xl text-sm leading-6 text-slate-600", children: props.extension.description })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { tone: extensionState === "enabled" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-300 bg-slate-100 text-slate-700", children: stateLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: props.extension.required ? "Required" : "Optional" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: props.extension.source }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill$1, { children: [
            "v",
            props.extension.version
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs font-semibold uppercase text-slate-500", children: "Authority" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 font-semibold text-slate-950", children: props.effective.health })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: props.extension.permission_count }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Permissions" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: props.extension.rule_count }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Rules" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs font-semibold uppercase text-slate-500", children: "Provenance" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 text-sm font-semibold text-slate-950", children: provenance.join(" · ") })
        ] })
      ] }),
      props.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "mt-5 flex gap-3 rounded-xl border border-slate-300 bg-slate-100 p-4 text-sm text-slate-800", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Global lockdown controls this capability." }),
          " Matching actions remain blocked regardless of optional local settings."
        ] })
      ] }) : null,
      props.onBroadControl && !props.extension.required && props.effective.health === "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onBroadControl, className: "mt-5 min-h-11 rounded-xl border border-brand-blue/25 bg-white px-4 text-sm font-semibold text-brand-blue hover:bg-blue-50", children: "Review broad capability control" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6 overflow-x-auto border-b border-slate-200", role: "tablist", "aria-label": "Extension detail sections", children: TABS.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { id: `extension-tab-${item.id}`, type: "button", role: "tab", "aria-selected": activeTab === item.id, "aria-controls": item.id === "policy" && props.externalPolicyPanelId ? props.externalPolicyPanelId : `extension-panel-${item.id}`, onKeyDown: (event) => handleTabKey(event, item.id), onClick: () => setTab(item.id), className: `min-h-11 border-b-2 px-4 py-3 text-sm font-semibold whitespace-nowrap focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${activeTab === item.id ? "border-brand-blue text-brand-blue" : "border-transparent text-slate-500 hover:text-slate-900"}`, children: item.label }, item.id)) }),
    activeTab !== props.urlState.tab ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600", children: "This older link points to a section that is not available in this build. Showing Overview instead." }) : null,
    activeTab === "overview" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-overview", role: "tabpanel", "aria-labelledby": "extension-tab-overview", className: "mt-6 grid gap-5 lg:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 text-brand-blue" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Canonical coverage" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Action classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.action_classes }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Risk classes", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.risk_classes }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Executables", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.executables, empty: "Registry matcher metadata" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Project markers", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.project_markers }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Ecosystems", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.ecosystem_ids }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Aliases", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.aliases }) })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Relationships and provenance" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Depends on", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.dependencies }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Conflicts with", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ListValue, { values: props.extension.conflicts }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Delegated protection", children: props.extension.delegated_protection ?? "None" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Catalog digest", children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.catalogDigest }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Effective state", children: stateLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Policy provenance", children: provenance.join(" · ") })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 lg:col-span-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: "Safer alternatives" }),
        props.extension.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 list-disc space-y-2 pl-5 text-sm text-slate-600", children: props.extension.safer_alternatives.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: item }, item)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "No extension-level alternative is registered." }),
        props.extension.reference_urls.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 border-t border-slate-100 pt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-slate-900", children: "References" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex flex-wrap gap-2", children: props.extension.reference_urls.map((value) => {
            const href = safeReferenceUrl(value);
            return href ? /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href, target: "_blank", rel: "noopener noreferrer", referrerPolicy: "no-referrer", className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-3 text-sm font-semibold text-brand-blue", children: [
              "Open reference ",
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4" })
            ] }, value) : null;
          }) })
        ] }) : null
      ] })
    ] }) : null,
    activeTab === "commands" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-commands", role: "tabpanel", "aria-labelledby": "extension-tab-commands", className: "mt-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(DetailFilters, { state: props.urlState, onChange: props.onUrlState }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", "aria-live": "polite", className: "mt-3 text-sm text-slate-500", children: [
        "Showing ",
        permissions.length,
        " permissions and ",
        rules.length,
        " rules."
      ] }),
      props.urlState.type !== "rule" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Permissions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 grid gap-3 lg:grid-cols-2", children: permissions.map((permission2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => props.onUrlState({ ...props.urlState, ruleId: permission2.permission_id }), className: "min-h-11 rounded-2xl border border-slate-200 bg-white p-4 text-left hover:border-blue-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-slate-950", children: permission2.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { tone: RISK_TONE$1[permission2.risk_tier], children: permission2.risk_tier }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: permissionStateLabel(props.effective, props.extension, permission2) }),
            !permission2.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: "Fixed" }) : null
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: permission2.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-slate-500", children: [
            "Baseline floor ",
            treatmentLabel(permission2.baseline_floor),
            " · ",
            permission2.rule_ids.length,
            " governed rule",
            permission2.rule_ids.length === 1 ? "" : "s"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-[11px] text-slate-400", children: permission2.permission_id })
        ] }, permission2.permission_id)) }),
        permissions.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 rounded-2xl border border-dashed border-slate-300 p-6 text-sm text-slate-500", children: "No permissions match these filters." }) : null
      ] }) : null,
      props.urlState.type !== "permission" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-8", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Commands and rules" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 hidden overflow-x-auto rounded-2xl border border-slate-200 bg-white md:block", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "min-w-full text-left text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "bg-slate-50 text-xs uppercase tracking-wide text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "State" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Rule" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Severity / default" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Matcher" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: "Permission" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Open" }) })
          ] }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: rules.map((rule2) => {
            const permission2 = permissionForRule(props.extension, rule2);
            const allowed = permission2 ? permissionEffectiveState(props.effective, props.extension, permission2) === "enabled" : extensionState === "enabled";
            return /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3 font-semibold text-slate-700", children: allowed ? "Allowed" : "Blocked" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "max-w-md px-4 py-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-semibold text-slate-950", children: rule2.title }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "text-[11px] text-slate-500", children: rule2.rule_id })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "px-4 py-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { tone: RISK_TONE$1[rule2.severity], children: rule2.severity }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 text-xs text-slate-500", children: treatmentLabel(rule2.default_mode) })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3 text-slate-600", children: rule2.matcher_kind }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3 text-slate-600", children: permission2?.label ?? "Compatibility" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", "aria-label": `Inspect rule ${rule2.title}`, onClick: () => props.onUrlState({ ...props.urlState, ruleId: rule2.rule_id }), className: "grid size-11 place-items-center rounded-xl text-brand-blue hover:bg-blue-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5" }) }) })
            ] }, rule2.rule_id);
          }) })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 grid gap-3 md:hidden", children: rules.map((rule2) => {
          const permission2 = permissionForRule(props.extension, rule2);
          const allowed = permission2 ? permissionEffectiveState(props.effective, props.extension, permission2) === "enabled" : extensionState === "enabled";
          return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => props.onUrlState({ ...props.urlState, ruleId: rule2.rule_id }), className: "rounded-2xl border border-slate-200 bg-white p-4 text-left", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { children: allowed ? "Allowed" : "Blocked" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Pill$1, { tone: RISK_TONE$1[rule2.severity], children: rule2.severity })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 font-semibold text-slate-950", children: rule2.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-[11px] text-slate-500", children: rule2.rule_id }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-slate-500", children: [
              rule2.matcher_kind,
              " · ",
              permission2?.label ?? "Compatibility"
            ] })
          ] }, rule2.rule_id);
        }) }),
        rules.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 rounded-2xl border border-dashed border-slate-300 p-6 text-sm text-slate-500", children: "No rules match these filters." }) : null
      ] }) : null
    ] }) : null,
    activeTab === "policy" && !props.externalPolicyPanelId ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-policy", role: "tabpanel", "aria-labelledby": "extension-tab-policy", className: "mt-6 rounded-3xl border border-slate-200 bg-white p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Policy" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm text-slate-600", children: "This Batch 1 view is read-only below the existing broad capability control. Permission editing and semantic preview arrive in the next implementation batch." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Effective capability", children: stateLabel }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Authority", children: props.effective.health }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Provenance", children: provenance.join(" · ") }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Definition, { label: "Global lockdown", children: props.effective.global_lockdown ? "Active" : "Off" })
      ] })
    ] }) : null,
    activeTab === "test-lab" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-test-lab", role: "tabpanel", "aria-labelledby": "extension-tab-test-lab", className: "mt-6 rounded-3xl border border-slate-200 bg-white p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Test Lab" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex gap-3 rounded-xl bg-blue-50 p-4 text-sm text-slate-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0 text-brand-blue" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Side-effect-free command simulation is delivered in Batch 3. This placeholder never accepts or executes command text." })
      ] }),
      props.urlState.ruleId ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-sm text-slate-600", children: [
        "Selected rule: ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: props.urlState.ruleId })
      ] }) : null
    ] }) : null,
    activeTab === "activity" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-panel-activity", role: "tabpanel", "aria-labelledby": "extension-tab-activity", className: "mt-6 rounded-3xl border border-slate-200 bg-white p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-slate-950", children: "Activity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Extension-scoped decision and policy history arrives in Batch 4. No activity is synthesized in the dashboard." })
    ] }) : null,
    selectedPermission ? /* @__PURE__ */ jsxRuntimeExports.jsx(PermissionInspector, { effective: props.effective, extension: props.extension, permission: selectedPermission, onClose: () => props.onUrlState({ ...props.urlState, ruleId: null }) }) : null,
    selectedRule ? /* @__PURE__ */ jsxRuntimeExports.jsx(RuleInspector, { extension: props.extension, rule: selectedRule, onClose: () => props.onUrlState({ ...props.urlState, ruleId: null }), onTest: () => props.onUrlState({ ...props.urlState, tab: "test-lab", ruleId: selectedRule.rule_id }) }) : null
  ] });
}
const DIGEST$2 = /^[a-f0-9]{64}$/;
const EXTENSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_EXTENSIONS = 512;
const MAX_PERMISSIONS = 4096;
const MAX_REASONS = 64;
function record$2(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid ${label}`);
  return value;
}
function text(value, label, max = 256) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid ${label}`);
  return value;
}
function integer$2(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${label}`);
  return value;
}
function boolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`Invalid ${label}`);
  return value;
}
function enumValue$1(value, label, values) {
  const candidate = text(value, label, 64);
  if (!values.includes(candidate)) throw new Error(`Invalid ${label}`);
  return candidate;
}
function id$1(value, label, pattern) {
  const candidate = text(value, label).toLowerCase();
  if (!pattern.test(candidate)) throw new Error(`Invalid ${label}`);
  return candidate;
}
function reasons(value, label) {
  if (!Array.isArray(value) || value.length > MAX_REASONS) throw new Error(`Invalid ${label}`);
  return value.map((item, index) => text(item, `${label}[${index}]`, 128));
}
function extensionItem(value, label) {
  const item = record$2(value, label);
  return {
    extension_id: id$1(item.extension_id, `${label}.extension_id`, EXTENSION_ID$1),
    effective_state: enumValue$1(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"]),
    local_state: enumValue$1(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"]),
    managed_state: enumValue$1(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"]),
    required: boolean(item.required, `${label}.required`),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`)
  };
}
function permissionItem(value, label) {
  const item = record$2(value, label);
  return {
    permission_id: id$1(item.permission_id, `${label}.permission_id`, PERMISSION_ID$1),
    extension_id: id$1(item.extension_id, `${label}.extension_id`, EXTENSION_ID$1),
    effective_state: enumValue$1(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"]),
    local_state: enumValue$1(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"]),
    managed_state: enumValue$1(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"]),
    configurable: boolean(item.configurable, `${label}.configurable`),
    fixed_reason: item.fixed_reason === null ? null : text(item.fixed_reason, `${label}.fixed_reason`, 2048),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`)
  };
}
function normalizeEffectiveExtensionControlProjection(value) {
  const root = record$2(value, "extension projection");
  const schemaVersion = text(root.schema_version, "projection.schema_version", 128);
  if (schemaVersion !== "guard.daemon.extension-control-projection.v1") throw new Error("Invalid extension projection schema");
  const digest2 = text(root.catalog_digest, "projection.catalog_digest", 64);
  if (!DIGEST$2.test(digest2)) throw new Error("Invalid projection.catalog_digest");
  if (!Array.isArray(root.extensions) || root.extensions.length > MAX_EXTENSIONS) throw new Error("Invalid projection.extensions");
  if (!Array.isArray(root.permissions) || root.permissions.length > MAX_PERMISSIONS) throw new Error("Invalid projection.permissions");
  const extensions = root.extensions.map((item, index) => extensionItem(item, `projection.extensions[${index}]`));
  const permissions = root.permissions.map((item, index) => permissionItem(item, `projection.permissions[${index}]`));
  if (new Set(extensions.map((item) => item.extension_id)).size !== extensions.length) throw new Error("Duplicate projection extension ID");
  if (new Set(permissions.map((item) => item.permission_id)).size !== permissions.length) throw new Error("Duplicate projection permission ID");
  return {
    schema_version: "guard.daemon.extension-control-projection.v1",
    revision: integer$2(root.revision, "projection.revision"),
    catalog_digest: digest2,
    health: enumValue$1(root.health, "projection.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"]),
    extensions,
    permissions
  };
}
const EXTENSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DIGEST$1 = /^[a-f0-9]{64}$/;
const VERSION = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;
const EXTENSION_CLIENT_LIMITS = Object.freeze({
  extensions: 256,
  rulesPerExtension: 1024,
  permissionsPerExtension: 1024,
  relationshipIds: 1024,
  controls: 4096,
  layers: 16,
  failures: 256,
  stringLength: 8192
});
class ExtensionControlProtocolError extends Error {
  constructor(message) {
    super(`Invalid extension-control response: ${message}`);
  }
}
function record$1(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ExtensionControlProtocolError(`${label} must be an object`);
  }
  return value;
}
function array(value, label, max) {
  if (!Array.isArray(value)) throw new ExtensionControlProtocolError(`${label} must be an array`);
  if (value.length > max) throw new ExtensionControlProtocolError(`${label} exceeds ${max} items`);
  return value;
}
function string$1(value, label, allowEmpty = false) {
  if (typeof value !== "string") throw new ExtensionControlProtocolError(`${label} must be a string`);
  if (value.length > EXTENSION_CLIENT_LIMITS.stringLength) throw new ExtensionControlProtocolError(`${label} is too long`);
  if (!allowEmpty && value.trim().length === 0) throw new ExtensionControlProtocolError(`${label} is required`);
  return value;
}
function optionalString(value, label) {
  if (value === null) return null;
  return string$1(value, label);
}
function bool$1(value, label) {
  if (typeof value !== "boolean") throw new ExtensionControlProtocolError(`${label} must be boolean`);
  return value;
}
function integer$1(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new ExtensionControlProtocolError(`${label} must be an integer >= ${min}`);
  }
  return value;
}
function enumValue(value, label, values) {
  const candidate = string$1(value, label);
  if (!values.includes(candidate)) throw new ExtensionControlProtocolError(`${label} has unsupported value`);
  return candidate;
}
function id(value, label, pattern) {
  const candidate = string$1(value, label).trim().toLowerCase();
  if (!pattern.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not canonical`);
  return candidate;
}
function digest$1(value, label) {
  const candidate = string$1(value, label).trim().toLowerCase();
  if (!DIGEST$1.test(candidate)) throw new ExtensionControlProtocolError(`${label} must be a SHA-256 digest`);
  return candidate;
}
function version(value, label) {
  const candidate = string$1(value, label);
  if (!VERSION.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not a semantic implementation version`);
  return candidate;
}
function stringList(value, label, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  return array(value, label, max).map((item, index) => string$1(item, `${label}[${index}]`));
}
function idList$1(value, label, pattern, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  const items = array(value, label, max).map((item, index) => id(item, `${label}[${index}]`, pattern));
  if (new Set(items).size !== items.length) throw new ExtensionControlProtocolError(`${label} contains duplicates`);
  return items;
}
function safeVariant(value, label) {
  const item = record$1(value, label);
  return {
    variant_id: string$1(item.variant_id, `${label}.variant_id`),
    title: string$1(item.title, `${label}.title`),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`)
  };
}
function rule(value, extensionId, label) {
  const item = record$1(value, label);
  const ruleId = id(item.rule_id, `${label}.rule_id`, RULE_ID);
  if (!ruleId.startsWith(`${extensionId}.`)) throw new ExtensionControlProtocolError(`${label}.rule_id belongs to another extension`);
  const rawVersion = item.rule_version;
  if (!(typeof rawVersion === "string" || Number.isSafeInteger(rawVersion))) {
    throw new ExtensionControlProtocolError(`${label}.rule_version must be string or integer`);
  }
  return {
    rule_id: ruleId,
    rule_version: rawVersion,
    title: string$1(item.title, `${label}.title`),
    description: string$1(item.description, `${label}.description`),
    severity: enumValue(item.severity, `${label}.severity`, ["low", "medium", "high", "critical"]),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    default_mode: enumValue(item.default_mode, `${label}.default_mode`, ["required", "enforce", "review", "monitor", "disabled"]),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`),
    safe_variants: array(item.safe_variants, `${label}.safe_variants`, EXTENSION_CLIENT_LIMITS.relationshipIds).map((entry, index) => safeVariant(entry, `${label}.safe_variants[${index}]`)),
    compatibility_fallback: bool$1(item.compatibility_fallback, `${label}.compatibility_fallback`)
  };
}
function permission(value, extensionId, label) {
  const item = record$1(value, label);
  const permissionId = id(item.permission_id, `${label}.permission_id`, PERMISSION_ID);
  const owner = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  if (owner !== extensionId || !permissionId.startsWith(`${extensionId}.permission.`)) {
    throw new ExtensionControlProtocolError(`${label} belongs to another extension`);
  }
  const replacement = item.replacement_permission_id === null ? null : id(item.replacement_permission_id, `${label}.replacement_permission_id`, PERMISSION_ID);
  return {
    permission_id: permissionId,
    schema_version: integer$1(item.schema_version, `${label}.schema_version`, 1),
    extension_id: owner,
    implementation_version: version(item.implementation_version, `${label}.implementation_version`),
    label: string$1(item.label, `${label}.label`),
    description: string$1(item.description, `${label}.description`),
    risk_tier: enumValue(item.risk_tier, `${label}.risk_tier`, ["low", "medium", "high", "critical"]),
    baseline_floor: enumValue(item.baseline_floor, `${label}.baseline_floor`, ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"]),
    default_enabled: bool$1(item.default_enabled, `${label}.default_enabled`),
    configurable: bool$1(item.configurable, `${label}.configurable`),
    fixed_reason: optionalString(item.fixed_reason, `${label}.fixed_reason`),
    typed_capabilities: stringList(item.typed_capabilities, `${label}.typed_capabilities`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    rule_ids: idList$1(item.rule_ids, `${label}.rule_ids`, RULE_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, PERMISSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, PERMISSION_ID),
    implied_permissions: idList$1(item.implied_permissions, `${label}.implied_permissions`, PERMISSION_ID),
    introduced_version: version(item.introduced_version, `${label}.introduced_version`),
    deprecated: bool$1(item.deprecated, `${label}.deprecated`),
    replacement_permission_id: replacement,
    safer_guidance: stringList(item.safer_guidance, `${label}.safer_guidance`)
  };
}
function extension(value, label) {
  const item = record$1(value, label);
  const extensionId = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  const rules = array(item.rules, `${label}.rules`, EXTENSION_CLIENT_LIMITS.rulesPerExtension).map((entry, index) => rule(entry, extensionId, `${label}.rules[${index}]`));
  const permissions = array(item.permissions, `${label}.permissions`, EXTENSION_CLIENT_LIMITS.permissionsPerExtension).map((entry, index) => permission(entry, extensionId, `${label}.permissions[${index}]`));
  const ruleIds = rules.map((entry) => entry.rule_id);
  const permissionIds = permissions.map((entry) => entry.permission_id);
  if (new Set(ruleIds).size !== ruleIds.length) throw new ExtensionControlProtocolError(`${label}.rules contains duplicate rule IDs`);
  if (new Set(permissionIds).size !== permissionIds.length) throw new ExtensionControlProtocolError(`${label}.permissions contains duplicate permission IDs`);
  const knownRules = new Set(ruleIds);
  for (const spec of permissions) {
    for (const ruleId of spec.rule_ids) {
      if (!knownRules.has(ruleId)) throw new ExtensionControlProtocolError(`${label} permission references unknown rule ${ruleId}`);
    }
  }
  const ruleCount = integer$1(item.rule_count, `${label}.rule_count`);
  const permissionCount = integer$1(item.permission_count, `${label}.permission_count`);
  if (ruleCount !== rules.length || permissionCount !== permissions.length) {
    throw new ExtensionControlProtocolError(`${label} count metadata does not match payload`);
  }
  return {
    schema_version: integer$1(item.schema_version, `${label}.schema_version`, 1),
    extension_id: extensionId,
    name: string$1(item.name, `${label}.name`),
    description: string$1(item.description, `${label}.description`),
    enabled: bool$1(item.enabled, `${label}.enabled`),
    required: bool$1(item.required, `${label}.required`),
    source: enumValue(item.source, `${label}.source`, ["built-in", "local-admin", "signed-cloud"]),
    version: version(item.version, `${label}.version`),
    aliases: idList$1(item.aliases, `${label}.aliases`, EXTENSION_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, EXTENSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, EXTENSION_ID),
    delegated_protection: optionalString(item.delegated_protection, `${label}.delegated_protection`),
    ecosystem_ids: stringList(item.ecosystem_ids, `${label}.ecosystem_ids`),
    executables: stringList(item.executables, `${label}.executables`),
    project_markers: stringList(item.project_markers, `${label}.project_markers`),
    reference_urls: stringList(item.reference_urls, `${label}.reference_urls`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    rule_count: ruleCount,
    rules,
    permission_count: permissionCount,
    permissions
  };
}
function controlLayer(value, label) {
  const item = record$1(value, label);
  const controls = array(item.controls, `${label}.controls`, EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$1(entry, `${label}.controls[${index}]`);
    const kind = enumValue(raw.target_kind, `${label}.controls[${index}].target_kind`, ["extension", "permission"]);
    return {
      target_kind: kind,
      target_id: id(raw.target_id, `${label}.controls[${index}].target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID),
      state: enumValue(raw.state, `${label}.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target_kind}:${control.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError(`${label}.controls contains duplicate targets`);
  return {
    schema_version: string$1(item.schema_version, `${label}.schema_version`),
    kind: enumValue(item.kind, `${label}.kind`, ["local-admin", "signed-cloud"]),
    catalog_digest: digest$1(item.catalog_digest, `${label}.catalog_digest`),
    global_lockdown: bool$1(item.global_lockdown, `${label}.global_lockdown`),
    controls
  };
}
function normalizeExtensionCatalog(value) {
  const root = record$1(value, "catalog");
  const extensions = array(root.extensions, "catalog.extensions", EXTENSION_CLIENT_LIMITS.extensions).map((entry, index) => extension(entry, `catalog.extensions[${index}]`));
  const ids = extensions.map((entry) => entry.extension_id);
  if (new Set(ids).size !== ids.length) throw new ExtensionControlProtocolError("catalog.extensions contains duplicate extension IDs");
  const limits = root.limits === void 0 ? void 0 : record$1(root.limits, "catalog.limits");
  return {
    schema_version: string$1(root.schema_version, "catalog.schema_version"),
    control_schema_version: root.control_schema_version === void 0 ? void 0 : string$1(root.control_schema_version, "catalog.control_schema_version"),
    catalog_digest: digest$1(root.catalog_digest, "catalog.catalog_digest"),
    extensions,
    limits: limits === void 0 ? void 0 : {
      max_body_bytes: limits.max_body_bytes === void 0 ? void 0 : integer$1(limits.max_body_bytes, "catalog.limits.max_body_bytes", 1),
      max_controls: limits.max_controls === void 0 ? void 0 : integer$1(limits.max_controls, "catalog.limits.max_controls", 1),
      max_observations: limits.max_observations === void 0 ? void 0 : integer$1(limits.max_observations, "catalog.limits.max_observations", 1)
    }
  };
}
function normalizeEffectiveExtensionControls(value) {
  const root = record$1(value, "effective");
  const controls = array(root.controls, "effective.controls", EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$1(entry, `effective.controls[${index}]`);
    const target2 = record$1(raw.target, `effective.controls[${index}].target`);
    const kind = enumValue(target2.kind, `effective.controls[${index}].target.kind`, ["extension", "permission"]);
    return {
      target: {
        kind,
        target_id: id(target2.target_id, `effective.controls[${index}].target.target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID)
      },
      state: enumValue(raw.state, `effective.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target.kind}:${control.target.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError("effective.controls contains duplicate targets");
  const layers = array(root.layers, "effective.layers", EXTENSION_CLIENT_LIMITS.layers).map((entry, index) => controlLayer(entry, `effective.layers[${index}]`));
  const failures = array(root.failures, "effective.failures", EXTENSION_CLIENT_LIMITS.failures).map((entry, index) => {
    const raw = record$1(entry, `effective.failures[${index}]`);
    return {
      code: string$1(raw.code, `effective.failures[${index}].code`),
      detail: raw.detail === void 0 ? void 0 : string$1(raw.detail, `effective.failures[${index}].detail`, true),
      layer_kind: raw.layer_kind === void 0 ? void 0 : string$1(raw.layer_kind, `effective.failures[${index}].layer_kind`)
    };
  });
  return {
    schema_version: string$1(root.schema_version, "effective.schema_version"),
    health: enumValue(root.health, "effective.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"]),
    revision: integer$1(root.revision, "effective.revision"),
    catalog_digest: digest$1(root.catalog_digest, "effective.catalog_digest"),
    global_lockdown: bool$1(root.global_lockdown, "effective.global_lockdown"),
    controls,
    layers,
    failures,
    projection: root.projection === void 0 ? void 0 : normalizeEffectiveExtensionControlProjection(root.projection)
  };
}
const DIGEST = /^[a-f0-9]{64}$/;
const TARGET_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_CHANGED_TARGETS = 4096;
const MAX_AFFECTED_IDS = 4096;
const MAX_WARNINGS = 64;
const MAX_TEXT = 8192;
function record(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid extension-control ${label}: expected object`);
  return value;
}
function string(value, label, max = MAX_TEXT) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function bool(value, label) {
  if (typeof value !== "boolean") throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function digest(value, label) {
  const candidate = string(value, label, 64);
  if (!DIGEST.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}
function targetId(value, label) {
  const candidate = string(value, label, 256);
  if (!TARGET_ID.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}
function boundedArray(value, label, max) {
  if (!Array.isArray(value) || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function idList(value, label) {
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => targetId(item, `${label}[${index}]`));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate IDs`);
  return items;
}
function optionalIdList(value, label) {
  return value === void 0 ? void 0 : idList(value, label);
}
function optionalStringList(value, label) {
  if (value === void 0) return void 0;
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => string(item, `${label}[${index}]`, 128));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate values`);
  return items;
}
function warning(value, label) {
  const item = record(value, label);
  return {
    code: string(item.code, `${label}.code`, 128),
    message: string(item.message, `${label}.message`, 1024),
    ...item.target_id === void 0 ? {} : { target_id: targetId(item.target_id, `${label}.target_id`) },
    ...item.count === void 0 ? {} : { count: integer(item.count, `${label}.count`) }
  };
}
function target(value, label) {
  const item = record(value, label);
  const rawTarget = record(item.target, `${label}.target`);
  const kind = string(rawTarget.kind, `${label}.target.kind`, 32);
  if (kind !== "extension" && kind !== "permission") throw new Error(`Invalid extension-control ${label}.target.kind`);
  const beforeExplicit = string(item.before_explicit, `${label}.before_explicit`, 32);
  const afterExplicit = string(item.after_explicit, `${label}.after_explicit`, 32);
  if (!["inherited", "enabled", "disabled"].includes(beforeExplicit) || !["inherited", "enabled", "disabled"].includes(afterExplicit)) throw new Error(`Invalid extension-control ${label} explicit state`);
  const beforeEffective = string(item.before_effective, `${label}.before_effective`, 32);
  const afterEffective = string(item.after_effective, `${label}.after_effective`, 32);
  if (!["allowed", "blocked"].includes(beforeEffective) || !["allowed", "blocked"].includes(afterEffective)) throw new Error(`Invalid extension-control ${label} effective state`);
  const affectedExtensionIds = optionalIdList(item.affected_extension_ids, `${label}.affected_extension_ids`);
  const dependencyPermissionIds = optionalIdList(item.dependency_permission_ids, `${label}.dependency_permission_ids`);
  const impliedPermissionIds = optionalIdList(item.implied_permission_ids, `${label}.implied_permission_ids`);
  const conflictPermissionIds = optionalIdList(item.conflict_permission_ids, `${label}.conflict_permission_ids`);
  const provenance = optionalStringList(item.provenance, `${label}.provenance`);
  return {
    target: { kind, target_id: targetId(rawTarget.target_id, `${label}.target.target_id`) },
    extension_id: targetId(item.extension_id, `${label}.extension_id`),
    label: string(item.label, `${label}.label`, 512),
    before_explicit: beforeExplicit,
    after_explicit: afterExplicit,
    before_effective: beforeEffective,
    after_effective: afterEffective,
    affected_permission_ids: idList(item.affected_permission_ids, `${label}.affected_permission_ids`),
    affected_rule_ids: idList(item.affected_rule_ids, `${label}.affected_rule_ids`),
    ...affectedExtensionIds === void 0 ? {} : { affected_extension_ids: affectedExtensionIds },
    ...dependencyPermissionIds === void 0 ? {} : { dependency_permission_ids: dependencyPermissionIds },
    ...impliedPermissionIds === void 0 ? {} : { implied_permission_ids: impliedPermissionIds },
    ...conflictPermissionIds === void 0 ? {} : { conflict_permission_ids: conflictPermissionIds },
    ...provenance === void 0 ? {} : { provenance },
    warnings: boundedArray(item.warnings, `${label}.warnings`, MAX_WARNINGS).map((entry, index) => warning(entry, `${label}.warnings[${index}]`)),
    ...item.extension_name === void 0 ? {} : { extension_name: string(item.extension_name, `${label}.extension_name`, 512) },
    ...item.baseline_risk === void 0 ? {} : { baseline_risk: string(item.baseline_risk, `${label}.baseline_risk`, 32) },
    ...item.baseline_floor === void 0 ? {} : { baseline_floor: string(item.baseline_floor, `${label}.baseline_floor`, 32) }
  };
}
function normalizeExtensionSemanticPreview(value) {
  const root = record(value, "semantic preview");
  if (string(root.schema_version, "semantic_preview.schema_version", 128) !== "guard.daemon.extension-control-semantic-preview.v1") throw new Error("Invalid extension-control semantic preview schema");
  const lockdown = record(root.global_lockdown, "semantic_preview.global_lockdown");
  const summary = record(root.summary, "semantic_preview.summary");
  const changedTargets = boundedArray(root.changed_targets, "semantic_preview.changed_targets", MAX_CHANGED_TARGETS).map((entry, index) => target(entry, `semantic_preview.changed_targets[${index}]`));
  const changedTargetCount = integer(root.changed_target_count, "semantic_preview.changed_target_count");
  if (changedTargetCount !== changedTargets.length) throw new Error("Invalid extension-control semantic preview target count");
  return {
    schema_version: "guard.daemon.extension-control-semantic-preview.v1",
    global_lockdown: {
      before: bool(lockdown.before, "semantic_preview.global_lockdown.before"),
      after: bool(lockdown.after, "semantic_preview.global_lockdown.after"),
      changed: bool(lockdown.changed, "semantic_preview.global_lockdown.changed")
    },
    changed_target_count: changedTargetCount,
    affected_permission_count: integer(root.affected_permission_count, "semantic_preview.affected_permission_count"),
    affected_rule_count: integer(root.affected_rule_count, "semantic_preview.affected_rule_count"),
    changed_targets: changedTargets,
    ...root.approval_required === void 0 ? {} : { approval_required: bool(root.approval_required, "semantic_preview.approval_required") },
    summary: {
      newly_blocked_permissions: integer(summary.newly_blocked_permissions, "semantic_preview.summary.newly_blocked_permissions"),
      newly_allowed_permissions: integer(summary.newly_allowed_permissions, "semantic_preview.summary.newly_allowed_permissions"),
      effective_change_count: integer(summary.effective_change_count, "semantic_preview.summary.effective_change_count")
    }
  };
}
function normalizeExtensionMutationPreview(value) {
  const root = record(value, "mutation preview");
  return {
    schema_version: string(root.schema_version, "preview.schema_version", 128),
    previous_revision: integer(root.previous_revision, "preview.previous_revision"),
    next_revision: integer(root.next_revision, "preview.next_revision"),
    catalog_digest: digest(root.catalog_digest, "preview.catalog_digest"),
    canonical_diff_digest: digest(root.canonical_diff_digest, "preview.canonical_diff_digest"),
    global_lockdown: bool(root.global_lockdown, "preview.global_lockdown"),
    controls: integer(root.controls, "preview.controls"),
    semantic_preview: normalizeExtensionSemanticPreview(root.semantic_preview),
    ...root.proof_id === void 0 ? {} : { proof_id: string(root.proof_id, "preview.proof_id", 256) }
  };
}
function normalizeExtensionMutationApply(value) {
  const root = record(value, "mutation apply");
  if (string(root.status, "apply.status", 32) !== "applied") throw new Error("Invalid extension-control apply status");
  return {
    schema_version: string(root.schema_version, "apply.schema_version", 128),
    status: "applied",
    revision: integer(root.revision, "apply.revision"),
    catalog_digest: digest(root.catalog_digest, "apply.catalog_digest")
  };
}
class ExtensionControlApiError extends Error {
  constructor(message, status, code, recoveryAction) {
    super(message);
    this.status = status;
    this.code = code;
    this.recoveryAction = recoveryAction;
  }
  status;
  code;
  recoveryAction;
}
async function request(path, init) {
  const response = await fetchExtensionControlApi(path, init);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ExtensionControlApiError(`Guard returned invalid JSON (${response.status})`, response.status);
  }
  if (!response.ok) {
    const error = typeof payload === "object" && payload !== null ? payload : {};
    throw new ExtensionControlApiError(
      typeof error.error === "string" ? error.error : `Request failed (${response.status})`,
      response.status,
      typeof error.error === "string" ? error.error : void 0,
      typeof error.recovery === "object" && error.recovery !== null && typeof error.recovery.action === "string" ? error.recovery.action : void 0
    );
  }
  return payload;
}
async function fetchExtensionCatalog() {
  return normalizeExtensionCatalog(await request("/v1/extension-controls/catalog"));
}
async function fetchEffectiveExtensionControls() {
  const raw = await request("/v1/extension-controls/effective");
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return normalized;
  const projectionValue = raw.projection;
  if (projectionValue === void 0) return normalized;
  const projection = normalizeEffectiveExtensionControlProjection(projectionValue);
  if (projection.revision !== normalized.revision || projection.catalog_digest !== normalized.catalog_digest || projection.health !== normalized.health) {
    throw new ExtensionControlApiError("Guard returned an inconsistent extension-control projection", 502);
  }
  return { ...normalized, projection };
}
async function recoverExtensionControlAuthority(credentials) {
  const raw = await request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && raw.projection !== void 0) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection(raw.projection) };
  }
  return normalized;
}
async function acknowledgeDegradedExtensionControlAuthority(credentials) {
  const raw = await request("/v1/extension-controls/acknowledge-degraded", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && raw.projection !== void 0) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection(raw.projection) };
  }
  return normalized;
}
async function previewExtensionMutation(payload) {
  try {
    return normalizeExtensionMutationPreview(await request("/v1/extension-controls/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid preview response", 502);
  }
}
async function applyExtensionMutation(payload) {
  try {
    return normalizeExtensionMutationApply(await request("/v1/extension-controls/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid apply response", 502);
  }
}
function cloneLayers$1(layers) {
  return layers.map((layer) => ({
    ...layer,
    controls: layer.controls.map((control) => ({ ...control }))
  }));
}
function sortedControls(layer) {
  return {
    ...layer,
    controls: [...layer.controls].sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    )
  };
}
function localPermissionDraftState(layers, permissionId) {
  const local = layers.find((layer) => layer.kind === "local-admin");
  const control = local?.controls.find(
    (item) => item.target_kind === "permission" && item.target_id === permissionId
  );
  if (!control) return "inherit";
  return control.state === "enabled" ? "allow" : "block";
}
function setLocalPermissionDraftState(layers, catalogDigest, permissionId, state) {
  const next = cloneLayers$1(layers);
  let local = next.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: catalogDigest,
      global_lockdown: false,
      controls: []
    };
    next.push(local);
  }
  local.controls = local.controls.filter(
    (control) => control.target_kind !== "permission" || control.target_id !== permissionId
  );
  if (state !== "inherit") {
    local.controls.push({
      target_kind: "permission",
      target_id: permissionId,
      state: state === "allow" ? "enabled" : "disabled"
    });
  }
  const normalized = next.map((layer) => sortedControls(layer));
  normalized.sort((left, right) => left.kind.localeCompare(right.kind));
  return normalized;
}
function canonicalLayerValue(layers) {
  return JSON.stringify(
    [...layers].map((layer) => sortedControls(layer)).sort((left, right) => left.kind.localeCompare(right.kind))
  );
}
function extensionPolicyDraftIsDirty(effective, draftLayers) {
  return canonicalLayerValue(effective.layers) !== canonicalLayerValue(draftLayers);
}
function buildExtensionPolicyDraftMutation(effective, catalogDigest, draftLayers, identity) {
  return {
    previous_revision: effective.revision,
    catalog_digest: catalogDigest,
    layers: cloneLayers$1(draftLayers),
    actor_id: "dashboard-admin",
    idempotency_key: identity.idempotencyKey,
    nonce: identity.nonce
  };
}
function newExtensionPolicyDraftIdentity() {
  return {
    idempotencyKey: crypto.randomUUID().replaceAll("-", ""),
    nonce: crypto.randomUUID().replaceAll("-", "")
  };
}
function permissionSuffix(permissionId) {
  const marker = ".permission.";
  const index = permissionId.indexOf(marker);
  return index < 0 ? null : permissionId.slice(index + marker.length);
}
function latestPermissionId(original, oldExtension, latestExtension) {
  if (latestExtension.permissions.some((permission2) => permission2.permission_id === original)) return original;
  if (latestExtension.extension_id !== oldExtension.extension_id && latestExtension.aliases.includes(oldExtension.extension_id)) {
    const suffix = permissionSuffix(original);
    if (!suffix) return null;
    const candidate = `${latestExtension.extension_id}.permission.${suffix}`;
    if (latestExtension.permissions.some((permission2) => permission2.permission_id === candidate)) return candidate;
  }
  return null;
}
function rebaseExtensionPolicyDraft(oldEffective, latestEffective, oldExtension, latestExtension, draftLayers) {
  let rebased = latestEffective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
  const conflicts = [];
  const remapped = {};
  for (const permission2 of oldExtension.permissions) {
    const baseState = localPermissionDraftState(oldEffective.layers, permission2.permission_id);
    const requestedState = localPermissionDraftState(draftLayers, permission2.permission_id);
    if (baseState === requestedState) continue;
    const mapped = latestPermissionId(permission2.permission_id, oldExtension, latestExtension);
    if (!mapped) {
      conflicts.push({
        original_permission_id: permission2.permission_id,
        latest_permission_id: null,
        kind: "removed",
        base_state: baseState,
        latest_state: "inherit",
        requested_state: requestedState
      });
      continue;
    }
    remapped[permission2.permission_id] = mapped;
    const latestState = localPermissionDraftState(latestEffective.layers, mapped);
    if (latestState !== baseState && latestState !== requestedState) {
      conflicts.push({
        original_permission_id: permission2.permission_id,
        latest_permission_id: mapped,
        kind: "overlap",
        base_state: baseState,
        latest_state: latestState,
        requested_state: requestedState
      });
      continue;
    }
    rebased = setLocalPermissionDraftState(rebased, latestEffective.catalog_digest, mapped, requestedState);
  }
  return { draft_layers: rebased, conflicts, remapped_permission_ids: remapped };
}
function keepExtensionPolicyRebaseConflicts(result, latestEffective) {
  let layers = result.draft_layers;
  for (const conflict of result.conflicts) {
    if (conflict.kind !== "overlap" || !conflict.latest_permission_id) continue;
    layers = setLocalPermissionDraftState(
      layers,
      latestEffective.catalog_digest,
      conflict.latest_permission_id,
      conflict.requested_state
    );
  }
  return layers;
}
const RISK_TONE = {
  critical: "border-red-200 bg-red-50 text-red-800",
  high: "border-orange-200 bg-orange-50 text-orange-800",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  low: "border-slate-200 bg-slate-50 text-slate-700"
};
function Pill(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${props.tone ?? "border-slate-200 bg-slate-50 text-slate-700"}`, children: props.children });
}
function cloneLayers(effective) {
  return effective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
}
function managedPermissionState(effective, permissionId) {
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permissionId)?.managed_state;
  if (projected && projected !== "inherited") return projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === "permission" && item.target_id === permissionId);
    if (control) return control.state;
  }
  return null;
}
function extensionPolicyRadioTabStop(choices, state, groupDisabled) {
  if (groupDisabled) return -1;
  const selected = choices.findIndex((choice) => choice.value === state && !choice.disabled);
  return selected >= 0 ? selected : choices.findIndex((choice) => !choice.disabled);
}
function nextExtensionPolicyRadioIndex(choices, index, key, groupDisabled) {
  if (groupDisabled || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(key)) return -1;
  const direction = key === "ArrowLeft" || key === "ArrowUp" ? -1 : 1;
  for (let offset = 1; offset <= choices.length; offset += 1) {
    const next = (index + direction * offset + choices.length) % choices.length;
    if (!choices[next]?.disabled) return next;
  }
  return -1;
}
function isCurrentExtensionPolicyDraft(generation, current) {
  return generation === current;
}
function draftChangeCount(effective, extension2, draftLayers) {
  return extension2.permissions.filter(
    (permission2) => localPermissionDraftState(effective.layers, permission2.permission_id) !== localPermissionDraftState(draftLayers, permission2.permission_id)
  ).length;
}
function DraftControl(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const choices = [
    { value: "inherit", label: "Inherit" },
    { value: "allow", label: "Allow", disabled: managed === "disabled" },
    { value: "block", label: "Block" }
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "radiogroup", "aria-label": `${props.permission.label} local policy`, className: "flex flex-wrap gap-1 rounded-xl bg-slate-100 p-1", children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", role: "radio", "aria-checked": props.state === choice.value, tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1, disabled: props.disabled || choice.disabled, title: choice.disabled ? "Managed policy already blocks this permission; local policy cannot weaken it." : void 0, onKeyDown: (event) => chooseAdjacent(event, index), onClick: () => props.onChange(choice.value), className: `min-h-10 rounded-lg px-3 text-xs font-semibold transition motion-reduce:transition-none ${props.state === choice.value ? "bg-white text-brand-blue shadow-sm" : "text-slate-600 hover:bg-white/70"} disabled:cursor-not-allowed disabled:opacity-45`, children: choice.label }, choice.value)) });
}
function PermissionPolicyRow(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const provenance = controlProvenance(props.effective, "permission", props.permission.permission_id);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("article", { className: "rounded-2xl border border-slate-200 bg-white p-4", "data-permission-id": props.permission.permission_id, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-slate-950", children: props.permission.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[props.permission.risk_tier], children: [
          props.permission.risk_tier,
          " baseline risk"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: permissionStateLabel(props.effective, props.extension, props.permission) }),
        !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: "Fixed" }) : null,
        managed ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: "border-indigo-200 bg-indigo-50 text-indigo-800", children: [
          "Managed ",
          managed === "disabled" ? "block" : "allow"
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-slate-600", children: props.permission.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          "Baseline floor: ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-slate-700", children: treatmentLabel(props.permission.baseline_floor) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          props.permission.rule_ids.length,
          " governed rule",
          props.permission.rule_ids.length === 1 ? "" : "s"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          "Provenance: ",
          provenance.join(" · ")
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-[11px] text-slate-400", children: props.permission.permission_id }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 rounded-xl bg-slate-50 p-3 text-xs leading-5 text-slate-600", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Why fixed:" }),
        " ",
        props.permission.fixed_reason ?? "Guard marks this safety permission as immutable."
      ] }) : null,
      managed === "disabled" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 flex items-start gap-2 rounded-xl border border-indigo-200 bg-indigo-50 p-3 text-xs leading-5 text-indigo-900", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Managed policy blocks this permission. Local policy may inherit or add a block, but it cannot weaken the managed block."
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(DraftControl, { permission: props.permission, effective: props.effective, state: props.draftState, disabled: props.disabled || !props.permission.configurable || props.effective.health !== "protected", onChange: props.onChange })
  ] }) });
}
function PreviewPanel(props) {
  const semantic = props.preview.semantic_preview;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Server semantic preview" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1 text-lg font-semibold text-slate-950", children: "Blast radius before apply" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.changed_target_count,
          " target",
          semantic.changed_target_count === 1 ? "" : "s"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_permission_count,
          " permissions"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_rule_count,
          " rules"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 grid gap-3 sm:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: semantic.summary.newly_blocked_permissions }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Newly blocked permissions" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: semantic.summary.newly_allowed_permissions }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Newly allowed permissions" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-2xl font-semibold text-slate-950", children: semantic.summary.effective_change_count }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs text-slate-500", children: "Effective changes" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: semantic.changed_targets.map((target2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-2xl border border-slate-200 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-slate-950", children: target2.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target2.before_explicit,
          " → ",
          target2.after_explicit
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target2.before_effective,
          " → ",
          target2.after_effective
        ] }),
        target2.baseline_risk ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[target2.baseline_risk], children: [
          target2.baseline_risk,
          " baseline"
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-slate-500", children: [
        "Affects ",
        target2.affected_permission_ids.length,
        " permission",
        target2.affected_permission_ids.length === 1 ? "" : "s",
        " and ",
        target2.affected_rule_ids.length,
        " rule",
        target2.affected_rule_ids.length === 1 ? "" : "s",
        "."
      ] }),
      target2.affected_rule_ids.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-blue", children: "Affected rule IDs" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 max-h-40 overflow-auto rounded-xl bg-slate-50 p-3", children: target2.affected_rule_ids.map((id2) => /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block break-all text-[11px] text-slate-600", children: id2 }, id2)) })
      ] }) : null,
      target2.warnings.map((warning2, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("strong", { children: [
            warning2.code,
            ":"
          ] }),
          " ",
          warning2.message
        ] })
      ] }, `${warning2.code}-${index}`))
    ] }, `${target2.target.kind}:${target2.target.target_id}`)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 break-all text-[11px] text-slate-400", children: [
      "Canonical diff: ",
      props.preview.canonical_diff_digest
    ] })
  ] });
}
function ReviewDrawer(props) {
  const ref = useModalDialog(props.onClose, !props.busy);
  const count = props.preview.semantic_preview.changed_target_count;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 bg-slate-950/40", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { ref, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "extension-policy-review-title", className: "absolute inset-y-0 right-0 w-full max-w-2xl overflow-y-auto bg-white p-5 shadow-2xl focus:outline-none sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Semantic review" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { id: "extension-policy-review-title", className: "mt-1 text-xl font-semibold text-slate-950", children: [
          "Review ",
          count,
          " permission change",
          count === 1 ? "" : "s"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, "aria-label": "Close semantic review", onClick: props.onClose, className: "grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100 disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PreviewPanel, { preview: props.preview }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sticky bottom-0 mt-6 flex flex-wrap justify-end gap-2 border-t border-slate-200 bg-white pt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onClose, className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-slate-700", children: "Continue editing" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: props.busy || count === 0, onClick: props.onApply, className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-40", children: [
        "Apply ",
        count,
        " reviewed change",
        count === 1 ? "" : "s"
      ] })
    ] })
  ] }) });
}
function ExtensionPolicyPanel(props) {
  const [baseEffective, setBaseEffective] = reactExports.useState(props.effective);
  const [policyExtension, setPolicyExtension] = reactExports.useState(props.extension);
  const [draftLayers, setDraftLayers] = reactExports.useState(() => cloneLayers(props.effective));
  const [identity, setIdentity] = reactExports.useState(() => newExtensionPolicyDraftIdentity());
  const [preview, setPreview] = reactExports.useState(null);
  const [previewBusy, setPreviewBusy] = reactExports.useState(false);
  const [applyBusy, setApplyBusy] = reactExports.useState(false);
  const [approvalOpen, setApprovalOpen] = reactExports.useState(false);
  const [reviewOpen, setReviewOpen] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [stale, setStale] = reactExports.useState(false);
  const [pendingRebase, setPendingRebase] = reactExports.useState(null);
  const [refreshRequired, setRefreshRequired] = reactExports.useState(false);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const draftGeneration = reactExports.useRef(0);
  const { onDirtyChange, onRefresh } = props;
  const dirty = reactExports.useMemo(() => extensionPolicyDraftIsDirty(baseEffective, draftLayers), [baseEffective, draftLayers]);
  const changeCount = reactExports.useMemo(() => draftChangeCount(baseEffective, policyExtension, draftLayers), [baseEffective, draftLayers, policyExtension]);
  reactExports.useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);
  reactExports.useEffect(() => {
    const beforeUnload = (event) => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [dirty]);
  reactExports.useEffect(() => {
    draftGeneration.current += 1;
    setBaseEffective(props.effective);
    setPolicyExtension(props.extension);
    setDraftLayers(cloneLayers(props.effective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setRefreshRequired(false);
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [props.effective.revision, props.effective.catalog_digest, props.extension.extension_id]);
  const resetDraft = reactExports.useCallback(() => {
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers(baseEffective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective]);
  const setPermission = reactExports.useCallback((permission2, state) => {
    if (!permission2.configurable) return;
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftState(current, baseEffective.catalog_digest, permission2.permission_id, state));
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective.catalog_digest]);
  const mutation = reactExports.useCallback(() => buildExtensionPolicyDraftMutation(baseEffective, baseEffective.catalog_digest, draftLayers, identity), [baseEffective, draftLayers, identity]);
  const handleApiError = reactExports.useCallback((caught, fallback) => {
    if (caught instanceof ExtensionControlApiError && ["revision_conflict", "catalog_conflict", "authority_conflict"].includes(caught.code ?? "")) {
      setStale(true);
      setError("The authoritative extension policy changed while this draft was open. Rebase the draft before applying; Guard will not silently overwrite security policy.");
      return;
    }
    setError(caught instanceof Error ? caught.message : fallback);
  }, []);
  const runPreview = reactExports.useCallback(async () => {
    if (!dirty) return;
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    setStale(false);
    try {
      const next = await previewExtensionMutation(mutation());
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) return;
      setPreview(next);
      setReviewOpen(true);
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not preview this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [dirty, handleApiError, mutation]);
  const openApproval = reactExports.useCallback(async () => {
    if (!preview || !dirty || stale) return;
    try {
      await resolveApprovalGate({ failClosed: true });
      setReviewOpen(false);
      setApprovalOpen(true);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Guard could not load the local approval gate.");
    }
  }, [dirty, preview, resolveApprovalGate, stale]);
  const apply = reactExports.useCallback(async (credentials) => {
    if (!preview || !dirty || stale) return;
    setApplyBusy(true);
    setError(null);
    try {
      const base = mutation();
      const proofPreview = await previewExtensionMutation({ ...base, ...credentials, session_nonce: crypto.randomUUID().replaceAll("-", "") });
      if (!proofPreview.proof_id) throw new Error("Guard did not issue an approval proof for this exact draft.");
      if (proofPreview.canonical_diff_digest !== preview.canonical_diff_digest) throw new Error("The policy draft changed after preview. Preview it again before applying.");
      const applied = await applyExtensionMutation({ ...base, proof_id: proofPreview.proof_id });
      setApprovalOpen(false);
      setPreview(null);
      setReviewOpen(false);
      setError(null);
      setStale(false);
      if (applied.revision <= baseEffective.revision) throw new Error("Guard did not advance the committed extension-control revision.");
      draftGeneration.current += 1;
      setDraftLayers(cloneLayers(baseEffective));
      setIdentity(newExtensionPolicyDraftIdentity());
      setRefreshRequired(true);
      try {
        await onRefresh();
      } catch {
        setError("The policy was applied, but Guard could not refresh the latest state. Refresh this page to confirm the committed policy.");
      }
    } catch (caught) {
      handleApiError(caught, "Guard could not apply this draft.");
    } finally {
      setApplyBusy(false);
    }
  }, [baseEffective.revision, dirty, handleApiError, mutation, onRefresh, preview, stale]);
  const rebaseDraft = reactExports.useCallback(async () => {
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    try {
      const [latestCatalog, latestEffective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      const exactExtension = latestCatalog.extensions.find((item) => item.extension_id === policyExtension.extension_id);
      const aliasMatches = latestCatalog.extensions.filter((item) => item.aliases.includes(policyExtension.extension_id));
      const latestExtension = exactExtension ?? (aliasMatches.length === 1 ? aliasMatches[0] : void 0);
      if (!latestExtension) {
        setError("This extension no longer exists in the authoritative catalog. Discard the draft and refresh before continuing.");
        return;
      }
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError("The draft changed while Guard was loading current policy. Rebase again to preserve the latest edits.");
        return;
      }
      const result = rebaseExtensionPolicyDraft(baseEffective, latestEffective, policyExtension, latestExtension, draftLayers);
      setBaseEffective(latestEffective);
      setPolicyExtension(latestExtension);
      setIdentity(newExtensionPolicyDraftIdentity());
      setPreview(null);
      setReviewOpen(false);
      if (result.conflicts.length) {
        setPendingRebase({ result, latestEffective, latestExtension });
        setDraftLayers(result.draft_layers);
        setStale(true);
        setError("The latest policy overlaps this draft. Choose whether to keep your overlapping changes or use current authoritative values. Removed permissions cannot be restored.");
      } else {
        setDraftLayers(result.draft_layers);
        setPendingRebase(null);
        setStale(false);
        setError(null);
      }
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError(caught instanceof Error ? caught.message : "Guard could not rebase this draft.");
      }
    } finally {
      setPreviewBusy(false);
    }
  }, [baseEffective, draftLayers, policyExtension]);
  const keepConflicts = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(keepExtensionPolicyRebaseConflicts(pendingRebase.result, pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const useCurrent = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(cloneLayers(pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setPreview(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const configurableCount = policyExtension.permissions.filter((permission2) => permission2.configurable).length;
  const managedCount = policyExtension.permissions.filter((permission2) => managedPermissionState(baseEffective, permission2.permission_id) !== null).length;
  const confirmationCount = preview?.semantic_preview.changed_target_count ?? changeCount;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-policy-editor", "aria-labelledby": "extension-policy-heading", className: "space-y-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-slate-200 bg-white p-5 sm:p-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Local policy draft" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-policy-heading", className: "mt-1 text-lg font-semibold text-slate-950", children: "Permission controls" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-3xl text-sm leading-6 text-slate-600", children: "Choose Inherit, Allow, or Block for independently configurable capabilities. A blocked capability makes Guard block matching actions; it does not turn detection off. Detector severity and baseline floors never change." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
            configurableCount,
            " configurable"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
            policyExtension.permissions.length - configurableCount,
            " fixed"
          ] }),
          dirty ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: "border-blue-200 bg-blue-50 text-blue-800", children: [
            changeCount,
            " staged"
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Pill, { children: "Authoritative" })
        ] })
      ] }),
      baseEffective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 flex gap-2 rounded-xl bg-slate-950 p-3 text-sm text-white", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Global lockdown remains dominant. You can prepare a local draft, but matching commands stay blocked while lockdown is active."
      ] }) : null,
      baseEffective.health !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "alert", className: "mt-4 flex gap-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
        "Permission editing is disabled until extension-control authority is protected."
      ] }) : null,
      managedCount ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 rounded-xl border border-indigo-200 bg-indigo-50 p-3 text-sm text-indigo-900", children: [
        managedCount,
        " permission",
        managedCount === 1 ? " is" : "s are",
        " governed by signed organization policy. Local policy cannot weaken a managed block. Managed exception requests must be made through the organization policy workflow."
      ] }) : null
    ] }),
    refreshRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "status", className: "rounded-2xl border border-blue-200 bg-blue-50 p-4 text-sm text-blue-900", children: "Policy applied. Editing stays locked until this page reloads current authoritative state." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", children: policyExtension.permissions.map((permission2) => /* @__PURE__ */ jsxRuntimeExports.jsx(PermissionPolicyRow, { permission: permission2, extension: policyExtension, effective: baseEffective, draftState: localPermissionDraftState(draftLayers, permission2.permission_id), disabled: refreshRequired, onChange: (state) => setPermission(permission2, state) }, permission2.permission_id)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sticky bottom-4 z-20 rounded-2xl border border-slate-200 bg-white/95 p-4 shadow-xl backdrop-blur supports-[backdrop-filter]:bg-white/85", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm text-slate-600", children: dirty ? `${changeCount} staged permission change${changeCount === 1 ? "" : "s"}.` : "No local policy changes drafted." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: !dirty || previewBusy || applyBusy, onClick: resetDraft, className: "min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 disabled:opacity-40", children: "Discard draft" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: !dirty || previewBusy || applyBusy || baseEffective.health !== "protected" || stale, onClick: () => {
          void runPreview();
        }, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-brand-blue/30 bg-blue-50 px-4 text-sm font-semibold text-brand-blue disabled:opacity-40", children: [
          previewBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }),
          "Review ",
          changeCount,
          " change",
          changeCount === 1 ? "" : "s"
        ] })
      ] })
    ] }) }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: error })
      ] }),
      stale && !pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy, onClick: () => {
        void rebaseDraft();
      }, className: "mt-3 min-h-11 rounded-xl bg-red-700 px-4 text-sm font-semibold text-white", children: "Rebase draft onto current policy" }) : null,
      pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: pendingRebase.result.conflicts.map((conflict) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "rounded-xl bg-white p-3 text-xs", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all", children: conflict.original_permission_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1", children: conflict.kind === "removed" ? "Target removed from the current catalog." : `Current ${conflict.latest_state}; your draft requests ${conflict.requested_state}.` })
        ] }, conflict.original_permission_id)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: keepConflicts, className: "min-h-11 rounded-xl bg-red-700 px-4 text-sm font-semibold text-white", children: "Keep my remaining draft changes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: useCurrent, className: "min-h-11 rounded-xl border border-red-300 bg-white px-4 text-sm font-semibold text-red-800", children: "Use current policy" })
        ] })
      ] }) : null
    ] }) : dirty && !preview ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review is required before apply. Guard calculates effective blast radius server-side from the canonical registry, dependencies, managed policy, and global lockdown." })
    ] }) : null,
    reviewOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewDrawer, { preview, busy: previewBusy || applyBusy, onClose: () => setReviewOpen(false), onApply: () => {
      void openApproval();
    } }) : null,
    approvalOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofModal, { title: `Apply ${confirmationCount} extension permission change${confirmationCount === 1 ? "" : "s"}`, detail: "Authenticate this exact reviewed draft. Guard issues a one-use proof bound to the canonical mutation digest.", confirmLabel: `Apply ${confirmationCount} reviewed change${confirmationCount === 1 ? "" : "s"}`, approvalGate: resolvedApprovalGate, busy: applyBusy, error, onCancel: () => {
      if (!applyBusy) setApprovalOpen(false);
    }, onConfirm: (credentials) => {
      void apply(credentials);
    } }) : null
  ] });
}
const DRAFT_EXIT_MESSAGE = "Discard the staged extension policy draft and leave this extension?";
function ExtensionControlCenterDetail(props) {
  const [policyDirty, setPolicyDirty] = reactExports.useState(false);
  const policyActive = props.urlState.tab === "policy";
  const guardedBack = reactExports.useCallback(() => {
    if (policyDirty && !window.confirm(DRAFT_EXIT_MESSAGE)) return;
    props.onBack();
  }, [policyDirty, props.onBack]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionControlCenterDetail$1,
      {
        ...props,
        externalPolicyPanelId: "extension-policy-tabpanel",
        onBack: guardedBack
      }
    ) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        id: "extension-policy-tabpanel",
        role: "tabpanel",
        "aria-labelledby": "extension-tab-policy",
        hidden: !policyActive,
        "aria-hidden": !policyActive,
        className: "mx-auto -mt-8 w-full max-w-7xl px-4 pb-10 sm:px-6 lg:px-8",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          ExtensionPolicyPanel,
          {
            extension: props.extension,
            effective: props.effective,
            catalogDigest: props.catalogDigest,
            onRefresh: () => window.location.reload(),
            onDirtyChange: setPolicyDirty
          }
        )
      }
    )
  ] });
}
const EMPTY_EXTENSION_FILTERS = {
  query: "",
  risk: "all",
  domain: "all",
  state: "all",
  required: "all"
};
const RISK_CLASS_ORDER = [
  "destructive_shell",
  "network_egress",
  "supply_chain",
  "local_secret_read",
  "encoded_execution",
  "policy_bypass",
  "data_flow_exfiltration",
  "credential_exfiltration",
  "execution"
];
const RISK_CLASS_LABELS = {
  destructive_shell: "Destructive shell",
  network_egress: "Network egress",
  supply_chain: "Supply chain",
  local_secret_read: "Local secrets",
  encoded_execution: "Encoded execution",
  policy_bypass: "Policy bypass",
  data_flow_exfiltration: "Data exfiltration",
  credential_exfiltration: "Credential exfiltration",
  execution: "Remote execution"
};
const RISK_CLASS_TONE = {
  destructive_shell: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-amber-300 hover:bg-amber-50",
    active: "border-amber-400 bg-amber-100 text-amber-900",
    label: "bg-amber-50 text-amber-800 border-amber-200"
  },
  network_egress: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-blue-300 hover:bg-blue-50",
    active: "border-blue-400 bg-blue-100 text-blue-900",
    label: "bg-blue-50 text-blue-800 border-blue-200"
  },
  supply_chain: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-violet-300 hover:bg-violet-50",
    active: "border-violet-400 bg-violet-100 text-violet-900",
    label: "bg-violet-50 text-violet-800 border-violet-200"
  },
  local_secret_read: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-rose-300 hover:bg-rose-50",
    active: "border-rose-400 bg-rose-100 text-rose-900",
    label: "bg-rose-50 text-rose-800 border-rose-200"
  },
  encoded_execution: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-slate-400 hover:bg-slate-100",
    active: "border-slate-500 bg-slate-200 text-slate-900",
    label: "bg-slate-100 text-slate-700 border-slate-300"
  },
  policy_bypass: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-red-300 hover:bg-red-50",
    active: "border-red-400 bg-red-100 text-red-900",
    label: "bg-red-50 text-red-800 border-red-200"
  },
  data_flow_exfiltration: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-orange-300 hover:bg-orange-50",
    active: "border-orange-400 bg-orange-100 text-orange-900",
    label: "bg-orange-50 text-orange-800 border-orange-200"
  },
  credential_exfiltration: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-orange-300 hover:bg-orange-50",
    active: "border-orange-400 bg-orange-100 text-orange-900",
    label: "bg-orange-50 text-orange-800 border-orange-200"
  },
  execution: {
    idle: "border-slate-200 bg-white text-slate-600 hover:border-teal-300 hover:bg-teal-50",
    active: "border-teal-400 bg-teal-100 text-teal-900",
    label: "bg-teal-50 text-teal-800 border-teal-200"
  }
};
const DOMAIN_LABELS = {
  core: "Core protection",
  package: "Package ecosystems",
  cloud: "Cloud providers",
  database: "Databases",
  storage: "Storage",
  backup: "Backup & sync",
  remote: "Remote access",
  cicd: "CI/CD pipelines",
  platform: "Platform",
  "managed-service": "Managed services",
  "search-messaging": "Search & messaging",
  "source-control": "Source control"
};
const DOMAIN_PREFIX_MAP = [
  ["command.package.", "package"],
  ["command.cloud.", "cloud"],
  ["command.aws", "cloud"],
  ["command.azure", "cloud"],
  ["command.gcp", "cloud"],
  ["command.database.", "database"],
  ["command.storage.", "storage"],
  ["command.backup.", "backup"],
  ["command.remote.", "remote"],
  ["command.cicd.", "cicd"],
  ["command.platform.", "platform"],
  ["command.managed-service.", "managed-service"],
  ["command.search-messaging.", "search-messaging"],
  ["command.github", "source-control"]
];
function classifyDomain(extensionId) {
  const id2 = extensionId.toLowerCase();
  for (const [prefix, domain] of DOMAIN_PREFIX_MAP) {
    if (id2.startsWith(prefix)) return domain;
  }
  return "core";
}
function isExtensionEnabled(effective, extension2) {
  return extensionEffectiveState(effective, extension2) === "enabled";
}
function hasActiveFilters(filters) {
  return filters.query.trim() !== "" || filters.risk !== "all" || filters.domain !== "all" || filters.state !== "all" || filters.required !== "all";
}
function searchHaystack(extension2) {
  const parts = [
    extension2.name,
    extension2.extension_id,
    extension2.description,
    extension2.source,
    ...extension2.action_classes,
    ...extension2.risk_classes,
    classifyDomain(extension2.extension_id)
  ];
  return parts.join(" ").toLowerCase();
}
function matchExtensionQuery(extension2, query) {
  const normalized = query.trim().toLowerCase();
  if (normalized === "") return true;
  const haystack = searchHaystack(extension2);
  return normalized.split(/\s+/).every((token) => haystack.includes(token));
}
function filterExtensions(extensions, effective, filters) {
  const items = extensions.filter((extension2) => {
    if (!matchExtensionQuery(extension2, filters.query)) return false;
    if (filters.risk !== "all" && !extension2.risk_classes.includes(filters.risk)) return false;
    if (filters.domain !== "all" && classifyDomain(extension2.extension_id) !== filters.domain) return false;
    if (filters.required !== "all") {
      const isRequired = extension2.required;
      if (filters.required === "required" && !isRequired) return false;
      if (filters.required === "optional" && isRequired) return false;
    }
    if (filters.state !== "all") {
      const enabled = isExtensionEnabled(effective, extension2);
      if (filters.state === "enabled" && !enabled) return false;
      if (filters.state === "disabled" && enabled) return false;
    }
    return true;
  });
  items.sort((left, right) => left.name.localeCompare(right.name));
  return items;
}
const SELECT_CLASS = "min-h-9 rounded-xl border border-slate-200 bg-white px-3 text-xs font-medium text-slate-700 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60";
const DOMAIN_ORDER = [
  "core",
  "package",
  "cloud",
  "database",
  "storage",
  "backup",
  "remote",
  "cicd",
  "platform",
  "managed-service",
  "search-messaging",
  "source-control"
];
function SearchField(props) {
  const handleChange = reactExports.useCallback(
    (event) => props.onChange(event.target.value),
    [props]
  );
  const handleClear = reactExports.useCallback(() => props.onChange(""), [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative flex flex-1 items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Search extensions" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      HiMiniMagnifyingGlass,
      {
        className: "pointer-events-none absolute left-3 size-4 text-slate-400",
        "aria-hidden": "true"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "input",
      {
        ref: props.inputRef,
        type: "search",
        value: props.value,
        onChange: handleChange,
        placeholder: "Search by name, command, or risk (press /)",
        className: "min-h-9 w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-9 text-sm text-slate-900 placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
      }
    ),
    props.value ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: handleClear,
        "aria-label": "Clear search",
        className: "absolute right-2 flex size-5 items-center justify-center rounded-full text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" })
      }
    ) : null
  ] });
}
function RiskChips(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-center gap-1.5", role: "group", "aria-label": "Filter by risk class", children: RISK_CLASS_ORDER.map((risk) => {
    const isActive = props.value === risk;
    const tone = RISK_CLASS_TONE[risk];
    const count = props.counts.get(risk) ?? 0;
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: () => props.onChange(isActive ? "all" : risk),
        "aria-pressed": isActive,
        className: `inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${isActive ? tone.active : tone.idle}`,
        children: [
          RISK_CLASS_LABELS[risk],
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: isActive ? "opacity-70" : "text-slate-400", "aria-hidden": "true", children: count })
        ]
      },
      risk
    );
  }) });
}
function ActiveChip(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 rounded-full bg-brand-blue/10 px-2.5 py-1 text-xs font-medium text-brand-blue", children: [
    props.label,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.onRemove,
        "aria-label": `Remove filter: ${props.label}`,
        className: "flex size-4 items-center justify-center rounded-full transition-colors hover:bg-brand-blue/20",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-3", "aria-hidden": "true" })
      }
    )
  ] });
}
function ExtensionsFilterBar(props) {
  const [showFacets, setShowFacets] = reactExports.useState(false);
  const searchRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    const handleKeyDown = (event) => {
      const target2 = event.target;
      const typing = target2?.tagName === "INPUT" || target2?.tagName === "TEXTAREA" || target2?.isContentEditable;
      if (event.key === "/" && !typing) {
        event.preventDefault();
        searchRef.current?.focus();
      } else if (event.key === "Escape" && document.activeElement === searchRef.current && props.filters.query) {
        props.onChange({ query: "" });
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [props]);
  const handleQuery = reactExports.useCallback((value) => props.onChange({ query: value }), [props]);
  const handleRisk = reactExports.useCallback((risk) => props.onChange({ risk }), [props]);
  const handleDomain = reactExports.useCallback(
    (event) => props.onChange({ domain: event.target.value === "all" ? "all" : event.target.value }),
    [props]
  );
  const handleState = reactExports.useCallback(
    (event) => props.onChange({ state: event.target.value }),
    [props]
  );
  const handleRequired = reactExports.useCallback(
    (event) => props.onChange({ required: event.target.value }),
    [props]
  );
  const toggleFacets = reactExports.useCallback(() => setShowFacets((prev) => !prev), []);
  const riskCounts = reactExports.useMemo(
    () => {
      const counts = /* @__PURE__ */ new Map();
      for (const risk of RISK_CLASS_ORDER) counts.set(risk, 0);
      for (const extension2 of props.extensions) {
        for (const risk of extension2.risk_classes) {
          if (risk in RISK_CLASS_LABELS) {
            const key = risk;
            counts.set(key, (counts.get(key) ?? 0) + 1);
          }
        }
      }
      return counts;
    },
    [props.extensions]
  );
  const totalCount = props.extensions.length;
  const filteredCount = reactExports.useMemo(
    () => filterExtensions(props.extensions, props.effective, props.filters).length,
    [props.extensions, props.effective, props.filters]
  );
  const active = hasActiveFilters(props.filters);
  const facetsActive = props.filters.domain !== "all" || props.filters.state !== "all" || props.filters.required !== "all";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", "aria-label": "Extension filters", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SearchField, { value: props.filters.query, onChange: handleQuery, inputRef: searchRef }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: toggleFacets,
          "aria-expanded": showFacets,
          "aria-label": "Toggle domain, state, and requirement filters",
          className: `inline-flex min-h-9 items-center gap-1.5 rounded-xl border px-3 text-xs font-medium transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${showFacets || facetsActive ? "border-brand-blue bg-brand-blue/5 text-brand-blue" : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "size-4", "aria-hidden": "true" }),
            "Filters",
            facetsActive ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex size-4 items-center justify-center rounded-full bg-brand-blue text-[10px] font-bold text-white", children: [props.filters.domain !== "all", props.filters.state !== "all", props.filters.required !== "all"].filter(Boolean).length }) : null
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(RiskChips, { value: props.filters.risk, onChange: handleRisk, counts: riskCounts }),
    showFacets ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 rounded-xl bg-slate-50/70 p-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: props.filters.domain,
          onChange: handleDomain,
          "aria-label": "Filter by domain",
          className: SELECT_CLASS,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All domains" }),
            DOMAIN_ORDER.map((domain) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: domain, children: DOMAIN_LABELS[domain] }, domain))
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: props.filters.state,
          onChange: handleState,
          "aria-label": "Filter by enabled state",
          className: SELECT_CLASS,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All states" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "enabled", children: "Enabled" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "disabled", children: "Disabled" })
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: props.filters.required,
          onChange: handleRequired,
          "aria-label": "Filter by required status",
          className: SELECT_CLASS,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "Required & optional" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "required", children: "Required only" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "optional", children: "Optional only" })
          ]
        }
      )
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5", children: [
      active ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        props.filters.query ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActiveChip, { label: `“${props.filters.query}”`, onRemove: () => props.onChange({ query: "" }) }) : null,
        props.filters.risk !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: RISK_CLASS_LABELS[props.filters.risk],
            onRemove: () => props.onChange({ risk: "all" })
          }
        ) : null,
        props.filters.domain !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: DOMAIN_LABELS[props.filters.domain],
            onRemove: () => props.onChange({ domain: "all" })
          }
        ) : null,
        props.filters.state !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: props.filters.state === "enabled" ? "Enabled" : "Disabled",
            onRemove: () => props.onChange({ state: "all" })
          }
        ) : null,
        props.filters.required !== "all" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveChip,
          {
            label: props.filters.required === "required" ? "Required only" : "Optional only",
            onRemove: () => props.onChange({ required: "all" })
          }
        ) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: props.onClear,
            className: "ml-1 text-xs font-medium text-brand-blue transition-colors hover:text-brand-dark",
            children: "Clear all"
          }
        )
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-auto text-xs text-slate-500", "aria-live": "polite", children: active ? `${filteredCount} of ${totalCount} shown` : `${totalCount} total` })
    ] })
  ] });
}
function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = reactExports.useState(value);
  reactExports.useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debouncedValue;
}
const PROTECTION_TERMS = {
  pageTitle: "Protection Center",
  modules: "Protection modules"
};
const PROTECTION_DENSITY_STORAGE_KEY = "guard-protection-center-density-v1";
function parseProtectionDensity(value) {
  return value === "advanced" || value === "developer" ? value : "simple";
}
function readProtectionDensity(storage = typeof window === "undefined" ? null : window.localStorage) {
  try {
    return parseProtectionDensity(storage?.getItem(PROTECTION_DENSITY_STORAGE_KEY));
  } catch {
    return "simple";
  }
}
function writeProtectionDensity(density, storage = typeof window === "undefined" ? null : window.localStorage) {
  try {
    storage?.setItem(PROTECTION_DENSITY_STORAGE_KEY, density);
  } catch {
  }
}
function deriveProtectionStatus(effective) {
  if (effective.global_lockdown) {
    return {
      status: "lockdown",
      title: "Emergency Lockdown active",
      summary: "Guard is blocking matching optional actions until you review and end lockdown.",
      tone: "danger",
      primaryAction: "review-lockdown",
      primaryActionLabel: "Review lockdown"
    };
  }
  switch (effective.health) {
    case "protected":
      return {
        status: "protected",
        title: "Protected",
        summary: "Guard is actively applying the trusted protection settings on this device.",
        tone: "safe",
        primaryAction: "none",
        primaryActionLabel: null
      };
    case "unenrolled":
      return {
        status: "finish-setup",
        title: "Finish setup",
        summary: "Complete local setup so Guard can protect and verify settings on this device.",
        tone: "attention",
        primaryAction: "finish-setup",
        primaryActionLabel: "Show setup steps"
      };
    case "tampered":
    case "recovery-required":
      return {
        status: "needs-repair",
        title: "Needs repair",
        summary: "Guard detected a problem with trusted protection settings and is staying fail-safe until they are repaired.",
        tone: "danger",
        primaryAction: "repair",
        primaryActionLabel: "Repair protection"
      };
    case "degraded-unacknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is staying fail-safe because it cannot fully verify protection settings. Repair is recommended.",
        tone: "attention",
        primaryAction: "repair",
        primaryActionLabel: "Restore protection"
      };
    case "degraded-acknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is still staying fail-safe. The earlier acknowledgement did not restore trusted protection.",
        tone: "attention",
        primaryAction: "retry-repair",
        primaryActionLabel: "Try repair again"
      };
    default:
      return {
        status: "unavailable",
        title: "Protection status unavailable",
        summary: "Guard could not verify the current protection state. Refresh before making any protection changes.",
        tone: "neutral",
        primaryAction: "refresh",
        primaryActionLabel: "Check again"
      };
  }
}
function useProtectionDensity() {
  const [density, setDensity] = reactExports.useState(() => readProtectionDensity());
  const update = reactExports.useCallback((next) => {
    writeProtectionDensity(next);
    setDensity(next);
  }, []);
  return [density, update];
}
function ProtectionDensityControl(props) {
  const choices = [
    { value: "simple", label: "Simple" },
    { value: "advanced", label: "Advanced" },
    { value: "developer", label: "Developer" }
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "radiogroup", "aria-label": "Information detail", className: "flex w-full max-w-full flex-wrap rounded-xl border border-slate-200 bg-slate-50 p-1 sm:inline-flex sm:w-auto sm:flex-nowrap", children: choices.map((choice) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.value === choice.value,
      onClick: () => props.onChange(choice.value),
      className: `min-h-10 min-w-0 flex-1 rounded-lg px-2.5 text-xs font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue sm:flex-none sm:px-3 ${props.value === choice.value ? "bg-white text-brand-blue shadow-sm" : "text-slate-600 hover:bg-white"}`,
      children: choice.label
    },
    choice.value
  )) });
}
const HERO_TONE = {
  safe: "border-emerald-200 bg-emerald-50 text-emerald-950",
  attention: "border-amber-200 bg-amber-50 text-amber-950",
  danger: "border-red-200 bg-red-50 text-red-950",
  neutral: "border-slate-200 bg-slate-50 text-slate-950"
};
function ProtectionStatusHero(props) {
  const safe = props.status.tone === "safe";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-status-heading", className: `rounded-3xl border p-5 sm:p-6 ${HERO_TONE[props.status.tone]}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid size-11 shrink-0 place-items-center rounded-2xl bg-white/80", "aria-hidden": "true", children: safe ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-6" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-6" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] opacity-70", children: "Local protection" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-status-heading", className: "mt-1 text-2xl font-semibold tracking-tight", children: props.status.title })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 max-w-2xl text-sm leading-6 opacity-85", children: props.status.summary })
      ] }),
      props.status.primaryActionLabel && props.onPrimaryAction ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          "aria-busy": props.busy,
          disabled: props.busy,
          onClick: props.onPrimaryAction,
          className: "min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:cursor-wait disabled:opacity-60",
          children: props.busy ? "Working…" : props.status.primaryActionLabel
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex min-h-10 items-center gap-2 self-start rounded-full border border-current/15 bg-white/70 px-3 text-xs font-semibold", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-4" }),
        "No action required"
      ] })
    ] }),
    props.children ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 border-t border-current/10 pt-4", children: props.children }) : null
  ] });
}
function ProtectionDecisionBadge({ result }) {
  const label = result === "allowed" ? "Allowed" : result === "ask-first" ? "Ask first" : "Blocked";
  const classes = result === "allowed" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : result === "ask-first" ? "border-amber-200 bg-amber-50 text-amber-800" : "border-red-200 bg-red-50 text-red-800";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${classes}`, children: label });
}
function ProtectionModuleRow(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onOpen, className: "flex min-h-20 w-full items-center gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-3 text-left transition hover:border-blue-200 hover:bg-blue-50/30 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue motion-reduce:transition-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid size-10 shrink-0 place-items-center rounded-xl bg-blue-50 text-brand-blue", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-slate-950", children: props.name }),
        props.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-600", children: "Required" }) : null,
        props.managed ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-indigo-50 px-2 py-0.5 text-[10px] font-semibold text-indigo-700", children: "Managed" }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block line-clamp-2 text-sm leading-5 text-slate-600", children: props.description })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "hidden shrink-0 text-xs font-semibold text-slate-600 sm:inline", children: props.behavior }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5 shrink-0 text-slate-400", "aria-hidden": "true" })
  ] });
}
function TechnicalDetails(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "rounded-2xl border border-slate-200 bg-slate-50 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer list-none text-sm font-semibold text-slate-700", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      props.title ?? "Technical details",
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "size-4", "aria-hidden": "true" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 text-sm text-slate-700", children: props.children })
  ] });
}
function InlineError({ message }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800", children: message });
}
const PROTECTION_CATEGORIES = [
  { id: "source-control", label: "Source control", description: "Protect repository history, branches, and source-control operations.", searchAliases: ["git", "github", "repository", "source"] },
  { id: "packages", label: "Packages and dependencies", description: "Protect dependency installs, package managers, and supply-chain changes.", searchAliases: ["npm", "pnpm", "yarn", "pip", "package", "dependency"] },
  { id: "files-secrets", label: "Files and secrets", description: "Protect sensitive files, credentials, and secret-bearing operations.", searchAliases: ["file", "secret", "credential", "environment"] },
  { id: "cloud-infrastructure", label: "Cloud and infrastructure", description: "Protect infrastructure, cloud resources, and administrative actions.", searchAliases: ["aws", "gcp", "azure", "terraform", "cloud", "infrastructure"] },
  { id: "network-downloads", label: "Network and downloads", description: "Protect downloads, remote access, and network-facing operations.", searchAliases: ["curl", "wget", "ssh", "network", "download", "remote"] },
  { id: "data-databases", label: "Data and databases", description: "Protect databases, storage, backups, and destructive data operations.", searchAliases: ["database", "sql", "postgres", "mysql", "redis", "data", "backup"] },
  { id: "deployments-ci", label: "Deployments and CI", description: "Protect deployment, build, release, and CI/CD operations.", searchAliases: ["deploy", "release", "ci", "cd", "workflow", "pipeline"] },
  { id: "messaging-collaboration", label: "Messaging and collaboration", description: "Protect actions in messaging, search, and collaboration tools.", searchAliases: ["slack", "message", "collaboration", "search"] },
  { id: "system-shell", label: "System and shell actions", description: "Protect high-impact local shell, process, and system operations.", searchAliases: ["shell", "system", "bash", "terminal", "process"] },
  { id: "ai-workflows", label: "AI tools and agent workflows", description: "Protect AI-agent, tool, and automated workflow actions.", searchAliases: ["ai", "agent", "mcp", "tool", "workflow"] }
];
const CATEGORY_BY_ID = new Map(PROTECTION_CATEGORIES.map((category) => [category.id, category]));
function searchableExtensionText(extension2) {
  return [
    extension2.extension_id,
    extension2.name,
    extension2.description,
    ...extension2.ecosystem_ids,
    ...extension2.executables,
    ...extension2.action_classes,
    ...extension2.risk_classes
  ].join(" ").toLowerCase();
}
function protectionCategoryIdForExtension(extension2) {
  const text2 = searchableExtensionText(extension2);
  if (/\bgit\b|github|source.?control|repository|branch|commit/.test(text2)) return "source-control";
  if (/package|dependency|npm|pnpm|yarn|pip|poetry|cargo|composer|gem|supply.?chain/.test(text2)) return "packages";
  if (/secret|credential|\.env|filesystem|sensitive.?file|keychain/.test(text2)) return "files-secrets";
  if (/aws|azure|gcp|cloud|terraform|kubectl|kubernetes|infrastructure|platform/.test(text2)) return "cloud-infrastructure";
  if (/network|egress|download|curl|wget|ssh|remote|http|ftp/.test(text2)) return "network-downloads";
  if (/database|sql|postgres|mysql|sqlite|redis|mongo|storage|backup|data/.test(text2)) return "data-databases";
  if (/deploy|release|ci.?cd|pipeline|workflow|build|artifact/.test(text2)) return "deployments-ci";
  if (/slack|discord|message|collaboration|search|email/.test(text2)) return "messaging-collaboration";
  if (/agent|\bmcp\b|assistant|model|prompt|ai.?tool/.test(text2)) return "ai-workflows";
  return "system-shell";
}
function protectionCategoryForExtension(extension2) {
  const id2 = protectionCategoryIdForExtension(extension2);
  return CATEGORY_BY_ID.get(id2) ?? PROTECTION_CATEGORIES[8];
}
function protectionDecisionForAction(action) {
  if (action === "block") return "blocked";
  if (action === "allow") return "allowed";
  return "ask-first";
}
function recentProtectionDecisions(activity, catalog, limit = 5) {
  const names = new Map(catalog.map((extension2) => [extension2.extension_id, extension2.name]));
  return [...activity].filter((item) => item.policy_action !== null).sort((left, right) => Date.parse(right.occurred_at) - Date.parse(left.occurred_at)).slice(0, Math.max(0, Math.min(limit, 20))).map((item) => {
    const extensionIds = [...new Set(item.matches.map((match) => match.extension_id))].slice(0, 8);
    return {
      activityId: item.activity_id,
      occurredAt: item.occurred_at,
      harness: item.harness,
      result: protectionDecisionForAction(item.policy_action),
      reasonCode: item.decision_reason_code,
      extensionIds,
      extensionNames: extensionIds.map((id2) => names.get(id2) ?? "Protection module"),
      controllingRuleId: item.controlling_rule_id
    };
  });
}
function rankProtectionModules(catalog, activity) {
  const involvement = /* @__PURE__ */ new Map();
  for (const item of activity) {
    for (const id2 of new Set(item.matches.map((match) => match.extension_id))) {
      const previous = involvement.get(id2);
      if (!previous) involvement.set(id2, { count: 1, lastAt: item.occurred_at });
      else {
        previous.count += 1;
        if (Date.parse(item.occurred_at) > Date.parse(previous.lastAt)) previous.lastAt = item.occurred_at;
      }
    }
  }
  return catalog.map((extension2) => {
    const used = involvement.get(extension2.extension_id);
    const section = used ? "in-use" : extension2.required || extension2.enabled ? "recommended" : "all";
    const recencyScore = used ? Math.max(0, Date.parse(used.lastAt)) : 0;
    const score = (used ? 1e15 : 0) + (used?.count ?? 0) * 1e9 + (extension2.required ? 1e8 : 0) + (extension2.enabled ? 1e7 : 0) + recencyScore;
    return {
      extension: extension2,
      section,
      score,
      lastInvolvedAt: used?.lastAt ?? null,
      involvementCount: used?.count ?? 0
    };
  }).sort((left, right) => right.score - left.score || left.extension.name.localeCompare(right.extension.name));
}
function safeSearchText(extension2) {
  const category = protectionCategoryForExtension(extension2);
  return [
    extension2.name,
    extension2.description,
    ...extension2.aliases,
    ...extension2.ecosystem_ids,
    ...extension2.executables,
    category.label,
    category.description,
    ...category.searchAliases
  ].join(" ").toLowerCase();
}
function filterProtectionModulesByHumanQuery(modules, query) {
  const normalized = query.trim().toLowerCase().slice(0, 160);
  if (!normalized) return [...modules];
  const terms = normalized.split(/\s+/).filter(Boolean).slice(0, 8);
  return modules.filter(({ extension: extension2 }) => {
    const text2 = safeSearchText(extension2);
    return terms.every((term) => text2.includes(term));
  });
}
function protectionCloudContinuity(runtime, loadFailed = false) {
  if (loadFailed) {
    return {
      state: "unavailable",
      label: "Cloud continuity unavailable",
      detail: "Local protection continues on this device. Cloud status could not be refreshed."
    };
  }
  if (!runtime || !runtime.sync_configured || runtime.cloud_state === "local_only") {
    return {
      state: "not-connected",
      label: "Cloud continuity not connected",
      detail: "Local protection continues. Connect Cloud only if you want cross-device continuity and Cloud history."
    };
  }
  if (runtime.cloud_state === "paired_waiting") {
    return {
      state: "waiting",
      label: "Cloud continuity connecting",
      detail: "Local protection continues while Cloud finishes pairing or synchronization."
    };
  }
  return {
    state: "connected",
    label: "Cloud continuity connected",
    detail: runtime.cloud_state_detail || "Cloud continuity is connected for this device."
  };
}
function protectionCategorySummary(catalog, effective) {
  const groups = /* @__PURE__ */ new Map();
  for (const extension2 of catalog) {
    const category = protectionCategoryForExtension(extension2);
    const group = groups.get(category.id) ?? {
      id: category.id,
      label: category.label,
      description: category.description,
      total: 0,
      allowed: 0,
      blocked: 0
    };
    group.total += 1;
    if (isExtensionEnabled(effective, extension2)) group.allowed += 1;
    else group.blocked += 1;
    groups.set(category.id, group);
  }
  return [...groups.values()].sort((left, right) => left.label.localeCompare(right.label));
}
function evaluateProtectionHealth(catalogDigest, effective, runtime) {
  const checks = [
    { id: "authority", label: "Trusted protection settings are verified", passed: effective.health === "protected" },
    { id: "catalog", label: "Protection catalog matches effective policy", passed: catalogDigest === effective.catalog_digest },
    { id: "runtime", label: "Guard runtime is responding", passed: runtime !== null && runtime.runtime_state !== null }
  ];
  const healthy = checks.every((check) => check.passed);
  return {
    status: healthy ? "healthy" : "needs-attention",
    summary: healthy ? "Protection health check passed. Guard's catalog, policy authority, and runtime agree." : "One or more local protection checks need attention. Guard remains conservative when it cannot verify state.",
    checks
  };
}
function managedByOrganization(effective, extensionId) {
  return effective.layers.some(
    (layer) => layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "extension" && control.target_id === extensionId)
  );
}
function CloudContinuityIndicator(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { "aria-label": "Cloud continuity", className: "flex items-start gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid size-9 shrink-0 place-items-center rounded-xl bg-slate-50 text-slate-600", "aria-hidden": "true", children: props.loading ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-5 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "size-5" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-semibold text-slate-900", children: props.loading ? "Checking Cloud continuity…" : props.continuity.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-slate-600", children: props.continuity.detail })
    ] })
  ] });
}
function ProtectionCategoryGrid(props) {
  const categories = reactExports.useMemo(() => protectionCategorySummary(props.catalog, props.effective), [props.catalog, props.effective]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "what-guard-protects-heading", className: "mt-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "what-guard-protects-heading", className: "text-xl font-semibold text-slate-950", children: "What HOL Guard protects" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-3xl text-sm text-slate-600", children: "Guard applies focused protections across the developer actions and tools on this device." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3", children: categories.map((category) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-2xl border border-slate-200 bg-white p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-slate-950", children: category.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-slate-600", children: category.description })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "grid size-9 shrink-0 place-items-center rounded-xl bg-blue-50 text-brand-blue", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5" }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 text-xs text-slate-500", children: [
        category.total,
        " module",
        category.total === 1 ? "" : "s",
        " · ",
        category.blocked ? `${category.blocked} locally blocked` : "Guard defaults active"
      ] })
    ] }, category.id)) })
  ] });
}
const SECTION_LABELS = {
  "in-use": "In use",
  recommended: "Recommended",
  all: "All"
};
function ProtectionModuleExplorer(props) {
  const hasInUse = props.modules.some((module) => module.section === "in-use");
  const [section, setSection] = reactExports.useState(hasInUse ? "in-use" : "recommended");
  const sectionTouched = reactExports.useRef(false);
  const [query, setQuery] = reactExports.useState("");
  const [advancedOpen, setAdvancedOpen] = reactExports.useState(false);
  reactExports.useEffect(() => {
    if (hasInUse && !sectionTouched.current && section !== "in-use") setSection("in-use");
  }, [hasInUse, section]);
  const queried = reactExports.useMemo(() => filterProtectionModulesByHumanQuery(props.modules, query), [props.modules, query]);
  const visible = queried.filter((module) => section === "all" || module.section === section);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-modules-heading", className: "mt-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-modules-heading", className: "text-xl font-semibold text-slate-950", children: "Protection modules" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Find protections by the thing you use, like Git, packages, secrets, or downloads." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
        props.modules.length,
        " available"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-col gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-3 sm:flex-row sm:items-center", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative min-w-0 flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Search protection modules" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "search", value: query, onChange: (event) => setQuery(event.target.value.slice(0, 160)), placeholder: "Search Git, packages, secrets, downloads…", className: "min-h-11 w-full rounded-xl border border-slate-300 bg-white py-2 pl-9 pr-3 text-sm text-slate-900 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "tablist", "aria-label": "Protection module groups", className: "flex shrink-0 rounded-xl border border-slate-200 bg-white p-1", children: ["in-use", "recommended", "all"].map((id2) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", role: "tab", "aria-selected": section === id2, disabled: id2 === "in-use" && !hasInUse, onClick: () => {
        sectionTouched.current = true;
        setSection(id2);
      }, className: `min-h-9 rounded-lg px-3 text-xs font-semibold disabled:opacity-40 ${section === id2 ? "bg-blue-50 text-brand-blue" : "text-slate-600 hover:bg-slate-50"}`, children: SECTION_LABELS[id2] }, id2)) })
    ] }),
    props.advancedFilters ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-expanded": advancedOpen, onClick: () => setAdvancedOpen((value) => !value), className: "inline-flex min-h-10 items-center gap-2 rounded-lg px-2 text-xs font-semibold text-slate-600 hover:bg-slate-100", children: [
        "Advanced filters ",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: `size-4 transition motion-reduce:transition-none ${advancedOpen ? "rotate-180" : ""}`, "aria-hidden": "true" })
      ] }),
      advancedOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: props.advancedFilters }) : null
    ] }) : null,
    visible.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-2", children: visible.map((module) => /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionModuleRow, { name: module.extension.name, description: module.extension.description, behavior: isExtensionEnabled(props.effective, module.extension) ? "Guard defaults active" : "Blocked on this device", required: module.extension.required, managed: managedByOrganization(props.effective, module.extension.extension_id), onOpen: () => props.onOpen(module.extension) }, module.extension.extension_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-slate-900", children: "No protection modules match this view." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Try All modules or a simpler search." })
    ] })
  ] });
}
function RecentProtectionDecisions(props) {
  if (props.loading) return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "recent-protection-decisions-heading", className: "mt-8 rounded-2xl border border-slate-200 bg-white p-5", "aria-busy": "true", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "recent-protection-decisions-heading", className: "text-lg font-semibold text-slate-950", children: "Recent decisions" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton mt-4 h-24 w-full" })
  ] });
  if (props.unavailable) return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "recent-protection-decisions-heading", className: "mt-8 rounded-2xl border border-slate-200 bg-white p-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "recent-protection-decisions-heading", className: "text-lg font-semibold text-slate-950", children: "Recent decisions" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Recent local decision evidence could not be loaded. Protection status above remains independent of this activity view." })
  ] });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "recent-protection-decisions-heading", className: "mt-8 rounded-2xl border border-slate-200 bg-white p-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "recent-protection-decisions-heading", className: "text-lg font-semibold text-slate-950", children: "Recent decisions" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Privacy-safe local evidence from Guard's existing command-activity store. Raw commands and paths are not shown here." })
    ] }),
    props.decisions.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 divide-y divide-slate-100", children: props.decisions.map((decision) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "py-3 first:pt-0 last:pb-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionDecisionBadge, { result: decision.result }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-slate-900", children: decision.extensionNames.length ? decision.extensionNames.join(", ") : "Guard protection" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("time", { className: "text-xs text-slate-500", dateTime: decision.occurredAt, children: new Date(decision.occurredAt).toLocaleString() })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-blue", children: "Why?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-slate-600", children: commandReasonLabel(decision.reasonCode) })
      ] })
    ] }, decision.activityId)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 rounded-xl bg-slate-50 p-4 text-sm text-slate-600", children: "No recent local command decisions are recorded yet. Guard will show real activity here as it is recorded." })
  ] });
}
function ProtectionHealthCheckPanel(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-health-check-heading", className: "mt-8 rounded-2xl border border-slate-200 bg-white p-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-health-check-heading", className: "text-lg font-semibold text-slate-950", children: "Protection health check" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm text-slate-600", children: "Safely re-read Guard's local catalog, trusted settings, and runtime. This check does not execute a command or change protection." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onRun, disabled: props.busy, "aria-busy": props.busy, className: "inline-flex min-h-11 shrink-0 items-center gap-2 rounded-xl border border-brand-blue/25 bg-white px-4 text-sm font-semibold text-brand-blue hover:bg-blue-50 disabled:opacity-60", children: [
        props.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-4", "aria-hidden": "true" }),
        props.busy ? "Checking…" : "Run health check"
      ] })
    ] }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800", children: props.error }) : null,
    props.result ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", "aria-live": "polite", className: `mt-4 rounded-xl border p-4 ${props.result.status === "healthy" ? "border-emerald-200 bg-emerald-50" : "border-amber-200 bg-amber-50"}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        props.result.status === "healthy" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 size-5 shrink-0 text-emerald-700" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0 text-amber-700" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-slate-900", children: props.result.summary })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 space-y-1.5", children: props.result.checks.map((check) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center gap-2 text-xs text-slate-700", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: check.passed ? "✓" : "•" }),
        check.label
      ] }, check.id)) })
    ] }) : null
  ] });
}
const client = createCommandActivityClient(fetchCommandActivityApi);
const INITIAL_STATE = {
  activity: [],
  activityLoading: true,
  activityError: false,
  runtime: null,
  runtimeLoading: true,
  runtimeError: false
};
function useProtectionLandingData() {
  const [state, setState] = reactExports.useState(INITIAL_STATE);
  const [refreshKey, setRefreshKey] = reactExports.useState(0);
  reactExports.useEffect(() => {
    const controller = new AbortController();
    setState((current) => ({
      ...current,
      activityLoading: true,
      activityError: false,
      runtimeLoading: true,
      runtimeError: false
    }));
    void client.fetchPage({ ...DEFAULT_COMMAND_ACTIVITY_FILTERS, limit: 12 }, null, controller.signal).then(
      (page) => setState((current) => ({ ...current, activity: page.items, activityLoading: false })),
      () => {
        if (!controller.signal.aborted) setState((current) => ({ ...current, activity: [], activityLoading: false, activityError: true }));
      }
    );
    void fetchRuntimeSnapshot({ includeItems: false, includeReceipts: false }).then(
      (runtime) => {
        if (!controller.signal.aborted) setState((current) => ({ ...current, runtime, runtimeLoading: false }));
      },
      () => {
        if (!controller.signal.aborted) setState((current) => ({ ...current, runtime: null, runtimeLoading: false, runtimeError: true }));
      }
    );
    return () => controller.abort();
  }, [refreshKey]);
  const refresh = reactExports.useCallback(() => setRefreshKey((value) => value + 1), []);
  return { ...state, refresh };
}
function ProtectionLandingExperience(props) {
  const landing = useProtectionLandingData();
  const [healthBusy, setHealthBusy] = reactExports.useState(false);
  const [healthResult, setHealthResult] = reactExports.useState(null);
  const [healthError, setHealthError] = reactExports.useState(null);
  const modules = reactExports.useMemo(() => rankProtectionModules(props.catalog, landing.activity), [landing.activity, props.catalog]);
  const decisions = reactExports.useMemo(() => recentProtectionDecisions(landing.activity, props.catalog, 5), [landing.activity, props.catalog]);
  const continuity = reactExports.useMemo(
    () => protectionCloudContinuity(landing.runtime, landing.runtimeError),
    [landing.runtime, landing.runtimeError]
  );
  async function runHealthCheck() {
    setHealthBusy(true);
    setHealthError(null);
    try {
      const [catalog, effective, runtime] = await Promise.all([
        fetchExtensionCatalog(),
        fetchEffectiveExtensionControls(),
        fetchRuntimeSnapshot({ includeItems: false, includeReceipts: false })
      ]);
      const result = evaluateProtectionHealth(catalog.catalog_digest, effective, runtime);
      if (catalog.catalog_digest !== props.catalogDigest) {
        result.status = "needs-attention";
        result.summary = "Protection data changed since this page loaded. Refresh Protection Center before making changes.";
        result.checks.push({ id: "view-freshness", label: "This page matches the latest protection catalog", passed: false });
      }
      setHealthResult(result);
    } catch (error) {
      setHealthResult(null);
      setHealthError(error instanceof Error ? error.message : "Guard could not complete the local protection health check.");
    } finally {
      setHealthBusy(false);
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(CloudContinuityIndicator, { continuity, loading: landing.runtimeLoading }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionCategoryGrid, { catalog: props.catalog, effective: props.effective }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionModuleExplorer,
      {
        modules,
        effective: props.effective,
        onOpen: props.onOpen,
        advancedFilters: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsFilterBar, { filters: props.filters, onChange: props.onFilters, onClear: props.onClearFilters, extensions: props.catalog, effective: props.effective })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(RecentProtectionDecisions, { decisions, loading: landing.activityLoading, unavailable: landing.activityError }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionHealthCheckPanel, { result: healthResult, busy: healthBusy, error: healthError, onRun: () => {
      void runHealthCheck();
    } })
  ] });
}
function currentExtensionRouteState() {
  return {
    route: parseExtensionRoute(window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search)
  };
}
function extensionRecoveryAction(health) {
  if (health === "protected") return null;
  if (health === "tampered" || health === "recovery-required") {
    return {
      title: "Repair extension controls",
      actionLabel: "Repair now",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority"
    };
  }
  if (health === "degraded-unacknowledged") {
    return {
      title: "Acknowledge degraded extension controls",
      actionLabel: "Acknowledge degraded state",
      copyLabel: "Copy status command",
      description: "Guard is failing closed because extension-control authority is degraded. Authenticate to acknowledge the degraded state. Acknowledgement does not restore protected authority.",
      command: "hol-guard status"
    };
  }
  if (health === "degraded-acknowledged") {
    return {
      title: "Degraded extension controls acknowledged",
      copyLabel: "Copy status command",
      description: "Guard remains fail-closed while extension-control authority is degraded. Restore protected authority before changing extension policy.",
      command: "hol-guard status"
    };
  }
  return {
    title: "Finish local enrollment",
    copyLabel: "Copy enrollment command",
    description: "Authenticate in this device's terminal to protect extension settings, then check again.",
    command: "hol-guard command controls enroll"
  };
}
function requiresExtensionRecoveryApproval(error) {
  return error instanceof ExtensionControlApiError && (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
}
function randomToken() {
  return crypto.randomUUID().replaceAll("-", "");
}
function buildExtensionMutation(state, change) {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: []
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled"
    });
    local.controls.sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    );
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken()
  };
}
function ExtensionStatusBanner(props) {
  const [copyState, setCopyState] = reactExports.useState("idle");
  const recovery = extensionRecoveryAction(props.effective.health);
  const handleCopy = reactExports.useCallback(async () => {
    if (!recovery) return;
    try {
      await navigator.clipboard.writeText(recovery.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }, [recovery]);
  if (props.effective.health === "protected") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 shrink-0", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Protected authority" }),
        " · revision ",
        props.effective.revision
      ] })
    ] });
  }
  const repairable = props.effective.health === "tampered" || props.effective.health === "recovery-required" || props.effective.health === "degraded-unacknowledged";
  const busyLabel = props.effective.health === "degraded-unacknowledged" ? "Acknowledging…" : "Repairing…";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-amber-200 bg-amber-50 p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-700", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: recovery?.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-slate-700", children: recovery?.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-2", children: [
        repairable && props.onRecover ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-busy": props.busy, disabled: props.busy, onClick: props.onRecover, className: "inline-flex min-h-11 items-center gap-2 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-60", children: [
          props.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4", "aria-hidden": "true" }),
          props.busy ? busyLabel : recovery?.actionLabel
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onRetry, className: "inline-flex min-h-11 items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4", "aria-hidden": "true" }),
          "Check again"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 border-t border-amber-200 pt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Command-line fallback" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-col gap-2 sm:flex-row sm:items-center", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-800", children: recovery?.command }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleCopy, className: "inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-brand-blue", children: [
            copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
            copyState === "copied" ? "Copied" : recovery?.copyLabel
          ] })
        ] }),
        copyState === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "status", className: "mt-2 block text-sm text-red-700", children: "Copy failed. Select the command above." }) : null
      ] }),
      props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm font-medium text-red-700", children: props.error }) : null,
      props.status ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-slate-800", children: props.status }) : null
    ] })
  ] }) });
}
function ReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const title = "globalLockdown" in props.change ? `${props.change.globalLockdown ? "Enable" : "Disable"} Emergency Lockdown` : `${props.change.enabled ? "Permit" : "Block"} ${props.change.extension.name}`;
  const current = "globalLockdown" in props.change ? props.change.globalLockdown ? "Off" : "Active" : props.change.enabled ? "Blocked" : "Allowed";
  const requested = "globalLockdown" in props.change ? props.change.globalLockdown ? "Active" : "Off" : props.change.enabled ? "Allowed within Guard safety rules" : "Blocked";
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, props.busy);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "protection-review-title", onSubmit: handleSubmit, className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Review protection change" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-review-title", className: "mt-2 text-xl font-semibold text-slate-950", children: title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, "aria-label": "Close review", className: "grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100 disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-slate-50 p-4 text-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: "Current" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "→" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-slate-950", children: "Requested" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: current }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", {}),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: requested })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm leading-6 text-slate-600", children: "Guard's built-in minimum safety rules and organization policy remain active. This change does not disable detection." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofFieldInputs, { approvalGate: props.approvalGate, approvalPassword: password, approvalTotpCode: totp, onApprovalPasswordChange: (event) => setPassword(event.target.value), onApprovalTotpCodeChange: (event) => setTotp(event.target.value) }) }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-slate-600 hover:bg-slate-100 disabled:opacity-50", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60", children: props.busy ? "Verifying…" : "Confirm change" })
    ] })
  ] }) });
}
function sourceIsManaged(effective, extensionId) {
  return effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some((control) => control.target_kind === "extension" && control.target_id === extensionId));
}
function ProtectionCenterWorkspace() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [routeState, setRouteState] = reactExports.useState(() => currentExtensionRouteState());
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [mutationError, setMutationError] = reactExports.useState(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = reactExports.useState(false);
  const [recoveryBusy, setRecoveryBusy] = reactExports.useState(false);
  const [recoveryError, setRecoveryError] = reactExports.useState(null);
  const [recoveryStatus, setRecoveryStatus] = reactExports.useState(null);
  const [filters, setFilters] = reactExports.useState(EMPTY_EXTENSION_FILTERS);
  const [density, setDensity] = useProtectionDensity();
  const [provenanceOpen, setProvenanceOpen] = reactExports.useState(false);
  const [troubleshootingOpen, setTroubleshootingOpen] = reactExports.useState(false);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = reactExports.useRef(null);
  const load = reactExports.useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      if (catalog.catalog_digest !== effective.catalog_digest) throw new Error("Protection data changed while Guard was loading. Check again before making changes.");
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Protection Center is unavailable" });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  reactExports.useEffect(() => {
    const onPopState = () => setRouteState(currentExtensionRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const catalogExtensions = reactExports.useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = reactExports.useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = reactExports.useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = reactExports.useMemo(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filtered = reactExports.useMemo(() => state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : [], [catalogExtensions, state, effectiveFilters]);
  reactExports.useEffect(() => {
    if (state.kind !== "ready" || routeState.route.kind !== "detail" || !canonicalSelected) return;
    if (routeState.route.extensionId === canonicalSelected) return;
    const key = `${routeState.route.extensionId}->${canonicalSelected}`;
    if (aliasRedirected.current === key) return;
    aliasRedirected.current = key;
    const href = extensionDetailHref(canonicalSelected, routeState.detail);
    window.history.replaceState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);
  const openExtension = reactExports.useCallback((extension2) => {
    const href = extensionDetailHref(extension2.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: extension2.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const closeExtension = reactExports.useCallback(() => {
    window.history.pushState({}, "", "/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const updateDetailState = reactExports.useCallback((next) => {
    if (!canonicalSelected) return;
    const href = extensionDetailHref(canonicalSelected, next);
    window.history.pushState({}, "", href);
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: next });
  }, [canonicalSelected]);
  const requestChange = reactExports.useCallback((change) => {
    setMutationError(null);
    void resolveApprovalGate({ failClosed: true }).then(() => setPending(change)).catch(() => setMutationError("Guard could not load local approval settings. Check the local connection and try again."));
  }, [resolveApprovalGate]);
  const confirm = reactExports.useCallback(async (credentials) => {
    if (state.kind !== "ready" || !pending) return;
    setBusy(true);
    setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      Object.assign(payload, credentials);
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a one-use proof for this protection change.");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
      setPending(null);
      await load();
    } catch (error) {
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : void 0;
      setMutationError(`${error instanceof Error ? error.message : "Protection change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally {
      setBusy(false);
    }
  }, [load, pending, state]);
  const recover = reactExports.useCallback(async (credentials) => {
    const acknowledgingDegraded = state.kind === "ready" && state.effective.health === "degraded-unacknowledged";
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(acknowledgingDegraded ? "Confirming the limited state…" : "Repairing local protection…");
    try {
      const effective = acknowledgingDegraded ? await acknowledgeDegradedExtensionControlAuthority(credentials) : await recoverExtensionControlAuthority(credentials);
      if (acknowledgingDegraded) {
        if (effective.health !== "degraded-acknowledged") throw new Error("Guard could not confirm the limited state.");
        setRecoveryStatus("The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored.");
      } else {
        if (effective.health !== "protected") throw new Error("Guard could not verify repaired protection.");
        setRecoveryStatus("Local protection repaired and verified.");
      }
      if (state.kind === "ready") setState({ ...state, effective });
      setRecoveryApprovalOpen(false);
    } catch (error) {
      if (!credentials && requiresExtensionRecoveryApproval(error)) {
        try {
          await resolveApprovalGate({ failClosed: true });
          setRecoveryApprovalOpen(true);
          setRecoveryStatus(null);
        } catch {
          setRecoveryError("Guard could not load local approval settings. Check the local connection and try again.");
          setRecoveryStatus(null);
        }
      } else {
        setRecoveryError(error instanceof Error ? error.message : "Guard could not repair local protection.");
        setRecoveryStatus(null);
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [resolveApprovalGate, state]);
  if (state.kind === "loading") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "grid min-h-[60vh] place-items-center", "aria-busy": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-7 animate-spin text-brand-blue motion-reduce:animate-none", "aria-label": "Loading Protection Center" }) });
  if (state.kind === "error") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "mx-auto max-w-4xl p-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-red-200 bg-red-50 p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-xl font-semibold text-red-950", children: "Protection Center unavailable" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-2 text-sm text-red-800", children: state.message }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: load, className: "mt-4 min-h-11 rounded-xl bg-red-700 px-4 text-sm font-semibold text-white", children: "Try again" })
  ] }) });
  const recoveryModal = recoveryApprovalOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(
    ApprovalProofModal,
    {
      title: state.effective.health === "degraded-unacknowledged" ? "Confirm limited protection state" : "Repair local protection",
      detail: state.effective.health === "degraded-unacknowledged" ? "Authenticate this acknowledgement on your device. It does not restore full protection." : "Authenticate this repair on your device. Guard uses the proof once and does not store it.",
      confirmLabel: state.effective.health === "degraded-unacknowledged" ? "Acknowledge limited state" : "Repair protection",
      approvalGate: resolvedApprovalGate,
      busy: recoveryBusy,
      error: recoveryError,
      onCancel: () => {
        if (!recoveryBusy) setRecoveryApprovalOpen(false);
      },
      onConfirm: (credentials) => {
        void recover(credentials);
      }
    }
  ) : null;
  if (routeState.route.kind === "detail" && selectedExtension) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ExtensionControlCenterDetail,
        {
          extension: selectedExtension,
          effective: state.effective,
          catalogDigest: state.catalog.catalog_digest,
          urlState: routeState.detail,
          onUrlState: updateDetailState,
          onBack: closeExtension,
          onBroadControl: () => requestChange({ extension: selectedExtension, enabled: !isExtensionEnabled(state.effective, selectedExtension) })
        }
      ),
      pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, approvalGate: resolvedApprovalGate, onCancel: () => {
        if (!busy) setPending(null);
      }, onConfirm: confirm }) : null,
      recoveryModal
    ] });
  }
  if (routeState.route.kind === "detail" || routeState.route.kind === "invalid") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "mx-auto max-w-4xl p-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-amber-200 bg-amber-50 p-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-amber-950", children: "Protection module not found" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-amber-800", children: "This link does not match a protection module in the current Guard catalog." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: closeExtension, className: "mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: "Back to Protections" })
      ] }) }),
      recoveryModal
    ] });
  }
  const status = deriveProtectionStatus(state.effective);
  const locked = state.effective.health !== "protected";
  const visible = density === "simple" ? catalogExtensions : filtered;
  const handlePrimaryStatusAction = () => {
    if (status.primaryAction === "repair" || status.primaryAction === "retry-repair") {
      void recover();
    } else if (status.primaryAction === "review-lockdown") {
      requestChange({ globalLockdown: false });
    } else if (status.primaryAction === "finish-setup") {
      setDensity("advanced");
      setTroubleshootingOpen(true);
      requestAnimationFrame(() => document.getElementById("advanced-protection-controls")?.scrollIntoView({ block: "nearest" }));
    } else {
      void load();
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "mx-auto w-full max-w-6xl px-4 py-8 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "flex flex-col gap-5 border-b border-slate-200 pb-7 lg:flex-row lg:items-end lg:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.2em] text-brand-blue", children: "Local protection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-3xl font-semibold tracking-tight text-slate-950", children: PROTECTION_TERMS.pageTitle }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-600", children: "See what Guard protects on this device, understand the current behavior, and make deliberate local changes without learning internal policy terminology." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionDensityControl, { value: density, onChange: setDensity })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionStatusHero, { status, busy: recoveryBusy, onPrimaryAction: status.primaryAction === "none" ? void 0 : handlePrimaryStatusAction, children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: "Cloud continuity is separate from local protection. Signing out or losing Cloud connectivity does not turn local protection off." }) }) }),
    mutationError && !pending ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: mutationError }) }) : null,
    recoveryError ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: recoveryError }) }) : null,
    recoveryStatus ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-4 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700", children: recoveryStatus }) : null,
    density === "simple" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionLandingExperience,
      {
        catalog: catalogExtensions,
        catalogDigest: state.catalog.catalog_digest,
        effective: state.effective,
        filters,
        onFilters: (patch) => setFilters((previous) => ({ ...previous, ...patch })),
        onClearFilters: () => setFilters(EMPTY_EXTENSION_FILTERS),
        onOpen: openExtension
      }
    ) : null,
    density !== "simple" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "advanced-protection-controls", className: "mt-6 space-y-3", "aria-label": "Advanced protection controls", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { open: troubleshootingOpen, onToggle: (event) => setTroubleshootingOpen(event.currentTarget.open), className: "rounded-2xl border border-slate-200 bg-white p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold text-slate-800", children: "Troubleshooting" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionStatusBanner, { busy: recoveryBusy, effective: state.effective, error: recoveryError, status: recoveryStatus, onRecover: () => {
          void recover();
        }, onRetry: load }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: locked, onClick: () => requestChange({ globalLockdown: !state.effective.global_lockdown }), className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 disabled:opacity-50", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-4" }),
        state.effective.global_lockdown ? "Review ending Emergency Lockdown" : "Review Emergency Lockdown"
      ] })
    ] }) : null,
    density !== "simple" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-modules-heading", className: "mt-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-modules-heading", className: "text-xl font-semibold text-slate-950", children: PROTECTION_TERMS.modules }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Open a protection to understand its current behavior and available controls." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
          catalogExtensions.length,
          " available"
        ] })
      ] }),
      density !== "simple" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsFilterBar, { filters, onChange: (patch) => setFilters((previous) => ({ ...previous, ...patch })), onClear: () => setFilters(EMPTY_EXTENSION_FILTERS), extensions: catalogExtensions, effective: state.effective }) }) : null,
      visible.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-2", children: visible.map((extension2) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        ProtectionModuleRow,
        {
          name: extension2.name,
          description: extension2.description,
          behavior: extensionStateLabel(state.effective, extension2),
          required: extension2.required,
          managed: sourceIsManaged(state.effective, extension2.extension_id),
          onOpen: () => openExtension(extension2)
        },
        extension2.extension_id
      )) }) : hasActiveFilters(effectiveFilters) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-slate-900", children: "No protections match these filters." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => setFilters(EMPTY_EXTENSION_FILTERS), className: "mt-3 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: "Clear filters" })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500", children: "No protection modules are registered." })
    ] }) : null,
    density === "developer" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-8", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(TechnicalDetails, { title: "Developer policy details", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: () => setProvenanceOpen((value) => !value), "aria-expanded": provenanceOpen, className: "flex min-h-11 w-full items-center justify-between rounded-xl border border-slate-200 bg-white px-4 text-left text-sm font-semibold text-slate-800", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Policy provenance and catalog identity" }),
        provenanceOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "size-4" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "size-4" })
      ] }),
      provenanceOpen ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 grid gap-3 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl bg-white p-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs font-semibold uppercase text-slate-500", children: "Catalog digest" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-xs text-slate-700", children: state.catalog.catalog_digest })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl bg-white p-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-xs font-semibold uppercase text-slate-500", children: "Authority layers" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 text-sm text-slate-700", children: [
            state.effective.layers.length,
            " active layer",
            state.effective.layers.length === 1 ? "" : "s"
          ] })
        ] }),
        state.effective.layers.map((layer) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl bg-white p-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-4 text-emerald-600" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm", children: layer.kind })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-500", children: [
            layer.controls.length,
            " explicit controls"
          ] })
        ] }, `${layer.kind}:${layer.catalog_digest}`))
      ] }) : null
    ] }) }) : null,
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, approvalGate: resolvedApprovalGate, onCancel: () => {
      if (!busy) setPending(null);
    }, onConfirm: confirm }) : null,
    recoveryModal
  ] });
}
export {
  ExtensionStatusBanner,
  ProtectionCenterWorkspace as ExtensionsWorkspace,
  ReviewModal,
  buildExtensionMutation,
  currentExtensionRouteState,
  extensionRecoveryAction,
  requiresExtensionRecoveryApproval
};
