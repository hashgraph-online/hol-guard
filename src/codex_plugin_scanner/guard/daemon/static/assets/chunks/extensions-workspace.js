import { an as fetchExtensionControlApi, r as reactExports, j as jsxRuntimeExports, $ as HiMiniAdjustmentsHorizontal, ak as HiMiniMagnifyingGlass, w as HiMiniXMark, o as HiMiniShieldCheck, J as HiMiniExclamationTriangle, ao as HiMiniArrowPath, U as HiMiniClipboardDocumentCheck, V as HiMiniClipboard, Z as HiMiniLockClosed, x as HiMiniChevronUp, y as HiMiniChevronDown, l as HiMiniCheckCircle, ap as HiMiniPuzzlePiece } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal } from "./use-resolved-approval-gate.js";
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
  const payload = await response.json();
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
function fetchExtensionCatalog() {
  return request("/v1/extension-controls/catalog");
}
function fetchEffectiveExtensionControls() {
  return request("/v1/extension-controls/effective");
}
function recoverExtensionControlAuthority(credentials) {
  return request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
}
function previewExtensionMutation(payload) {
  return request("/v1/extension-controls/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}
function applyExtensionMutation(payload) {
  return request("/v1/extension-controls/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
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
  const id = extensionId.toLowerCase();
  for (const [prefix, domain] of DOMAIN_PREFIX_MAP) {
    if (id.startsWith(prefix)) return domain;
  }
  return "core";
}
function isExtensionEnabled(effective, extension) {
  if (extension.required) return true;
  const control = effective.controls.find(
    (candidate) => candidate.target.kind === "extension" && candidate.target.target_id === extension.extension_id
  );
  return control?.state !== "disabled";
}
function hasActiveFilters(filters) {
  return filters.query.trim() !== "" || filters.risk !== "all" || filters.domain !== "all" || filters.state !== "all" || filters.required !== "all";
}
function searchHaystack(extension) {
  const parts = [
    extension.name,
    extension.extension_id,
    extension.description,
    extension.source,
    ...extension.action_classes,
    ...extension.risk_classes,
    classifyDomain(extension.extension_id)
  ];
  return parts.join(" ").toLowerCase();
}
function matchExtensionQuery(extension, query) {
  const normalized = query.trim().toLowerCase();
  if (normalized === "") return true;
  const haystack = searchHaystack(extension);
  return normalized.split(/\s+/).every((token) => haystack.includes(token));
}
function filterExtensions(extensions, effective, filters) {
  const items = extensions.filter((extension) => {
    if (!matchExtensionQuery(extension, filters.query)) return false;
    if (filters.risk !== "all" && !extension.risk_classes.includes(filters.risk)) return false;
    if (filters.domain !== "all" && classifyDomain(extension.extension_id) !== filters.domain) return false;
    if (filters.required !== "all") {
      const isRequired = extension.required;
      if (filters.required === "required" && !isRequired) return false;
      if (filters.required === "optional" && isRequired) return false;
    }
    if (filters.state !== "all") {
      const enabled = isExtensionEnabled(effective, extension);
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
      const target = event.target;
      const typing = target?.tagName === "INPUT" || target?.tagName === "TEXTAREA" || target?.isContentEditable;
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
      for (const extension of props.extensions) {
        for (const risk of extension.risk_classes) {
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
function extensionRecoveryAction(health) {
  if (health === "protected") return null;
  if (health === "tampered") {
    return {
      title: "Repair extension controls",
      copyLabel: "Copy repair command",
      description: "Guard locked these settings after detecting damaged authority data. Authenticate on this device to rebuild trusted authority.",
      command: "hol-guard command controls recover-authority"
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
  const tampered = props.effective.health === "tampered";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `rounded-2xl border p-5 ${tampered ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-amber-200 bg-amber-50"}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-700", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-brand-dark", children: recovery?.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-slate-700", children: recovery?.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-2", children: [
        tampered && props.onRecover ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-busy": props.busy, disabled: props.busy, onClick: props.onRecover, className: "inline-flex min-h-10 items-center gap-2 rounded-lg bg-brand-blue px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:opacity-60", children: [
          props.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4", "aria-hidden": "true" }),
          props.busy ? "Repairing…" : "Repair now"
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onRetry, className: "inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4", "aria-hidden": "true" }),
          "Check again"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 border-t border-brand-blue/10 pt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Command-line fallback" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-col gap-2 sm:flex-row sm:items-center", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-slate-100 px-3 py-2 text-xs text-brand-dark", children: recovery?.command }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleCopy, className: "inline-flex min-h-10 shrink-0 items-center justify-center gap-2 rounded-lg border border-brand-blue/25 bg-white px-3 py-2 text-sm font-semibold text-brand-blue hover:bg-brand-blue/[0.05]", children: [
            copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
            copyState === "copied" ? "Copied" : recovery?.copyLabel
          ] })
        ] }),
        copyState === "failed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "status", className: "mt-2 block text-sm text-brand-attention", children: "Copy failed. Select the command above." }) : null
      ] }),
      props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm font-medium text-brand-attention", children: props.error }) : null,
      props.status ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-brand-dark", children: props.status }) : null
    ] })
  ] }) });
}
function ExtensionCard(props) {
  const handleChange = reactExports.useCallback(() => {
    props.onChange({ extension: props.extension, enabled: !props.enabled });
  }, [props]);
  const domain = classifyDomain(props.extension.extension_id);
  const knownRisks = props.extension.risk_classes.filter((risk) => risk in RISK_CLASS_LABELS);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "group flex min-h-52 flex-col rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_10px_30px_rgba(15,23,42,0.05)] transition hover:-translate-y-0.5 hover:border-blue-200 hover:shadow-[0_18px_45px_rgba(30,64,175,0.10)]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex size-11 items-center justify-center rounded-2xl bg-blue-50 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPuzzlePiece, { className: "size-6", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          role: "switch",
          "aria-checked": props.enabled,
          "aria-label": `${props.enabled ? "Disable" : "Enable"} ${props.extension.name}`,
          disabled: props.locked || props.extension.required,
          onClick: handleChange,
          className: `relative h-7 w-12 rounded-full transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue disabled:cursor-not-allowed disabled:opacity-50 ${props.enabled ? "bg-brand-blue" : "bg-slate-300"}`,
          children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `absolute top-1 size-5 rounded-full bg-white shadow transition ${props.enabled ? "left-6" : "left-1"}` })
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: props.extension.name }),
      props.extension.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-brand-blue", children: "Required" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 line-clamp-3 text-sm leading-6 text-slate-600", children: props.extension.description }),
    knownRisks.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-1", children: knownRisks.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `rounded-full border px-2 py-0.5 text-[10px] font-medium ${RISK_CLASS_TONE[risk].label}`, children: RISK_CLASS_LABELS[risk] }, risk)) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-auto flex items-center justify-between gap-2 pt-4 text-xs text-slate-500", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "truncate", children: [
        DOMAIN_LABELS[domain],
        " · ",
        props.extension.source
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "shrink-0", children: [
        "v",
        props.extension.version
      ] })
    ] })
  ] });
}
function ReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const passwordInput = reactExports.useRef(null);
  reactExports.useEffect(() => {
    passwordInput.current?.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && !props.busy) {
        props.onCancel();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [props.busy, props.onCancel]);
  const handlePasswordChange = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotpChange = reactExports.useCallback((event) => {
    setTotp(event.target.value);
  }, []);
  const title = "globalLockdown" in props.change ? `${props.change.globalLockdown ? "Enable" : "Disable"} global lockdown` : `${props.change.enabled ? "Enable" : "Disable"} ${props.change.extension.name}`;
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    props.onConfirm(password, totp);
  }, [password, props, totp]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", role: "presentation", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { onSubmit: handleSubmit, role: "dialog", "aria-modal": "true", "aria-labelledby": "extension-review-title", className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Review control change" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-review-title", className: "mt-2 text-xl font-semibold text-slate-950", children: title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onCancel, "aria-label": "Close review", className: "rounded-full p-2 text-slate-500 hover:bg-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-slate-50 p-4 text-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: "Current" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "→" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-slate-950", children: "Requested" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "globalLockdown" in props.change ? !props.change.globalLockdown ? "Open" : "Locked" : props.change.enabled ? "Disabled" : "Enabled" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", {}),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "globalLockdown" in props.change ? props.change.globalLockdown ? "Locked" : "Open" : props.change.enabled ? "Enabled" : "Disabled" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-5 block text-sm font-medium text-slate-700", children: [
      "Approval password",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { ref: passwordInput, type: "password", autoComplete: "current-password", value: password, onChange: handlePasswordChange, className: "mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block text-sm font-medium text-slate-700", children: [
      "Authenticator code",
      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { inputMode: "numeric", autoComplete: "one-time-code", value: totp, onChange: handleTotpChange, className: "mt-2 w-full rounded-xl border border-slate-300 px-3 py-2.5 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100" })
    ] }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 rounded-xl bg-red-50 px-3 py-2 text-sm text-red-700", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onCancel, className: "rounded-xl px-4 py-2.5 text-sm font-semibold text-slate-600 hover:bg-slate-100", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: props.busy, className: "rounded-xl bg-brand-blue px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:opacity-60", children: props.busy ? "Verifying…" : "Confirm change" })
    ] })
  ] }) });
}
function ExtensionsWorkspace() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [mutationError, setMutationError] = reactExports.useState(null);
  const [recoveryApprovalOpen, setRecoveryApprovalOpen] = reactExports.useState(false);
  const [recoveryBusy, setRecoveryBusy] = reactExports.useState(false);
  const [recoveryError, setRecoveryError] = reactExports.useState(null);
  const [recoveryStatus, setRecoveryStatus] = reactExports.useState(null);
  const [provenanceOpen, setProvenanceOpen] = reactExports.useState(false);
  const [filters, setFilters] = reactExports.useState(EMPTY_EXTENSION_FILTERS);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const load = reactExports.useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      setState({ kind: "ready", catalog, effective });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Extension controls are unavailable" });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  const locked = state.kind !== "ready" || state.effective.health !== "protected";
  const catalogExtensions = reactExports.useMemo(
    () => state.kind === "ready" ? [...state.catalog.extensions].sort((left, right) => left.name.localeCompare(right.name)) : [],
    [state]
  );
  const debouncedQuery = useDebounce(filters.query, 120);
  const effectiveFilters = reactExports.useMemo(() => ({ ...filters, query: debouncedQuery }), [filters, debouncedQuery]);
  const filteredExtensions = reactExports.useMemo(
    () => state.kind === "ready" ? filterExtensions(catalogExtensions, state.effective, effectiveFilters) : [],
    [catalogExtensions, state, effectiveFilters]
  );
  const updateFilters = reactExports.useCallback((patch) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  }, []);
  const clearFilters = reactExports.useCallback(() => setFilters(EMPTY_EXTENSION_FILTERS), []);
  const handleChange = reactExports.useCallback((change) => {
    setMutationError(null);
    setPending(change);
  }, []);
  const handleCancel = reactExports.useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const handleConfirm = reactExports.useCallback(async (password, totp) => {
    if (state.kind !== "ready" || pending === null) return;
    setBusy(true);
    setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      payload.approval_password = password;
      payload.approval_totp_code = totp;
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a mutation proof");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
      setPending(null);
      await load();
    } catch (error) {
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : void 0;
      setMutationError(`${error instanceof Error ? error.message : "Change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally {
      setBusy(false);
    }
  }, [load, pending, state]);
  const recoverAuthority = reactExports.useCallback(async (credentials) => {
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus("Repairing extension controls…");
    try {
      const effective = await recoverExtensionControlAuthority(credentials);
      if (effective.health !== "protected") throw new Error("Guard could not restore protected extension controls.");
      if (state.kind === "ready") setState({ ...state, effective });
      setRecoveryApprovalOpen(false);
      setRecoveryStatus("Extension controls repaired.");
    } catch (error) {
      if (credentials === void 0 && requiresExtensionRecoveryApproval(error)) {
        await resolveApprovalGate();
        setRecoveryApprovalOpen(true);
      } else {
        setRecoveryError(error instanceof Error ? error.message : "Guard could not repair extension controls.");
        setRecoveryStatus(null);
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [resolveApprovalGate, state]);
  const handleRecover = reactExports.useCallback(() => {
    void recoverAuthority();
  }, [recoverAuthority]);
  const handleRecoveryConfirm = reactExports.useCallback((credentials) => {
    void recoverAuthority(credentials);
  }, [recoverAuthority]);
  const handleRecoveryCancel = reactExports.useCallback(() => {
    if (!recoveryBusy) setRecoveryApprovalOpen(false);
  }, [recoveryBusy]);
  const toggleProvenance = reactExports.useCallback(() => setProvenanceOpen((value) => !value), []);
  const toggleLockdown = reactExports.useCallback(() => {
    if (state.kind === "ready") handleChange({ globalLockdown: !state.effective.global_lockdown });
  }, [handleChange, state]);
  if (state.kind === "loading") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "grid min-h-[60vh] place-items-center", "aria-busy": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-7 animate-spin text-brand-blue" }) });
  if (state.kind === "error") return /* @__PURE__ */ jsxRuntimeExports.jsx("main", { className: "mx-auto max-w-5xl p-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-red-200 bg-red-50 p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-red-950", children: "Extensions unavailable" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-red-700", children: state.message }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: load, className: "mt-4 rounded-xl bg-red-700 px-4 py-2 text-sm font-semibold text-white", children: "Try again" })
  ] }) });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "flex flex-col gap-5 border-b border-slate-200 pb-7 sm:flex-row sm:items-end sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.22em] text-brand-blue", children: "Command safety" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-3xl font-semibold tracking-tight text-slate-950", children: "Extensions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-600", children: "Inspect and govern the capabilities Guard uses to understand development commands." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: toggleLockdown, disabled: locked, className: `inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold ${state.effective.global_lockdown ? "bg-red-700 text-white" : "border border-slate-300 bg-white text-slate-700"} disabled:opacity-50`, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-4" }),
        state.effective.global_lockdown ? "Disable lockdown" : "Enable lockdown"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionStatusBanner, { busy: recoveryBusy, effective: state.effective, error: recoveryError, status: recoveryStatus, onRecover: handleRecover, onRetry: load }) }),
    state.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-center gap-3 rounded-2xl bg-slate-950 px-4 py-3 text-sm text-white", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-5" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Global lockdown active." }),
        " Optional extensions remain disabled regardless of individual settings."
      ] })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "installed-extensions", className: "mt-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "installed-extensions", className: "text-lg font-semibold text-slate-950", children: "Installed extensions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
            catalogExtensions.length,
            " available"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Search by name or command, or filter by risk, domain, or state to govern capabilities." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsFilterBar, { filters, onChange: updateFilters, onClear: clearFilters, extensions: catalogExtensions, effective: state.effective }) }),
      filteredExtensions.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3", children: filteredExtensions.map((extension) => /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionCard, { extension, enabled: isExtensionEnabled(state.effective, extension), locked: locked || state.effective.global_lockdown, onChange: handleChange }, extension.extension_id)) }) : hasActiveFilters(effectiveFilters) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-col items-center gap-3 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "size-7 text-slate-300", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-slate-900", children: "No extensions match these filters" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "max-w-sm text-sm text-slate-500", children: [
          "Try a different search term, or clear the active filters to see all ",
          catalogExtensions.length,
          " extensions."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: clearFilters, className: "mt-1 rounded-xl bg-brand-blue px-4 py-2 text-sm font-semibold text-white hover:bg-brand-dark", children: "Clear filters" })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-12 text-center text-sm text-slate-500", children: "No extensions are registered." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8 overflow-hidden rounded-3xl border border-slate-200 bg-white", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: toggleProvenance, "aria-expanded": provenanceOpen, className: "flex w-full items-center justify-between p-5 text-left", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block font-semibold text-slate-950", children: "Policy provenance" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-1 block text-sm text-slate-500", children: [
            "Catalog ",
            state.catalog.catalog_digest.slice(0, 12),
            "… · ",
            state.effective.layers.length,
            " authority layer",
            state.effective.layers.length === 1 ? "" : "s"
          ] })
        ] }),
        provenanceOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "size-5" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "size-5" })
      ] }),
      provenanceOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-200 p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: state.effective.layers.map((layer) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl bg-slate-50 p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-5 text-emerald-600" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-slate-900", children: layer.kind === "local-admin" ? "Local administrator" : "Signed cloud policy" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-slate-500", children: [
          layer.controls.length,
          " explicit controls · catalog ",
          layer.catalog_digest.slice(0, 12),
          "…"
        ] })
      ] }, `${layer.kind}-${layer.catalog_digest}`)) }) }) : null
    ] }),
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, onCancel: handleCancel, onConfirm: handleConfirm }) : null,
    recoveryApprovalOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofModal, { title: "Repair extension controls", detail: "Authenticate this repair on your device. Guard uses the proof once and does not store it.", confirmLabel: "Repair controls", approvalGate: resolvedApprovalGate, busy: recoveryBusy, error: recoveryError, onCancel: handleRecoveryCancel, onConfirm: handleRecoveryConfirm }) : null
  ] });
}
export {
  ExtensionStatusBanner,
  ExtensionsWorkspace,
  buildExtensionMutation,
  extensionRecoveryAction,
  requiresExtensionRecoveryApproval
};
