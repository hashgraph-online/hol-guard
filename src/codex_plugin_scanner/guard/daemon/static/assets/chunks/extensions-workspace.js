import { aq as fetchExtensionControlApi, r as reactExports, j as jsxRuntimeExports, ar as HiMiniArrowPath, Z as HiMiniLockClosed, y as HiMiniChevronUp, z as HiMiniChevronDown, m as HiMiniCheckCircle, q as HiMiniShieldCheck, K as HiMiniExclamationTriangle, as as HiMiniPuzzlePiece, x as HiMiniXMark } from "../guard-dashboard.js";
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
      typeof error.recovery_action === "string" ? error.recovery_action : void 0
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
function effectiveState(effective, extension) {
  const control = effective.controls.find(
    (candidate) => candidate.target.kind === "extension" && candidate.target.target_id === extension.extension_id
  );
  return extension.required || control?.state !== "disabled";
}
function StatusBanner({ effective }) {
  if (effective.health === "protected") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-5 shrink-0", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Protected authority" }),
        " · revision ",
        effective.revision
      ] })
    ] });
  }
  const tampered = effective.health === "tampered";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `rounded-2xl border p-5 ${tampered ? "border-red-200 bg-red-50" : "border-amber-200 bg-amber-50"}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: `mt-0.5 size-6 shrink-0 ${tampered ? "text-red-600" : "text-amber-600"}`, "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "font-semibold text-slate-950", children: tampered ? "Extension controls are locked" : "Finish local enrollment" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-slate-700", children: tampered ? "Guard detected authority integrity damage. Mutations remain blocked until local recovery completes." : "Enrollment requires direct confirmation in the device terminal. The dashboard cannot collect or relay this proof." }),
      !tampered ? /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-3 block w-fit rounded-lg bg-slate-950 px-3 py-2 text-xs text-white", children: "hol-guard guard command controls enroll" }) : null
    ] })
  ] }) });
}
function ExtensionCard(props) {
  const handleChange = reactExports.useCallback(() => {
    props.onChange({ extension: props.extension, enabled: !props.enabled });
  }, [props]);
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
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-auto flex items-center justify-between pt-4 text-xs text-slate-500", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: props.extension.source }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
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
  const [provenanceOpen, setProvenanceOpen] = reactExports.useState(false);
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
  const sortedExtensions = reactExports.useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((left, right) => left.name.localeCompare(right.name)) : [], [state]);
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
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(StatusBanner, { effective: state.effective }) }),
    state.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-center gap-3 rounded-2xl bg-slate-950 px-4 py-3 text-sm text-white", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-5" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Global lockdown active." }),
        " Optional extensions remain disabled regardless of individual settings."
      ] })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "installed-extensions", className: "mt-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "installed-extensions", className: "text-lg font-semibold text-slate-950", children: "Installed extensions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-slate-500", children: [
          sortedExtensions.length,
          " available"
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3", children: sortedExtensions.map((extension) => /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionCard, { extension, enabled: effectiveState(state.effective, extension), locked: locked || state.effective.global_lockdown, onChange: handleChange }, extension.extension_id)) })
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
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewModal, { change: pending, busy, error: mutationError, onCancel: handleCancel, onConfirm: handleConfirm }) : null
  ] });
}
export {
  ExtensionsWorkspace,
  buildExtensionMutation
};
