import { j as jsxRuntimeExports, T as Tag, f as formatRelativeTime } from "../guard-dashboard.js";
function resolveProtectionLevelCopy(level) {
  if (level === "gentle") {
    return "Monitors quietly, asks only for high-risk actions";
  }
  if (level === "balanced") {
    return "Asks before secrets and destructive commands";
  }
  if (level === "strict") {
    return "Asks more often, including new network";
  }
  if (level === "paranoid") {
    return "Asks before nearly every action";
  }
  return "Custom rules active";
}
function resolveCloudIntelCopy(state) {
  if (state === "local_only") {
    return { label: "Offline, free", detail: "Running locally with no cloud sync. Your choices stay on this machine." };
  }
  if (state === "paired_waiting") {
    return { label: "First sync in progress", detail: "Connected to Guard Cloud. Local Guard is sending the first shared proof now." };
  }
  return { label: "Synced, pro", detail: "Guard Cloud is active and syncing choices across your devices." };
}
function resolveProofStatusCopy(proofStatus) {
  if (proofStatus.state === "synced") {
    return { label: proofStatus.label, detail: proofStatus.detail, tone: "green" };
  }
  if (proofStatus.state === "pending" || proofStatus.state === "waiting") {
    return { label: proofStatus.label, detail: proofStatus.detail, tone: "blue" };
  }
  if (proofStatus.state === "sync_unavailable") {
    return {
      label: "Cloud proof not available",
      detail: "Connect to Guard Cloud to unlock cross-device proof and shared history.",
      tone: "slate"
    };
  }
  if (proofStatus.state === "failed" || proofStatus.state === "expired") {
    return { label: proofStatus.label, detail: proofStatus.detail, tone: "attention" };
  }
  return {
    label: "Local only",
    detail: "Local protection is active. Cloud proof is optional.",
    tone: "slate"
  };
}
function formatDeviceInstallationId(installationId) {
  const trimmed = installationId?.trim() ?? "";
  if (trimmed.length === 0) {
    return "local";
  }
  return trimmed.slice(0, 8);
}
function DeviceProofCard(props) {
  const copy = resolveProofStatusCopy(props.proofStatus);
  const shortId = formatDeviceInstallationId(props.device.installation_id);
  const timeValue = props.proofStatus.first_synced_at ?? props.proofStatus.runtime_session_synced_at;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-border bg-white px-5 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue", children: "Device & proof" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: copy.tone, children: copy.label })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 min-w-0 space-y-0.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm font-medium text-brand-dark", title: props.device.device_label, children: props.device.device_label }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "font-mono text-xs text-slate-400", children: [
        shortId,
        "…"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-brand-dark/80", children: copy.detail }),
    timeValue !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-400", children: formatRelativeTime(timeValue) }) : null
  ] });
}
function resolvePackageManagerProtectionCopy(protection) {
  if (protection === void 0) {
    return {
      pathLabel: "Status unknown",
      pathDetail: "Supply-chain protection data is not available for this session.",
      pathTone: "slate",
      protectedList: [],
      unprotectedList: []
    };
  }
  if (protection.path_status === "restart_required") {
    return {
      pathLabel: "Restart shell or apps to finish activation",
      pathDetail: protection.shell_profile_configured ? `Guard updated the shell profile for ${protection.shim_dir}. Open a new shell or restart AI apps so package-manager commands resolve through Guard.` : `Guard installed shims in ${protection.shim_dir}, but activation is still waiting for a fresh shell or app session.`,
      pathTone: "blue",
      protectedList: protection.protected_managers,
      unprotectedList: protection.unprotected_managers
    };
  }
  const pathInPath = protection.path_status === "in_path";
  return {
    pathLabel: pathInPath ? "Guard shim directory is in PATH" : "Guard shim directory missing from PATH",
    pathDetail: pathInPath ? `Package manager commands are intercepted via ${protection.shim_dir}.` : `The shim directory (${protection.shim_dir}) is not on PATH. Install bypass is possible for package managers that are not otherwise protected.`,
    pathTone: pathInPath ? "green" : "attention",
    protectedList: protection.protected_managers,
    unprotectedList: protection.unprotected_managers
  };
}
export {
  DeviceProofCard as D,
  resolveProtectionLevelCopy as a,
  resolvePackageManagerProtectionCopy as b,
  resolveCloudIntelCopy as r
};
