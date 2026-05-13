import { j as jsxRuntimeExports, T as Tag, d as formatRelativeTime } from "../guard-dashboard.js";
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
function DeviceProofCard(props) {
  const copy = resolveProofStatusCopy(props.proofStatus);
  const shortId = props.device.installation_id.slice(0, 8);
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
export {
  DeviceProofCard as D,
  resolveProtectionLevelCopy as r
};
