import { j as jsxRuntimeExports, S as SectionLabel, o as HiMiniXMark, B as Badge, ac as Tag, aD as scopeLabel, A as ActionButton, m as formatRelativeTime, aE as HiMiniDocumentText, d as HiMiniCheckCircle, aF as HiMiniCloudArrowUp, aG as HiMiniCheck, h as harnessDisplayName, r as reactExports, aH as createCloudExceptionRequest, b as EmptyState, ad as HiMiniMagnifyingGlass, p as HiMiniChevronUp, q as HiMiniChevronDown, y as HiMiniChevronRight, aA as HiMiniCommandLine, aI as HiMiniFolder, aJ as HiMiniPuzzlePiece, aK as HiMiniGlobeAlt, aL as policyActionLabel, aM as fetchCloudExceptions, aN as fetchCloudExceptionRequests, aO as HiMiniClipboardDocument, aP as guardAwareHref, Q as HiMiniLockClosed, ax as HiMiniTrash, aQ as HiMiniCube, l as HiMiniShieldCheck, aw as HiMiniArrowPath, aR as HiMiniUsers, Y as fetchSettings, _ as updateSettings, aS as HiMiniQueueList, t as HiMiniCloud, aT as HiMiniNoSymbol, aU as HiMiniArrowRight, aV as HiMiniBeaker, aW as HiMiniPlay, aB as WorkspacePageHeader, aC as __vitePreload } from "../guard-dashboard.js";
const CLOUD_EXCEPTION_EXPIRING_SOON_DAYS = 7;
function parseCloudExceptionTimestamp(value) {
  if (!value || !value.trim()) {
    return null;
  }
  const normalized = value.replace("Z", "+00:00");
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}
function resolveCloudExceptionExpiryValue(item) {
  const expiry = item.expiry?.trim();
  if (expiry) {
    return expiry;
  }
  const legacyExpiry = item.expires_at?.trim();
  return legacyExpiry || null;
}
function resolveCloudExceptionExpiryTimestamp(item) {
  return parseCloudExceptionTimestamp(resolveCloudExceptionExpiryValue(item));
}
function isCloudExceptionActive(item, now = /* @__PURE__ */ new Date()) {
  const expiry = resolveCloudExceptionExpiryTimestamp(item);
  if (expiry === null) {
    return false;
  }
  return expiry.getTime() > now.getTime();
}
function isCloudExceptionExpiringSoon(item, now = /* @__PURE__ */ new Date(), withinDays = CLOUD_EXCEPTION_EXPIRING_SOON_DAYS) {
  if (!isCloudExceptionActive(item, now)) {
    return false;
  }
  const expiry = resolveCloudExceptionExpiryTimestamp(item);
  if (expiry === null) {
    return false;
  }
  const thresholdMs = now.getTime() + withinDays * 24 * 60 * 60 * 1e3;
  return expiry.getTime() <= thresholdMs;
}
function isCloudExceptionAckFailure(item) {
  return item.ack_status === "failed" || item.ack_status === "offline";
}
function resolveCloudExceptionScopeTarget(item) {
  if (typeof item.artifact_id === "string" && item.artifact_id.trim()) {
    return item.artifact_id.trim();
  }
  if (item.scope === "artifact" && item.id.startsWith("artifact:")) {
    return item.id.slice("artifact:".length);
  }
  if (typeof item.publisher === "string" && item.publisher.trim()) {
    return item.publisher.trim();
  }
  if (item.scope === "publisher" && item.id.startsWith("publisher:")) {
    return item.id.slice("publisher:".length);
  }
  if (item.harness) {
    return item.harness;
  }
  if (item.scope === "harness" && item.id.startsWith("harness:")) {
    return item.id.slice("harness:".length);
  }
  return item.id;
}
function resolveCloudExceptionHeadline(item) {
  const target = resolveCloudExceptionScopeTarget(item);
  if (item.scope === "artifact" && target) {
    return target;
  }
  if (item.scope === "publisher" && target) {
    return `Publisher ${target}`;
  }
  if (item.scope === "harness" && target) {
    return `${target} harness`;
  }
  if (item.scope === "workspace") {
    return "Workspace scope";
  }
  if (item.scope === "global") {
    return "Global risk acceptance";
  }
  return item.id;
}
function resolvePersonDisplayLabel(value) {
  if (!value || !value.trim()) {
    return "Unknown";
  }
  const trimmed = value.trim();
  if (trimmed.includes("@")) {
    const localPart = trimmed.split("@")[0] ?? trimmed;
    return localPart.replace(/[._-]+/g, " ").trim() || trimmed;
  }
  return trimmed;
}
function resolvePersonInitials(value) {
  const label = resolvePersonDisplayLabel(value);
  const parts = label.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[0]?.[0] ?? ""}${parts[1]?.[0] ?? ""}`.toUpperCase();
  }
  return label.slice(0, 2).toUpperCase();
}
function resolveCloudExceptionBlastRadius(scope) {
  if (scope === "artifact") {
    return {
      label: "Narrow",
      detail: "Applies to one artifact fingerprint only.",
      tone: "narrow"
    };
  }
  if (scope === "publisher") {
    return {
      label: "Medium",
      detail: "Applies to packages and plugins from one publisher.",
      tone: "medium"
    };
  }
  if (scope === "harness") {
    return {
      label: "Medium",
      detail: "Applies across one harness on this device.",
      tone: "medium"
    };
  }
  if (scope === "workspace") {
    return {
      label: "Wide",
      detail: "Applies within the current project workspace.",
      tone: "wide"
    };
  }
  return {
    label: "Wide",
    detail: "Applies as a global Cloud risk acceptance.",
    tone: "wide"
  };
}
function resolveCloudExceptionWhyCopy(item) {
  if (item.rejection_reason?.trim()) {
    return item.rejection_reason.trim();
  }
  const blast = resolveCloudExceptionBlastRadius(item.scope);
  return `Cloud-approved risk acceptance (${blast.detail.toLowerCase()}) synced from a signed policy bundle.`;
}
function resolveCloudExceptionEffectLabel(effect) {
  if (effect === "allow") {
    return "Allow temporarily";
  }
  return effect;
}
function resolveCloudExceptionEvidenceUrl(item) {
  const receiptId = item.source_receipt_id?.trim();
  if (!receiptId) {
    return null;
  }
  return `/evidence?receipt_id=${encodeURIComponent(receiptId)}`;
}
function resolveCloudExceptionScopePath(item) {
  const target = resolveCloudExceptionScopeTarget(item);
  if (!target) {
    return null;
  }
  if (item.scope === "workspace" || item.scope === "publisher") {
    return target;
  }
  return null;
}
function summarizeCloudExceptions(exceptions, pendingRequests, now = /* @__PURE__ */ new Date()) {
  const active = exceptions.filter((item) => isCloudExceptionActive(item, now));
  const expiringSoon = active.filter((item) => isCloudExceptionExpiringSoon(item, now));
  const ackFailures = active.filter((item) => isCloudExceptionAckFailure(item));
  const pending = pendingRequests.filter((item) => item.status === "pending");
  return {
    activeCount: active.length,
    pendingCount: pending.length,
    expiringSoonCount: expiringSoon.length,
    ackFailureCount: ackFailures.length
  };
}
function groupCloudExceptions(exceptions, pendingRequests, now = /* @__PURE__ */ new Date()) {
  const active = exceptions.filter((item) => isCloudExceptionActive(item, now)).sort((left, right) => {
    const leftExpiry = resolveCloudExceptionExpiryTimestamp(left)?.getTime() ?? Number.MAX_SAFE_INTEGER;
    const rightExpiry = resolveCloudExceptionExpiryTimestamp(right)?.getTime() ?? Number.MAX_SAFE_INTEGER;
    return leftExpiry - rightExpiry;
  });
  const pending = pendingRequests.filter((item) => item.status === "pending").sort(
    (left, right) => (parseCloudExceptionTimestamp(right.requestedAt)?.getTime() ?? 0) - (parseCloudExceptionTimestamp(left.requestedAt)?.getTime() ?? 0)
  );
  const expiringSoon = active.filter((item) => isCloudExceptionExpiringSoon(item, now));
  const ackFailures = active.filter((item) => isCloudExceptionAckFailure(item));
  return { active, pending, expiringSoon, ackFailures };
}
function PersonRow({
  label,
  value
}) {
  const display = resolvePersonDisplayLabel(value);
  const initials = resolvePersonInitials(value);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        "aria-hidden": "true",
        className: "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-xs font-semibold text-brand-blue",
        children: initials
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-words text-sm font-medium text-brand-dark", children: display })
    ] })
  ] });
}
function DetailField({ label, value }) {
  if (!value) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-all text-sm text-brand-dark", children: value })
  ] });
}
function resolveAckCopy(item) {
  if (item.ack_status === "synced") {
    return { label: "Acknowledged", detail: "This device acknowledged the signed policy bundle." };
  }
  if (item.ack_status === "pending") {
    return { label: "Pending ack", detail: "Waiting for this device to acknowledge the signed bundle on next sync." };
  }
  if (item.ack_status === "failed") {
    return {
      label: "Ack failed",
      detail: item.rejection_reason?.trim() || "The local daemon could not acknowledge this exception bundle."
    };
  }
  if (item.ack_status === "offline") {
    return {
      label: "Offline",
      detail: "This device was offline when the signed bundle was issued."
    };
  }
  return { label: "Unknown", detail: "Local acknowledgement status is unavailable." };
}
function ExpiryTimeline({
  expiryTimestamp,
  expiryValue
}) {
  if (!expiryTimestamp || !expiryValue) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between text-[11px] font-medium text-slate-500", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Approved" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Expires ",
        formatRelativeTime(expiryValue)
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-full w-2/3 rounded-full bg-brand-blue/70", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-slate-600", children: expiryTimestamp.toLocaleString() })
  ] });
}
function blastRadiusBadgeTone(tone) {
  if (tone === "narrow") {
    return "success";
  }
  if (tone === "medium") {
    return "warning";
  }
  return "destructive";
}
function PolicyCloudExceptionDetailPanel({
  exception,
  cloudControlsUrl,
  onClose
}) {
  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(exception);
  const expiryValue = resolveCloudExceptionExpiryValue(exception);
  const ackCopy = resolveAckCopy(exception);
  const headline = resolveCloudExceptionHeadline(exception);
  const blast = resolveCloudExceptionBlastRadius(exception.scope);
  const whyCopy = resolveCloudExceptionWhyCopy(exception);
  const isActive = isCloudExceptionActive(exception);
  const isEnforcedLocally = exception.ack_status === "synced";
  const evidenceUrl = resolveCloudExceptionEvidenceUrl(exception);
  const scopePath = resolveCloudExceptionScopePath(exception);
  const effectLabel = resolveCloudExceptionEffectLabel(exception.effect);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "aside",
    {
      className: "min-w-0 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm lg:sticky lg:top-4",
      "aria-label": "Cloud exception details",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex min-w-0 items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Temporary cloud exception" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1 break-words text-lg font-semibold text-brand-dark", children: headline }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: effectLabel })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: onClose,
              className: "rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-brand-dark",
              "aria-label": "Close exception detail",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex flex-wrap gap-2", children: [
          isActive ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Active" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Expired" }),
          isEnforcedLocally ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Enforced locally" }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: effectLabel }),
          !isEnforcedLocally ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: ackCopy.label }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Why this exists" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-brand-dark", children: whyCopy })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 sm:grid-cols-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Blast radius" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: blastRadiusBadgeTone(blast.tone), children: blast.label }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: blast.detail })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Scope (exact)" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: scopeLabel(exception.scope, "policy") }) }),
              scopePath ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 break-all text-sm text-slate-600", children: scopePath }) : null
            ] })
          ] }),
          evidenceUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Source review item" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-medium text-brand-dark", children: exception.source_receipt_id?.trim() ?? "Linked approval record" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: evidenceUrl, variant: "secondary", children: "Open in Review" }) })
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(PersonRow, { label: "Owner", value: exception.owner }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(PersonRow, { label: "Approved by", value: exception.approver }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Expiry timeline" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark", children: expiryTimestamp && expiryValue ? `${expiryTimestamp.toLocaleString()} (${formatRelativeTime(expiryValue)})` : expiryValue ?? "Expiry unavailable" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(ExpiryTimeline, { expiryTimestamp, expiryValue }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              DetailField,
              {
                label: "Last used",
                value: exception.last_used_at ? formatRelativeTime(exception.last_used_at) : null
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DetailField, { label: "Harness", value: exception.harness }),
          exception.bundle_hash ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Signed bundle entry" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-start gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all text-sm font-medium text-brand-dark", children: exception.bundle_hash }),
                exception.source_receipt_id ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-all text-xs text-slate-500", children: exception.source_receipt_id }) : null
              ] })
            ] })
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Local daemon acknowledgement" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-center gap-2", children: [
              exception.ack_status === "synced" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-emerald-600", "aria-hidden": "true" }) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: ackCopy.label })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: ackCopy.detail }),
            isCloudExceptionAckFailure(exception) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-slate-500", children: "Run Guard sync to retry bundle acknowledgement." }) : null
          ] })
        ] }),
        cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Open Guard Cloud to revoke or renew this exception." }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
            "Open in Guard Cloud"
          ] })
        ] }) : null
      ]
    }
  );
}
const REQUEST_STEPS = ["Source", "Scope", "Guardrails", "Submit"];
function RequestStepper({ activeStep }) {
  const activeIndex = REQUEST_STEPS.indexOf(activeStep);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "flex flex-wrap gap-2", "aria-label": "Request steps", children: REQUEST_STEPS.map((step, index) => {
    const complete = index < activeIndex;
    const active = index === activeIndex;
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "li",
      {
        className: `flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${active ? "border-brand-blue bg-brand-blue/10 text-brand-blue" : complete ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-200 bg-slate-50 text-slate-500"}`,
        "aria-current": active ? "step" : void 0,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "span",
            {
              className: `inline-flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-semibold ${active ? "bg-brand-blue text-white" : complete ? "bg-emerald-600 text-white" : "bg-slate-200 text-slate-600"}`,
              children: complete ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { className: "h-3 w-3", "aria-hidden": "true" }) : index + 1
            }
          ),
          step
        ]
      },
      step
    );
  }) });
}
const SCOPE_CARD_TONES = {
  narrow: "border-emerald-200 bg-emerald-50/70 hover:border-emerald-300",
  medium: "border-amber-200 bg-amber-50/60 hover:border-amber-300",
  wide: "border-rose-200 bg-rose-50/50 hover:border-rose-300"
};
function ScopeCardGrid({ options, value, onChange }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2 sm:grid-cols-2", role: "radiogroup", "aria-label": "Exception scope", children: options.map((option) => {
    const blast = resolveCloudExceptionBlastRadius(option.value);
    const selected = value === option.value;
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        role: "radio",
        "aria-checked": selected,
        onClick: () => onChange(option.value),
        className: `rounded-xl border p-3 text-left transition ${selected ? `${SCOPE_CARD_TONES[blast.tone]} ring-2 ring-brand-blue/30` : `${SCOPE_CARD_TONES[blast.tone]} opacity-90`}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: option.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-600", children: option.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-[11px] font-medium uppercase tracking-wide text-slate-500", children: [
            "Blast radius · ",
            blast.label
          ] })
        ]
      },
      option.value
    );
  }) });
}
function SafetyPreview({
  scope,
  harness,
  artifactId,
  publisher,
  workingDirectory,
  reason,
  expiresLabel
}) {
  const blast = resolveCloudExceptionBlastRadius(scope);
  const scopeTarget = scope === "artifact" ? artifactId || "Selected artifact" : scope === "publisher" ? publisher || "Publisher" : scope === "harness" ? harness : scope === "workspace" ? workingDirectory || "Project folder" : "Global";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-slate-50/80 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Safety preview" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 space-y-3 text-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-500", children: "Scope" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-medium text-brand-dark", children: scopeLabel(scope, "policy") })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-500", children: "Target" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "break-all font-medium text-brand-dark", children: scopeTarget })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-500", children: "Blast radius" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-brand-dark", children: blast.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-xs text-slate-600", children: blast.detail })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-500", children: "Expires" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-brand-dark", children: expiresLabel })
      ] }),
      reason.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-500", children: "Reason" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-brand-dark", children: reason.trim() })
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs leading-relaxed text-slate-500", children: "Guard Cloud must approve this request before it syncs as a signed bundle entry on this device." })
  ] });
}
function SourceReceiptSummary({ receipt }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-slate-50/80 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Source: approval record" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: receipt.artifact_name ?? receipt.artifact_id }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
      harnessDisplayName(receipt.harness),
      " · ",
      receipt.receipt_id
    ] })
  ] });
}
function ResultPreview({ scope, harness, expiresLabel }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-white p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Result preview" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-sm leading-relaxed text-brand-dark", children: [
      "If approved in Guard Cloud, Guard will apply this exception for ",
      scopeLabel(scope, "policy"),
      harness.trim() ? ` in ${harnessDisplayName(harness)}` : "",
      " until ",
      expiresLabel,
      "."
    ] })
  ] });
}
function RequestModalShell({ title, stepper, children, footer, onCancel }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-900/45 p-4 sm:p-6",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "cloud-exception-request-title",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full max-w-6xl rounded-2xl border border-slate-200 bg-white shadow-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cloud-exception-request-title", className: "text-lg font-semibold text-brand-dark", children: title }),
            stepper
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: onCancel,
              className: "rounded-lg px-2 py-1 text-sm font-medium text-slate-500 hover:bg-slate-100 hover:text-brand-dark",
              children: "Close"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-5 py-5", children }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-5 py-4", children: footer })
      ] })
    }
  );
}
const SCOPE_OPTIONS = [
  {
    value: "artifact",
    label: "Exact action",
    description: "Limit the exception to one specific action fingerprint."
  },
  {
    value: "publisher",
    label: "This cwd",
    description: "Reuse within the current working directory scope."
  },
  {
    value: "workspace",
    label: "This project",
    description: "Apply within the current project folder on this device."
  },
  {
    value: "harness",
    label: "This harness",
    description: "Apply across one harness such as Codex or Cursor."
  }
];
function defaultExpiryIso() {
  const date = /* @__PURE__ */ new Date();
  date.setDate(date.getDate() + 30);
  return date.toISOString();
}
function toDatetimeLocalValue(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
function fromDatetimeLocalValue(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return (/* @__PURE__ */ new Date()).toISOString();
  }
  return date.toISOString();
}
function resolveDefaultWorkingDirectory(snapshot) {
  const install = snapshot.managed_installs?.find((entry) => entry.workspace?.trim());
  return install?.workspace?.trim() ?? "";
}
function PolicyCloudExceptionRequestPanel({
  snapshot,
  onSubmitted,
  onCancel
}) {
  const receiptOptions = snapshot.latest_receipts ?? [];
  const harnessOptions = reactExports.useMemo(() => {
    const fromReceipts = receiptOptions.map((receipt) => receipt.harness).filter(Boolean);
    const fromInstalls = (snapshot.managed_installs ?? []).map((entry) => entry.harness).filter(Boolean);
    return [.../* @__PURE__ */ new Set([...fromReceipts, ...fromInstalls, "codex", "cursor"])].sort();
  }, [receiptOptions, snapshot.managed_installs]);
  const [scope, setScope] = reactExports.useState("artifact");
  const [harness, setHarness] = reactExports.useState(harnessOptions[0] ?? "codex");
  const [artifactId, setArtifactId] = reactExports.useState(receiptOptions[0]?.artifact_id ?? "");
  const [publisher, setPublisher] = reactExports.useState("");
  const [workingDirectory, setWorkingDirectory] = reactExports.useState(resolveDefaultWorkingDirectory(snapshot));
  const [sourceReceiptId, setSourceReceiptId] = reactExports.useState(receiptOptions[0]?.receipt_id ?? "");
  const [requestedBy, setRequestedBy] = reactExports.useState("");
  const [owner, setOwner] = reactExports.useState("");
  const [reason, setReason] = reactExports.useState("");
  const [requestedExpiresAt, setRequestedExpiresAt] = reactExports.useState(defaultExpiryIso());
  const [linkedTicket, setLinkedTicket] = reactExports.useState("");
  const [maxUses, setMaxUses] = reactExports.useState("");
  const [submitting, setSubmitting] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [successMessage, setSuccessMessage] = reactExports.useState(null);
  const [stepIndex, setStepIndex] = reactExports.useState(0);
  const activeStep = REQUEST_STEPS[stepIndex] ?? "Source";
  const selectedReceipt = reactExports.useMemo(
    () => receiptOptions.find((entry) => entry.receipt_id === sourceReceiptId) ?? null,
    [receiptOptions, sourceReceiptId]
  );
  const expiryLabel = reactExports.useMemo(() => {
    const date = new Date(requestedExpiresAt);
    return Number.isNaN(date.getTime()) ? "Not set" : date.toLocaleString();
  }, [requestedExpiresAt]);
  const handleReceiptChange = reactExports.useCallback(
    (event) => {
      const receiptId = event.target.value;
      setSourceReceiptId(receiptId);
      const receipt = receiptOptions.find((entry) => entry.receipt_id === receiptId);
      if (!receipt) {
        return;
      }
      setHarness(receipt.harness);
      setArtifactId(receipt.artifact_id);
    },
    [receiptOptions]
  );
  const handleArtifactIdChange = reactExports.useCallback((event) => {
    setArtifactId(event.target.value);
  }, []);
  const handlePublisherChange = reactExports.useCallback((event) => {
    setPublisher(event.target.value);
  }, []);
  const handleHarnessChange = reactExports.useCallback((event) => {
    setHarness(event.target.value);
  }, []);
  const handleWorkingDirectoryChange = reactExports.useCallback((event) => {
    setWorkingDirectory(event.target.value);
  }, []);
  const handleRequestedByChange = reactExports.useCallback((event) => {
    setRequestedBy(event.target.value);
  }, []);
  const handleOwnerChange = reactExports.useCallback((event) => {
    setOwner(event.target.value);
  }, []);
  const handleReasonChange = reactExports.useCallback((event) => {
    setReason(event.target.value);
  }, []);
  const handleExpiryChange = reactExports.useCallback((event) => {
    setRequestedExpiresAt(fromDatetimeLocalValue(event.target.value));
  }, []);
  const handleLinkedTicketChange = reactExports.useCallback((event) => {
    setLinkedTicket(event.target.value);
  }, []);
  const handleMaxUsesChange = reactExports.useCallback((event) => {
    setMaxUses(event.target.value);
  }, []);
  const buildReasonForSubmit = reactExports.useCallback(() => {
    const parts = [reason.trim()];
    if (linkedTicket.trim()) {
      parts.push(`Ticket: ${linkedTicket.trim()}`);
    }
    if (maxUses.trim()) {
      parts.push(`Max uses: ${maxUses.trim()}`);
    }
    return parts.filter(Boolean).join("\n");
  }, [linkedTicket, maxUses, reason]);
  const handleSubmit = reactExports.useCallback(
    async (event) => {
      event.preventDefault();
      setSubmitting(true);
      setError(null);
      setSuccessMessage(null);
      const payload = {
        scope,
        requestedBy: requestedBy.trim(),
        owner: owner.trim(),
        reason: buildReasonForSubmit(),
        requestedExpiresAt,
        sourceReceiptId: sourceReceiptId.trim() || null
      };
      if (scope === "artifact") {
        payload.harness = harness.trim() || null;
        payload.artifactId = artifactId.trim() || null;
      } else if (scope === "publisher") {
        payload.publisher = publisher.trim() || null;
      } else if (scope === "harness") {
        payload.harness = harness.trim() || null;
      } else if (scope === "workspace") {
        payload.workingDirectory = workingDirectory.trim() || null;
      }
      try {
        const response = await createCloudExceptionRequest(payload);
        const created = response.items.find((item) => item.status === "pending") ?? response.items[0];
        setSuccessMessage(
          created ? `Cloud exception request ${created.requestId} is pending Guard Cloud review.` : "Cloud exception request submitted."
        );
      } catch (submitError) {
        const message = submitError instanceof Error && submitError.message.trim() ? submitError.message : "Unable to submit the Cloud exception request.";
        setError(message);
      } finally {
        setSubmitting(false);
      }
    },
    [
      artifactId,
      buildReasonForSubmit,
      harness,
      owner,
      publisher,
      requestedBy,
      requestedExpiresAt,
      scope,
      sourceReceiptId,
      workingDirectory
    ]
  );
  const handleDone = reactExports.useCallback(() => {
    onSubmitted();
  }, [onSubmitted]);
  const canAdvanceFromSource = Boolean(sourceReceiptId.trim());
  const canAdvanceFromScope = (scope !== "artifact" || artifactId.trim()) && (scope !== "publisher" || publisher.trim()) && (scope !== "workspace" || workingDirectory.trim()) && (scope === "harness" || scope === "artifact" ? harness.trim() : true) && reason.trim().length > 0 && owner.trim().length > 0 && requestedExpiresAt.trim().length > 0;
  const canAdvanceFromGuardrails = requestedBy.trim().length > 0;
  const canSubmit = canAdvanceFromSource && canAdvanceFromScope && canAdvanceFromGuardrails;
  const handleBack = reactExports.useCallback(() => {
    setStepIndex((current) => Math.max(0, current - 1));
  }, []);
  const handleNext = reactExports.useCallback(() => {
    setStepIndex((current) => Math.min(REQUEST_STEPS.length - 1, current + 1));
  }, []);
  if (receiptOptions.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      RequestModalShell,
      {
        title: "Request cloud exception",
        stepper: /* @__PURE__ */ jsxRuntimeExports.jsx(RequestStepper, { activeStep: "Source" }),
        onCancel,
        footer: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onCancel, children: "Back" }),
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Source receipt required" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Guard needs at least one receipt on this device to anchor a Cloud exception request. Run a protected action first, then return here from Evidence or Inbox." })
        ]
      }
    );
  }
  if (successMessage) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      RequestModalShell,
      {
        title: "Request submitted",
        stepper: /* @__PURE__ */ jsxRuntimeExports.jsx(RequestStepper, { activeStep: "Submit" }),
        onCancel,
        footer: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: handleDone, children: "Done" }),
        children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-emerald-800", children: successMessage })
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    RequestModalShell,
    {
      title: "Request cloud exception",
      stepper: /* @__PURE__ */ jsxRuntimeExports.jsx(RequestStepper, { activeStep }),
      onCancel,
      footer: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: onCancel, disabled: submitting, children: "Cancel" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          stepIndex > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: handleBack, disabled: submitting, children: "Back" }) : null,
          activeStep !== "Submit" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            ActionButton,
            {
              variant: "primary",
              type: "button",
              onClick: handleNext,
              disabled: submitting || activeStep === "Source" && !canAdvanceFromSource || activeStep === "Scope" && !canAdvanceFromScope || activeStep === "Guardrails" && !canAdvanceFromGuardrails,
              children: "Next"
            }
          ) : /* @__PURE__ */ jsxRuntimeExports.jsx("form", { onSubmit: handleSubmit, children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", type: "submit", disabled: submitting || !canSubmit, children: submitting ? "Submitting…" : "Submit to Guard Cloud" }) })
        ] })
      ] }),
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-4 text-sm text-brand-dark/75", children: "Ask Guard Cloud to create a policy override. Local Review handles reusable approvals." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_280px] lg:items-start", children: [
          activeStep === "Source" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 lg:col-span-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Source" }),
            selectedReceipt ? /* @__PURE__ */ jsxRuntimeExports.jsx(SourceReceiptSummary, { receipt: selectedReceipt }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Or choose a different record" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "select",
                {
                  className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                  value: sourceReceiptId,
                  onChange: handleReceiptChange,
                  required: true,
                  children: receiptOptions.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: receipt.receipt_id, children: [
                    harnessDisplayName(receipt.harness),
                    " · ",
                    receipt.artifact_name ?? receipt.artifact_id
                  ] }, receipt.receipt_id))
                }
              )
            ] })
          ] }) : null,
          activeStep === "Scope" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-4 lg:col-start-1", children: selectedReceipt ? /* @__PURE__ */ jsxRuntimeExports.jsx(SourceReceiptSummary, { receipt: selectedReceipt }) : null }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-xl border border-slate-100 bg-slate-50/50 p-4 lg:col-start-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Scope" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Choose the narrowest scope that solves the problem." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(ScopeCardGrid, { options: SCOPE_OPTIONS, value: scope, onChange: setScope }),
              scope === "artifact" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Artifact fingerprint" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                    value: artifactId,
                    onChange: handleArtifactIdChange,
                    required: true
                  }
                )
              ] }) : null,
              scope === "publisher" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Publisher" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                    value: publisher,
                    onChange: handlePublisherChange,
                    required: true
                  }
                )
              ] }) : null,
              scope === "harness" || scope === "artifact" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "App" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "select",
                  {
                    className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                    value: harness,
                    onChange: handleHarnessChange,
                    required: true,
                    children: harnessOptions.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option, children: harnessDisplayName(option) }, option))
                  }
                )
              ] }) : null,
              scope === "workspace" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Project folder" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                    value: workingDirectory,
                    onChange: handleWorkingDirectoryChange,
                    required: true
                  }
                )
              ] }) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Risk owner" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                    type: "email",
                    value: owner,
                    onChange: handleOwnerChange,
                    required: true
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Reason (required)" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "textarea",
                  {
                    className: "min-h-24 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                    value: reason,
                    onChange: handleReasonChange,
                    maxLength: 280,
                    required: true
                  }
                ),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
                  reason.trim().length,
                  "/280"
                ] }),
                !reason.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-red-600", children: "Reason is required." }) : null
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1 md:max-w-sm", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Requested expiry (required)" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                    type: "datetime-local",
                    value: toDatetimeLocalValue(requestedExpiresAt),
                    onChange: handleExpiryChange,
                    required: true
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 md:grid-cols-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Max uses (optional)" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                      inputMode: "numeric",
                      value: maxUses,
                      onChange: handleMaxUsesChange,
                      placeholder: "50"
                    }
                  )
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Linked ticket (optional)" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
                      value: linkedTicket,
                      onChange: handleLinkedTicketChange,
                      placeholder: "ENG-123 or URL"
                    }
                  )
                ] })
              ] }),
              scope === "harness" || scope === "workspace" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80", children: "Broad scopes require step-up authentication and Cloud approval." }) : null
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 lg:col-start-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                SafetyPreview,
                {
                  scope,
                  harness,
                  artifactId,
                  publisher,
                  workingDirectory,
                  reason,
                  expiresLabel: expiryLabel
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(ResultPreview, { scope, harness, expiresLabel: expiryLabel })
            ] })
          ] }) : null,
          activeStep === "Guardrails" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-xl border border-slate-100 bg-white p-4 lg:col-span-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guardrails" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1 md:max-w-md", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Requested by" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
                  type: "email",
                  value: requestedBy,
                  onChange: handleRequestedByChange,
                  required: true
                }
              ),
              !requestedBy.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-red-600", children: "Requested by is required." }) : null
            ] })
          ] }) : null,
          activeStep === "Submit" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3 rounded-xl border border-slate-100 bg-slate-50/50 p-4 lg:col-span-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Review and submit" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: "Guard Cloud will review this request. If approved, the exception syncs as a signed bundle entry on this device." }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid gap-2 text-sm text-slate-600", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs uppercase tracking-wide text-slate-500", children: "Scope" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-medium text-brand-dark", children: scope })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs uppercase tracking-wide text-slate-500", children: "Reason" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-brand-dark", children: reason.trim() })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs uppercase tracking-wide text-slate-500", children: "Expires" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-brand-dark", children: expiryLabel })
              ] })
            ] })
          ] }) : null,
          activeStep === "Guardrails" || activeStep === "Submit" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            SafetyPreview,
            {
              scope,
              harness,
              artifactId,
              publisher,
              workingDirectory,
              reason,
              expiresLabel: expiryLabel
            }
          ) : null,
          activeStep === "Submit" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ResultPreview, { scope, harness, expiresLabel: expiryLabel }) : null
        ] }),
        error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-red-600", children: error }) : null
      ]
    }
  );
}
const EXCEPTION_ROW_GRID = "grid grid-cols-[minmax(0,1fr)] items-center gap-x-2 gap-y-2 border-b border-slate-100 px-3 py-2.5 last:border-0 hover:bg-slate-50/80 md:grid-cols-[72px_minmax(140px,1.3fr)_88px_72px_36px_36px_88px_80px_72px]";
const EXCEPTION_HEADER_GRID = "hidden border-b border-slate-100 bg-slate-50/80 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500 md:grid md:grid-cols-[72px_minmax(140px,1.3fr)_88px_72px_36px_36px_88px_80px_72px] md:gap-x-2";
function resolveAckStatusLabel(item) {
  if (item.ack_status === "synced") {
    return { label: "Ack OK", tone: "success" };
  }
  if (isCloudExceptionAckFailure(item)) {
    return { label: "Ack issue", tone: "warning" };
  }
  if (item.ack_status === "pending") {
    return { label: "Pending", tone: "default" };
  }
  return { label: "Unknown", tone: "default" };
}
function PersonAvatar({ label }) {
  const initials = resolvePersonInitials(label);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "span",
    {
      "aria-hidden": "true",
      className: "inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-[10px] font-semibold text-brand-blue",
      title: resolvePersonDisplayLabel(label),
      children: initials
    }
  );
}
function resolveRowIcon(scope) {
  if (scope === "artifact") {
    return HiMiniCommandLine;
  }
  if (scope === "publisher" || scope === "workspace") {
    return HiMiniFolder;
  }
  if (scope === "harness") {
    return HiMiniPuzzlePiece;
  }
  return HiMiniGlobeAlt;
}
function ExceptionTableRow({
  item,
  selected,
  onSelect
}) {
  const handleSelect = reactExports.useCallback(() => onSelect(item), [item, onSelect]);
  const expiryValue = resolveCloudExceptionExpiryValue(item);
  const headline = resolveCloudExceptionHeadline(item);
  const ackStatus = resolveAckStatusLabel(item);
  const effectLabel = resolveCloudExceptionEffectLabel(item.effect);
  const RowIcon = resolveRowIcon(item.scope);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      role: "listitem",
      onClick: handleSelect,
      "aria-pressed": selected,
      className: `min-w-0 w-full text-left transition ${EXCEPTION_ROW_GRID} ${selected ? "bg-brand-blue/[0.04] ring-1 ring-inset ring-brand-blue/20" : ""}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 md:col-start-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(RowIcon, { className: "hidden h-4 w-4 shrink-0 text-slate-400 md:block", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: effectLabel })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 md:col-start-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm font-semibold text-brand-dark", children: headline }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-2 text-xs text-slate-500 md:hidden", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: scopeLabel(item.scope, "policy") }),
            item.harness ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: harnessDisplayName(item.harness) }) : null
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden md:col-start-3 md:block", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: scopeLabel(item.scope, "policy") }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden truncate text-sm text-brand-dark md:col-start-4 md:block", children: item.harness ? harnessDisplayName(item.harness) : "—" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden md:col-start-5 md:flex md:justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PersonAvatar, { label: item.owner }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden md:col-start-6 md:flex md:justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PersonAvatar, { label: item.approver }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden whitespace-nowrap text-xs text-slate-500 md:col-start-7 md:block", children: expiryValue ? formatRelativeTime(expiryValue) : "—" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden whitespace-nowrap text-xs text-slate-500 md:col-start-8 md:block", children: item.last_used_at ? formatRelativeTime(item.last_used_at) : "—" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "hidden md:col-start-9 md:flex md:items-center md:gap-1", children: [
          ackStatus.tone === "success" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 text-emerald-600", "aria-hidden": "true" }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: ackStatus.tone, children: ackStatus.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-3.5 w-3.5 text-slate-400", "aria-hidden": "true" })
        ] })
      ]
    }
  );
}
function PendingRequestRow({ item }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: `${EXCEPTION_ROW_GRID} bg-amber-50/30`, role: "listitem", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "md:col-start-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: "Pending" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 md:col-start-2 md:col-span-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-words text-sm font-semibold text-brand-dark", children: item.reason }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-slate-600", children: [
        scopeLabel(item.scope, "policy"),
        " · ",
        resolvePersonDisplayLabel(item.owner),
        " · expires",
        " ",
        formatRelativeTime(item.requestedExpiresAt)
      ] })
    ] })
  ] });
}
function GroupSection({
  title,
  count,
  defaultOpen = true,
  children
}) {
  const [open, setOpen] = reactExports.useState(defaultOpen);
  const handleToggle = reactExports.useCallback(() => setOpen((current) => !current), []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm", "aria-label": title, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: handleToggle,
        className: "flex w-full items-center justify-between gap-3 px-4 py-3 text-left",
        "aria-expanded": open,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "text-sm font-semibold text-brand-dark", children: [
            title,
            " (",
            count,
            ")"
          ] }),
          open ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" })
        ]
      }
    ),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: EXCEPTION_HEADER_GRID, "aria-hidden": "true", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Action" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Description" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Scope" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "App" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-center", children: "Owner" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-center", children: "Approver" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Expires" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Last used" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Status" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "list", children }),
      count > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 px-4 py-2.5 text-sm font-medium text-brand-blue", children: [
        "View all (",
        count,
        ") →"
      ] }) : null
    ] }) : null
  ] });
}
function ExceptionFilters({
  searchQuery,
  onSearchChange,
  scopeFilter,
  actionFilter,
  onScopeFilterChange,
  onActionFilterChange
}) {
  const handleSearchChange = reactExports.useCallback(
    (event) => onSearchChange(event.target.value),
    [onSearchChange]
  );
  const handleScopeChange = reactExports.useCallback(
    (event) => onScopeFilterChange(event.target.value),
    [onScopeFilterChange]
  );
  const handleActionChange = reactExports.useCallback(
    (event) => onActionFilterChange(event.target.value),
    [onActionFilterChange]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 lg:flex-row lg:items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "search",
          placeholder: "Search exceptions…",
          value: searchQuery,
          onChange: handleSearchChange,
          "aria-label": "Search exceptions",
          className: "w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: scopeFilter,
          onChange: handleScopeChange,
          className: "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
          "aria-label": "All scopes",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All scopes" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "artifact", children: "Once" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "publisher", children: "This cwd" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "workspace", children: "This project" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "harness", children: "This harness" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "global", children: "Team policy" })
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: actionFilter,
          onChange: handleActionChange,
          className: "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
          "aria-label": "All actions",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "all", children: "All actions" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "allow", children: "Allow" })
          ]
        }
      )
    ] })
  ] });
}
function matchesFilters(item, scopeFilter, actionFilter, searchQuery) {
  if (scopeFilter !== "all" && item.scope !== scopeFilter) {
    return false;
  }
  if (actionFilter !== "all" && item.effect !== actionFilter) {
    return false;
  }
  const query = searchQuery.trim().toLowerCase();
  if (!query) {
    return true;
  }
  const haystack = [
    resolveCloudExceptionHeadline(item),
    item.owner,
    item.approver,
    item.harness,
    item.scope,
    item.source_receipt_id
  ].filter(Boolean).join(" ").toLowerCase();
  return haystack.includes(query);
}
function PolicyCloudExceptionsListSkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", "aria-busy": "true", "aria-label": "Loading Cloud exceptions", children: [0, 1, 2].map((index) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-28 animate-pulse rounded-2xl border border-slate-100 bg-slate-100" }, index)) });
}
function PolicyCloudExceptionsList({
  active,
  pending,
  expiringSoon,
  selectedExceptionId,
  onSelectException,
  cloudConnected,
  scopeFilter,
  actionFilter,
  onScopeFilterChange,
  onActionFilterChange
}) {
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const filterActive = reactExports.useCallback(
    (items) => items.filter((item) => matchesFilters(item, scopeFilter, actionFilter, searchQuery)),
    [scopeFilter, actionFilter, searchQuery]
  );
  const expiringSoonIds = reactExports.useMemo(() => new Set(expiringSoon.map((item) => item.id)), [expiringSoon]);
  const filteredActive = reactExports.useMemo(() => filterActive(active), [active, filterActive]);
  const filteredExpiringSoon = reactExports.useMemo(() => filterActive(expiringSoon), [expiringSoon, filterActive]);
  const activeWithoutExpiringGroup = reactExports.useMemo(
    () => filteredActive.filter((item) => !expiringSoonIds.has(item.id)),
    [filteredActive, expiringSoonIds]
  );
  if (!cloudConnected) {
    return null;
  }
  const hasAnyRows = active.length > 0 || pending.length > 0;
  if (!hasAnyRows) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No Cloud exceptions synced yet",
        body: "Approved Cloud risk acceptances will appear here after Guard Cloud syncs a signed policy bundle to this device.",
        tone: "teach"
      }
    );
  }
  const hasFilteredRows = activeWithoutExpiringGroup.length > 0 || pending.length > 0 || filteredExpiringSoon.length > 0;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", "aria-label": "Cloud exception groups", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExceptionFilters,
      {
        searchQuery,
        onSearchChange: setSearchQuery,
        scopeFilter,
        actionFilter,
        onScopeFilterChange,
        onActionFilterChange
      }
    ),
    !hasFilteredRows ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No exceptions match these filters",
        body: "Try a broader search, scope, or action filter to see synced Cloud exceptions.",
        tone: "teach"
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      activeWithoutExpiringGroup.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(GroupSection, { title: "Active on this device", count: activeWithoutExpiringGroup.length, defaultOpen: true, children: activeWithoutExpiringGroup.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        ExceptionTableRow,
        {
          item,
          selected: selectedExceptionId === item.id,
          onSelect: onSelectException
        },
        item.id
      )) }) : null,
      pending.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(GroupSection, { title: "Pending in Guard Cloud", count: pending.length, defaultOpen: false, children: pending.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(PendingRequestRow, { item }, item.requestId)) }) : null,
      filteredExpiringSoon.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(GroupSection, { title: "Expiring soon", count: filteredExpiringSoon.length, defaultOpen: false, children: filteredExpiringSoon.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        ExceptionTableRow,
        {
          item,
          selected: selectedExceptionId === item.id,
          onSelect: onSelectException
        },
        `expiring-${item.id}`
      )) }) : null
    ] })
  ] });
}
const SUMMARY_TONE_CLASSES = {
  blue: "text-brand-blue",
  green: "text-emerald-700",
  amber: "text-amber-700",
  attention: "text-brand-attention",
  slate: "text-brand-dark"
};
function SummaryCard({
  label,
  value,
  detail,
  tone = "slate"
}) {
  const toneClass = SUMMARY_TONE_CLASSES[tone];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200/70 bg-white p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-2 text-3xl font-semibold tabular-nums ${toneClass}`, children: value }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: detail })
  ] });
}
function SummarySkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 gap-3 md:grid-cols-4", children: [0, 1, 2, 3].map((index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "h-[88px] animate-pulse rounded-xl border border-slate-200/70 bg-slate-100",
      "aria-hidden": "true"
    },
    index
  )) });
}
function PolicyCloudExceptionsSummary({
  activeCount,
  pendingCount,
  expiringSoonCount,
  ackFailureCount,
  loading = false
}) {
  if (loading) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(SummarySkeleton, {});
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "grid grid-cols-2 gap-3 md:grid-cols-4",
      "aria-label": "Cloud exception summary",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Active synced", value: activeCount, detail: "Enforced locally", tone: "green" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Pending approval", value: pendingCount, detail: "Awaiting decision", tone: "blue" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Expiring soon", value: expiringSoonCount, detail: "Within 7 days", tone: "amber" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Local ack failures", value: ackFailureCount, detail: "Needs attention", tone: "attention" })
      ]
    }
  );
}
const MATCHER_FAMILY_LABELS = {
  "package-request": "Package install",
  "tool-action": "Shell or tool command",
  "tool-output": "Command output review",
  prompt: "Prompt submission",
  "prompt-env-read": "Environment variable read",
  mcp: "MCP server call",
  "file-read": "File read"
};
const GENERIC_REASONS = [
  "approved in review",
  "approved in local approval center",
  "local auto-resume proof",
  "local e2e approval proof"
];
function formatPolicyScopePath(path) {
  if (!path?.trim()) {
    return null;
  }
  const value = path.trim();
  if (value.length <= 72) {
    return value;
  }
  const segments = value.split(/[/\\]/).filter(Boolean);
  if (segments.length <= 2) {
    return value;
  }
  return `…/${segments.slice(-2).join("/")}`;
}
function isCloudManagedPolicy(source) {
  return source === "cloud-sync" || source === "team-policy" || source === "policy-bundle";
}
function policyTargetLabel(policy) {
  return policy.artifact_id ?? policy.publisher ?? policy.workspace ?? "Global";
}
function isGenericReason(reason) {
  if (!reason?.trim()) {
    return true;
  }
  const normalized = reason.trim().toLowerCase();
  return GENERIC_REASONS.some((phrase) => normalized.includes(phrase));
}
function extractMatcherFamily(artifactId) {
  if (artifactId.startsWith("family:")) {
    return artifactId.slice("family:".length);
  }
  const parts = artifactId.split(":");
  for (const family of Object.keys(MATCHER_FAMILY_LABELS)) {
    if (parts.includes(family)) {
      return family;
    }
  }
  return null;
}
function resolveRuntimeActionLabel(artifactId) {
  const parts = artifactId.split(":");
  const runtimeIndex = parts.indexOf("runtime");
  if (runtimeIndex < 0) {
    return null;
  }
  const tail = parts.slice(runtimeIndex + 1);
  if (tail[0] === "global" && tail.length >= 3) {
    const tool = tail[1].replace(/-/g, " ");
    const action = tail.slice(2).join(" ").replace(/_/g, " ");
    return `${tool}: ${action}`;
  }
  return null;
}
function resolvePromptSubtypeLabel(artifactId) {
  const parts = artifactId.split(":");
  const promptIndex = parts.indexOf("prompt");
  if (promptIndex < 0) {
    return "prompt review";
  }
  const subtype = parts[promptIndex + 1];
  if (!subtype) {
    return "prompt review";
  }
  return subtype.replace(/_/g, " ");
}
function resolveWorkspaceLabel(workspace) {
  if (!workspace?.trim()) {
    return "this project";
  }
  const value = workspace.trim();
  if (value.startsWith("workspace:")) {
    return "this project";
  }
  if (value.startsWith("/") || value.startsWith("~")) {
    const segments = value.split("/").filter(Boolean);
    return segments[segments.length - 1] ?? "this project";
  }
  if (value.length > 32 && /^[a-f0-9]+$/i.test(value)) {
    return "this project";
  }
  return value;
}
function resolveActionVerb(action) {
  if (action === "allow") {
    return "Allow";
  }
  if (action === "block") {
    return "Block";
  }
  return policyActionLabel(action);
}
function resolveRememberSentence(policy, commandLabel) {
  const app = harnessDisplayName(policy.harness);
  const folder = policy.workspace_label?.trim() || resolveWorkspaceLabel(policy.workspace);
  const verb = policy.action === "block" ? "block" : "allow";
  if (policy.scope === "artifact") {
    return `Guard will ${verb} "${commandLabel}" the next time ${app} retries this exact action.`;
  }
  if (policy.scope === "workspace") {
    return `Guard will ${verb} "${commandLabel}" every time ${app} runs it in ${folder}.`;
  }
  if (policy.scope === "harness") {
    return `Guard will ${verb} "${commandLabel}" every time ${app} runs a matching action.`;
  }
  if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this publisher";
    return `Guard will ${verb} actions from ${publisher} in ${app}.`;
  }
  if (policy.scope === "global") {
    return `Guard will ${verb} matching actions on every project on this device.`;
  }
  return `Guard will ${verb} matching actions when ${scopeLabel(policy.scope).toLowerCase()} rules apply.`;
}
function resolveScopeSubtitle(policy) {
  const app = harnessDisplayName(policy.harness);
  if (policy.scope === "artifact") {
    return `Once in ${app}`;
  }
  if (policy.scope === "workspace") {
    const folder = policy.workspace_label?.trim() || resolveWorkspaceLabel(policy.workspace);
    return `This project · ${folder}`;
  }
  if (policy.scope === "harness") {
    return `Every time in ${app}`;
  }
  if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this publisher";
    return `${publisher} in ${app}`;
  }
  if (policy.scope === "global") {
    return "Every project on this device";
  }
  return scopeLabel(policy.scope, "policy");
}
function resolveWhatPhrase(policy) {
  const artifactId = policy.artifact_id?.trim() ?? "";
  const publisher = policy.publisher?.trim();
  if (policy.scope === "global" && !artifactId && !publisher) {
    return "all guarded actions on this device";
  }
  const runtimeLabel = artifactId ? resolveRuntimeActionLabel(artifactId) : null;
  if (runtimeLabel) {
    return runtimeLabel;
  }
  const family = artifactId ? extractMatcherFamily(artifactId) : null;
  const familyPhrase = family ? MATCHER_FAMILY_LABELS[family] ?? family.replace(/-/g, " ") : null;
  if (familyPhrase) {
    if (artifactId.startsWith("family:") || policy.scope === "harness") {
      return `all ${familyPhrase.toLowerCase()}s`;
    }
    if (family === "prompt") {
      const subtype = resolvePromptSubtypeLabel(artifactId);
      return subtype ? `${familyPhrase} (${subtype})` : familyPhrase;
    }
    return familyPhrase.toLowerCase();
  }
  if (publisher) {
    return `actions from ${publisher}`;
  }
  return "matching guarded actions";
}
function resolveKindLine(policy) {
  const remembered = policy.remembered_context?.trim();
  if (remembered) {
    return remembered;
  }
  const family = policy.artifact_id ? extractMatcherFamily(policy.artifact_id) : null;
  if (family && MATCHER_FAMILY_LABELS[family]) {
    return MATCHER_FAMILY_LABELS[family];
  }
  return resolveScopeSubtitle(policy);
}
function resolvePathLine(policy) {
  return formatPolicyScopePath(policy.source_scope_path);
}
function resolveProjectLabel(policy) {
  const label = policy.workspace_label?.trim();
  if (label) {
    return label;
  }
  const workspace = policy.workspace?.trim();
  if (!workspace || workspace.startsWith("workspace:")) {
    return null;
  }
  return resolveWorkspaceLabel(workspace);
}
function resolvePolicyDisplay(policy) {
  const reason = policy.reason?.trim() ?? null;
  const rememberedCommand = policy.remembered_command?.trim();
  const kindLine = resolveKindLine(policy);
  const pathLine = resolvePathLine(policy);
  const projectLabel = resolveProjectLabel(policy);
  if (rememberedCommand) {
    return {
      headline: rememberedCommand,
      kindLine,
      pathLine,
      projectLabel,
      rememberSentence: resolveRememberSentence(policy, rememberedCommand),
      technicalId: policy.artifact_id
    };
  }
  const actionVerb = resolveActionVerb(policy.action);
  if (reason && !isGenericReason(reason)) {
    return {
      headline: reason,
      kindLine,
      pathLine,
      projectLabel,
      rememberSentence: resolveRememberSentence(policy, reason),
      technicalId: policy.artifact_id
    };
  }
  const what = resolveWhatPhrase(policy);
  const headline = `${actionVerb} ${what}`;
  return {
    headline,
    kindLine,
    pathLine,
    projectLabel,
    rememberSentence: resolveRememberSentence(policy, what),
    technicalId: policy.artifact_id
  };
}
function resolvePolicyRowTitle(policy, display) {
  const headline = display.headline.trim();
  const verb = policyActionLabel(policy.action);
  const headlineHasVerb = headline.toLowerCase().startsWith(verb.toLowerCase());
  const project = display.projectLabel?.trim();
  if (headlineHasVerb) {
    if (project && project !== "this project" && !headline.toLowerCase().includes(project.toLowerCase())) {
      return `${headline} in ${project}`;
    }
    return headline;
  }
  if (project && project !== "this project" && !headline.toLowerCase().includes(project.toLowerCase())) {
    return `${verb} ${headline} in ${project}`;
  }
  return `${verb} ${headline}`;
}
function resolvePolicyRowSourceLabel(policy) {
  if (isCloudManagedPolicy(policy.source)) {
    return "Team policy";
  }
  return scopeLabel(policy.scope, "policy");
}
function resolvePolicyEvidenceSearchTerm(policy) {
  const receiptId = policy.source_receipt_id?.trim();
  if (receiptId) {
    return receiptId;
  }
  const hash = policy.artifact_hash?.trim();
  if (hash) {
    return hash.replace(/^sha256:/i, "").slice(0, 12);
  }
  const target = policyTargetLabel(policy);
  if (!target || target === "Global") {
    return null;
  }
  if (target.startsWith("family:")) {
    return target.slice("family:".length);
  }
  const parts = target.split(":");
  const last = parts[parts.length - 1];
  if (last && last.length >= 12 && /^[a-f0-9]+$/i.test(last)) {
    return last.slice(0, 12);
  }
  return null;
}
function resolvePolicyEvidenceHref(policy) {
  const params = new URLSearchParams();
  const receiptId = policy.source_receipt_id?.trim();
  if (receiptId) {
    params.set("selected", receiptId);
    params.set("search", receiptId);
    return `/evidence?${params.toString()}`;
  }
  const searchTerm = resolvePolicyEvidenceSearchTerm(policy);
  if (searchTerm) {
    params.set("search", searchTerm);
  }
  const query = params.toString();
  return query ? `/evidence?${query}` : "/evidence";
}
function resolvePolicyApprovalRecordLabel(policy) {
  const receiptId = policy.source_receipt_id?.trim();
  if (receiptId) {
    return `${receiptId}.json`;
  }
  const hash = policy.artifact_hash?.replace(/^sha256:/i, "").slice(0, 8);
  if (hash) {
    return `receipt_${hash}.json`;
  }
  return "View in Evidence";
}
function resolveCloudPolicyControlsUrl(snapshot) {
  const dashboardUrl = snapshot.dashboard_url?.trim();
  if (dashboardUrl) {
    return dashboardUrl;
  }
  const connectUrl = snapshot.connect_url?.trim();
  return connectUrl && connectUrl.length > 0 ? connectUrl : null;
}
function resolveCloudBundleSurfaceClass(tone) {
  if (tone === "attention") {
    return "rounded-2xl border border-amber-200/70 bg-amber-50/70 p-4 shadow-sm";
  }
  if (tone === "green") {
    return "rounded-2xl border border-emerald-200/70 bg-emerald-50/70 p-4 shadow-sm";
  }
  return "rounded-2xl border border-slate-200/70 bg-slate-50/70 p-4 shadow-sm";
}
function resolvePolicyMatcherFamily(policy) {
  const target = policy.artifact_id?.trim();
  if (!target) {
    return null;
  }
  return extractMatcherFamily(target);
}
function groupPoliciesByHarness(policies) {
  const map = /* @__PURE__ */ new Map();
  for (const policy of policies) {
    const key = policy.harness || "global";
    const existing = map.get(key) ?? [];
    map.set(key, [...existing, policy]);
  }
  return map;
}
function resolveSecurityModeCopy(level) {
  if (level === "strict") {
    return {
      label: "Protect",
      description: "Guard asks before risky actions that are not already allowed by policy, remembered rules, or Cloud exceptions.",
      tone: "attention"
    };
  }
  if (level === "balanced") {
    return {
      label: "Balanced (default)",
      description: "Guard asks for secrets, destructive commands, and new network destinations. Low noise, solid coverage.",
      tone: "green"
    };
  }
  if (level === "gentle" || level === "relaxed") {
    return {
      label: "Low noise",
      description: "Guard only asks for the highest-risk actions. Minimal interruptions.",
      tone: "slate"
    };
  }
  return {
    label: level ?? "Custom",
    description: "Custom policy rules apply. Review individual rules below.",
    tone: "slate"
  };
}
function resolveCloudPolicyBundleCopy(snapshot) {
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim();
  if (!bundleVersion) {
    return null;
  }
  const rollout = snapshot.cloud_policy_rollout_state?.trim() || "unknown";
  const syncError = snapshot.cloud_policy_sync_error?.trim();
  const hash = snapshot.cloud_policy_bundle_hash?.trim() || null;
  if (syncError) {
    return {
      label: "Needs attention",
      detail: `Bundle ${bundleVersion} is connected, but the latest sync reported: ${syncError}`,
      hash,
      tone: "attention"
    };
  }
  return {
    label: "Synced",
    detail: `Bundle ${bundleVersion} is active on this device (${rollout}).`,
    hash,
    tone: "green"
  };
}
function resolveCloudExceptionsConnected(snapshot) {
  return snapshot.cloud_state === "paired_active" || snapshot.cloud_state === "paired_waiting";
}
function PolicyCloudExceptionsTab({
  snapshot,
  requestOpen: requestOpenProp,
  onRequestOpenChange
}) {
  const [requestOpenInternal, setRequestOpenInternal] = reactExports.useState(false);
  const requestOpen = requestOpenProp ?? requestOpenInternal;
  const setRequestOpen = onRequestOpenChange ?? setRequestOpenInternal;
  const [loadState, setLoadState] = reactExports.useState("loading");
  const [loadError, setLoadError] = reactExports.useState(null);
  const [exceptions, setExceptions] = reactExports.useState([]);
  const [pendingRequests, setPendingRequests] = reactExports.useState([]);
  const [selectedExceptionId, setSelectedExceptionId] = reactExports.useState(null);
  const [reloadToken, setReloadToken] = reactExports.useState(0);
  const [scopeFilter, setScopeFilter] = reactExports.useState("all");
  const [actionFilter, setActionFilter] = reactExports.useState("all");
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  snapshot.connect_url?.trim() || null;
  const reloadData = reactExports.useCallback(async () => {
    if (!cloudConnected) {
      setExceptions([]);
      setPendingRequests([]);
      setLoadState("ready");
      setLoadError(null);
      return;
    }
    setLoadState("loading");
    setLoadError(null);
    try {
      const [nextExceptions, nextRequests] = await Promise.all([
        fetchCloudExceptions(),
        fetchCloudExceptionRequests()
      ]);
      setExceptions(nextExceptions);
      setPendingRequests(nextRequests.items ?? []);
      setLoadState("ready");
    } catch (error) {
      setLoadState("error");
      setLoadError(error instanceof Error ? error.message : "Unable to load Cloud exceptions.");
    }
  }, [cloudConnected]);
  reactExports.useEffect(() => {
    void reloadData();
  }, [reloadData, reloadToken]);
  const handleCloseRequestPanel = reactExports.useCallback(() => {
    setRequestOpen(false);
  }, [setRequestOpen]);
  const handleRequestSubmitted = reactExports.useCallback(() => {
    setRequestOpen(false);
    setReloadToken((current) => current + 1);
  }, [setRequestOpen]);
  const handleRetryLoad = reactExports.useCallback(() => {
    setReloadToken((current) => current + 1);
  }, []);
  const handleSelectException = reactExports.useCallback((exception) => {
    setSelectedExceptionId(exception.id);
  }, []);
  const handleCloseDetail = reactExports.useCallback(() => {
    setSelectedExceptionId(null);
  }, []);
  const handleScopeFilterChange = reactExports.useCallback((value) => {
    setScopeFilter(value);
  }, []);
  const handleActionFilterChange = reactExports.useCallback((value) => {
    setActionFilter(value);
  }, []);
  const summary = reactExports.useMemo(
    () => summarizeCloudExceptions(exceptions, pendingRequests),
    [exceptions, pendingRequests]
  );
  const groups = reactExports.useMemo(
    () => groupCloudExceptions(exceptions, pendingRequests),
    [exceptions, pendingRequests]
  );
  const selectedException = reactExports.useMemo(
    () => exceptions.find((item) => item.id === selectedExceptionId) ?? null,
    [exceptions, selectedExceptionId]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    requestOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyCloudExceptionRequestPanel,
      {
        snapshot,
        onSubmitted: handleRequestSubmitted,
        onCancel: handleCloseRequestPanel
      }
    ) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] px-4 py-3 text-sm text-brand-dark/80", children: "Exceptions are approved in Guard Cloud, then enforced locally as signed policy bundle entries." }),
      !cloudConnected ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "Guard Cloud is not connected",
          body: "Cloud exceptions are managed in Guard Cloud. Connect this device to request a risk acceptance or view synced exceptions here.",
          tone: "teach"
        }
      ) : loadState === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "Could not load Cloud exceptions",
          body: `${loadError ?? "Try again after Guard Cloud sync completes."} Local remembered rules and strict config still apply on this device.`,
          action: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: handleRetryLoad, children: "Retry" })
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicyCloudExceptionsSummary,
          {
            activeCount: summary.activeCount,
            pendingCount: summary.pendingCount,
            expiringSoonCount: summary.expiringSoonCount,
            ackFailureCount: summary.ackFailureCount,
            loading: loadState === "loading"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start", children: [
          loadState === "loading" ? /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyCloudExceptionsListSkeleton, {}) : /* @__PURE__ */ jsxRuntimeExports.jsx(
            PolicyCloudExceptionsList,
            {
              active: groups.active,
              pending: groups.pending,
              expiringSoon: groups.expiringSoon,
              selectedExceptionId,
              onSelectException: handleSelectException,
              cloudConnected,
              scopeFilter,
              actionFilter,
              onScopeFilterChange: handleScopeFilterChange,
              onActionFilterChange: handleActionFilterChange
            }
          ),
          selectedException ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            PolicyCloudExceptionDetailPanel,
            {
              exception: selectedException,
              cloudControlsUrl,
              onClose: handleCloseDetail
            }
          ) : null
        ] })
      ] })
    ] })
  ] });
}
function PolicyGuardCloudBundleCard({ snapshot }) {
  const cloudBundleCopy = resolveCloudPolicyBundleCopy(snapshot);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const lastAckAt = snapshot.runtime_state?.last_heartbeat_at?.trim() ?? snapshot.generated_at?.trim() ?? null;
  const policyHash = cloudBundleCopy?.hash?.slice(0, 8) ?? null;
  const handleCopyHash = reactExports.useCallback(() => {
    const fullHash = cloudBundleCopy?.hash?.trim();
    if (!fullHash || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(fullHash);
  }, [cloudBundleCopy?.hash]);
  if (!cloudBundleCopy) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200/70 bg-slate-50/70 p-4 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Not connected. Remembered Cloud rules appear when Guard Cloud syncs a bundle." }),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
        "Open Guard Cloud"
      ] }) }) : null
    ] });
  }
  const synced = cloudBundleCopy.tone === "green";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: resolveCloudBundleSurfaceClass(cloudBundleCopy.tone), children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 grid gap-4 sm:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Status" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex items-center gap-1.5", children: [
            synced ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-emerald-600", "aria-hidden": "true" }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: synced ? "green" : "amber", children: cloudBundleCopy.label })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: cloudBundleCopy.detail })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Policy hash" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex items-center gap-1.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-sm text-brand-dark", children: policyHash ?? "Unavailable" }),
            policyHash ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: handleCopyHash,
                className: "rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark",
                "aria-label": "Copy policy hash",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { className: "h-4 w-4", "aria-hidden": "true" })
              }
            ) : null
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Last ack" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex items-center gap-1.5", children: [
            lastAckAt ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-emerald-600", "aria-hidden": "true" }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: lastAckAt ? formatRelativeTime(lastAckAt) : "Not yet" })
          ] })
        ] })
      ] })
    ] }),
    cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
      "Open Guard Cloud"
    ] }) : null
  ] }) });
}
const PAGE_SIZE = 5;
const RULE_GRID_CLASS = "grid grid-cols-[minmax(0,1fr)] items-center gap-x-3 gap-y-2 border-b border-slate-100 px-4 py-3 last:border-0 hover:bg-slate-50/80 md:grid-cols-[40px_72px_minmax(200px,1.4fr)_88px_96px_88px_104px_minmax(120px,1fr)_72px]";
const RULE_HEADER_CLASS = "hidden border-b border-slate-100 bg-slate-50/80 px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 md:grid md:grid-cols-[40px_72px_minmax(200px,1.4fr)_88px_96px_88px_104px_minmax(120px,1fr)_72px] md:gap-x-3";
function resolveActionTone(action) {
  if (action === "allow") {
    return "success";
  }
  if (action === "block") {
    return "destructive";
  }
  if (action === "warn" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}
function resolveFamilyIcon(family) {
  if (family === "package-request") {
    return HiMiniCube;
  }
  if (family === "tool-action" || family === "tool-output") {
    return HiMiniCommandLine;
  }
  if (family === "prompt" || family === "prompt-env-read") {
    return HiMiniDocumentText;
  }
  if (family === "mcp") {
    return HiMiniGlobeAlt;
  }
  return HiMiniShieldCheck;
}
function PolicyRuleRow({ policy, cloudControlsUrl, onClear, cloudVariant = false }) {
  const handleClear = reactExports.useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = cloudVariant || isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== void 0 && !cloudManaged;
  const family = resolvePolicyMatcherFamily(policy);
  const Icon = resolveFamilyIcon(family);
  const title = resolvePolicyRowTitle(policy, display);
  const scopeTag = scopeLabel(policy.scope, "policy");
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: RULE_GRID_CLASS, role: "listitem", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden items-center justify-center md:flex", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 md:col-start-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500 md:hidden", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: resolveActionTone(policy.action), children: policyActionLabel(policy.action) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 md:col-start-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold leading-snug text-brand-dark", children: title }),
      display.kindLine ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: display.kindLine }) : null,
      display.pathLine ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 break-all font-mono text-[11px] leading-relaxed text-slate-500", children: display.pathLine }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap gap-3 text-xs text-slate-600 md:hidden", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: resolvePolicyRowSourceLabel(policy) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: scopeTag }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: harnessDisplayName(policy.harness) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden text-sm text-brand-dark md:col-start-4 md:block", children: cloudManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: resolvePolicyRowSourceLabel(policy) }) : resolvePolicyRowSourceLabel(policy) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden md:col-start-5 md:block", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: scopeTag }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden text-sm text-brand-dark md:col-start-6 md:block", children: harnessDisplayName(policy.harness) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden whitespace-nowrap text-xs text-slate-500 md:col-start-7 md:block", children: policy.updated_at ? formatRelativeTime(policy.updated_at) : "—" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "hidden min-w-0 md:col-start-8 md:block", children: [
      !cloudManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: guardAwareHref(resolvePolicyEvidenceHref(policy)),
          className: "max-w-full truncate font-mono text-xs font-medium text-brand-blue hover:underline",
          title: resolvePolicyApprovalRecordLabel(policy),
          children: resolvePolicyApprovalRecordLabel(policy)
        }
      ) : null,
      cloudManaged && cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: cloudControlsUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
            "View on cloud"
          ]
        }
      ) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "hidden items-center justify-end md:col-start-9 md:flex", children: [
      cloudManaged ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 text-xs font-medium text-slate-500", title: "Read-only Cloud policy", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
        "Policy"
      ] }) : null,
      canClear ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: handleClear,
          className: "inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-red-600",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
            "Remove rule"
          ]
        }
      ) : null
    ] })
  ] });
}
function PolicyRuleTable({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
  cloudVariant = false,
  totalCount,
  viewAllLabel
}) {
  const [visibleCount, setVisibleCount] = reactExports.useState(PAGE_SIZE);
  const [expanded, setExpanded] = reactExports.useState(false);
  reactExports.useEffect(() => {
    setExpanded(false);
    setVisibleCount(PAGE_SIZE);
  }, [policies]);
  const visiblePolicies = reactExports.useMemo(
    () => expanded ? policies : policies.slice(0, visibleCount),
    [expanded, policies, visibleCount]
  );
  const remaining = policies.length - visiblePolicies.length;
  const hasMore = !expanded && remaining > 0;
  const listTotal = totalCount ?? policies.length;
  const handleShowMore = reactExports.useCallback(() => {
    setVisibleCount((current) => current + PAGE_SIZE);
  }, []);
  const handleViewAll = reactExports.useCallback(() => {
    setExpanded(true);
  }, []);
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: emptyTitle, body: emptyBody, tone: "teach" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "overflow-x-auto rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: RULE_HEADER_CLASS, "aria-hidden": "true", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", {}),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Action" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Description" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Source" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Scope" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: cloudVariant ? "Applies to" : "Harness" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Last updated" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: cloudVariant ? "Policy" : "Approval record" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-right", children: cloudVariant ? "" : "Actions" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "list", children: visiblePolicies.map((policy) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyRuleRow,
        {
          policy,
          cloudControlsUrl,
          onClear: onClearPolicy,
          cloudVariant
        },
        `${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`
      )) })
    ] }),
    hasMore && viewAllLabel ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex justify-center pt-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: handleViewAll,
        className: "text-sm font-medium text-brand-blue hover:underline",
        children: viewAllLabel.replace("{count}", String(listTotal))
      }
    ) }) : hasMore ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex justify-center pt-1", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: handleShowMore,
        className: "text-sm font-medium text-brand-blue hover:underline",
        children: [
          "Show ",
          Math.min(PAGE_SIZE, remaining),
          " more (",
          remaining,
          " remaining)"
        ]
      }
    ) }) : null
  ] });
}
function GroupedPolicySection({
  title,
  badge,
  description,
  policies,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
  defaultOpen = true,
  cloudVariant = false,
  viewAllLabel
}) {
  const [open, setOpen] = reactExports.useState(defaultOpen);
  const handleToggle = reactExports.useCallback(() => setOpen((current) => !current), []);
  const ruleLabel = policies.length === 1 ? "1 rule" : `${policies.length} rules`;
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-semibold text-brand-dark", children: title }),
        badge ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: badge }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: description }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: emptyTitle, body: emptyBody, tone: "teach" })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: handleToggle,
        className: "flex w-full items-start justify-between gap-3 text-left",
        "aria-expanded": open,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-semibold text-brand-dark", children: title }),
              badge ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: badge }) : null
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: description })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 items-center gap-2 pt-0.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-slate-500", children: ruleLabel }),
            open ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" })
          ] })
        ]
      }
    ),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyRuleTable,
      {
        policies,
        cloudControlsUrl,
        onClearPolicy,
        emptyTitle,
        emptyBody,
        cloudVariant,
        totalCount: policies.length,
        viewAllLabel
      }
    ) : null
  ] });
}
function resolveFamilyFilterLabel(family) {
  switch (family) {
    case "package-request":
      return "Package installs";
    case "tool-action":
      return "Commands";
    case "tool-output":
      return "Output";
    case "prompt":
      return "Prompts";
    default:
      return family.replace(/-/g, " ");
  }
}
function groupPoliciesByFamily(policies) {
  const counts = /* @__PURE__ */ new Map();
  for (const policy of policies) {
    const family = resolvePolicyMatcherFamily(policy) ?? "other";
    counts.set(family, (counts.get(family) ?? 0) + 1);
  }
  return counts;
}
function PolicyRememberedCloudRules({
  policies,
  cloudControlsUrl
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    GroupedPolicySection,
    {
      title: "From Guard Cloud",
      badge: "Team policy rules",
      description: "Managed by your team in Guard Cloud. These rules are read-only locally.",
      policies,
      cloudControlsUrl,
      emptyTitle: "No Guard Cloud rules synced",
      emptyBody: "Connect Guard Cloud to sync shared policy bundles.",
      defaultOpen: policies.length > 0,
      cloudVariant: true,
      viewAllLabel: "View all cloud rules ({count}) →"
    }
  );
}
function PolicyRememberedLocalRules({
  policies,
  cloudControlsUrl,
  onClearPolicy
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    GroupedPolicySection,
    {
      title: "Remembered on this device",
      badge: "Local rules",
      description: "Decisions you've remembered on this machine.",
      policies,
      cloudControlsUrl,
      onClearPolicy,
      emptyTitle: "No local remembered rules yet",
      emptyBody: "Approve or block in Inbox and Guard remembers the decision here in plain language.",
      defaultOpen: true,
      viewAllLabel: "View all local rules ({count}) →"
    }
  );
}
const REVIEW_SCOPE_LADDER = [
  {
    label: "Once",
    detail: "One time only.",
    icon: HiMiniArrowPath
  },
  {
    label: "This cwd",
    detail: "Reuse in this working directory.",
    icon: HiMiniFolder
  },
  {
    label: "This project",
    detail: "Reuse across this project.",
    icon: HiMiniFolder
  },
  {
    label: "This harness",
    detail: "Reuse across this tool harness.",
    icon: HiMiniGlobeAlt
  },
  {
    label: "Team policy",
    detail: "Organization-wide policy.",
    icon: HiMiniUsers
  }
];
function PolicyRememberedRulesRightRail({
  snapshot,
  onOpenCloudExceptions
}) {
  const modeCopy = resolveSecurityModeCopy(snapshot.security_level);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "space-y-4 lg:sticky lg:top-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active mode" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-5 w-5", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: modeCopy.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-slate-600", children: modeCopy.description })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: "Approvals are still fast" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-500", children: "When you approve in Inbox, you pick how broadly Guard should remember the decision." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 space-y-2.5", children: REVIEW_SCOPE_LADDER.map((step) => {
        const Icon = step.icon;
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-3.5 w-3.5", "aria-hidden": "true" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: step.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: step.detail })
          ] })
        ] }, step.label);
      }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: "Cloud exceptions" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-slate-600", children: "Governed risk acceptances override team policy when approved in Guard Cloud. They sync as signed bundle entries on this device." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: onOpenCloudExceptions,
          className: "mt-3 text-sm font-medium text-brand-blue hover:underline",
          children: "Open Cloud exceptions tab"
        }
      ),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
        "Open Guard Cloud"
      ] }) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: "Local remembered rules are for your machine only. Cloud exceptions and team policy sync from Guard Cloud." })
  ] });
}
function PolicyRememberedRulesTab({
  policies,
  snapshot,
  cloudControlsUrl,
  onClearPolicy,
  onOpenCloudExceptions
}) {
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [appFilter, setAppFilter] = reactExports.useState("");
  const [familyFilter, setFamilyFilter] = reactExports.useState("");
  const handleSearchChange = reactExports.useCallback((event) => {
    setSearchQuery(event.target.value);
  }, []);
  const filteredPolicies = reactExports.useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return policies.filter((policy) => {
      if (appFilter && policy.harness !== appFilter) {
        return false;
      }
      if (familyFilter) {
        const family = resolvePolicyMatcherFamily(policy) ?? "other";
        if (family !== familyFilter) {
          return false;
        }
      }
      if (!query) {
        return true;
      }
      const display = resolvePolicyDisplay(policy);
      const displayHaystack = [
        policy.harness,
        policy.artifact_id,
        policy.workspace,
        policy.publisher,
        policy.scope,
        policy.action,
        policy.reason,
        policy.remembered_command,
        policy.remembered_context,
        policy.workspace_label,
        policy.source_scope_path,
        policy.source_receipt_id,
        display.headline,
        display.kindLine,
        display.pathLine,
        display.projectLabel,
        harnessDisplayName(policy.harness),
        policyActionLabel(policy.action)
      ].filter(Boolean).join(" ").toLowerCase();
      return displayHaystack.includes(query);
    });
  }, [policies, searchQuery, appFilter, familyFilter]);
  const rememberedRules = reactExports.useMemo(
    () => filteredPolicies.filter((policy) => policy.action === "allow" || policy.action === "block").sort((a, b) => new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime()),
    [filteredPolicies]
  );
  const localRules = reactExports.useMemo(
    () => rememberedRules.filter((policy) => !isCloudManagedPolicy(policy.source)),
    [rememberedRules]
  );
  const cloudRules = reactExports.useMemo(
    () => rememberedRules.filter((policy) => isCloudManagedPolicy(policy.source)),
    [rememberedRules]
  );
  const appOptions = reactExports.useMemo(
    () => [...new Set(policies.map((policy) => policy.harness).filter(Boolean))].sort(),
    [policies]
  );
  const familyCounts = reactExports.useMemo(() => groupPoliciesByFamily(rememberedRules), [rememberedRules]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyGuardCloudBundleCard, { snapshot }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "search",
              placeholder: "Search by app, action, or reason…",
              value: searchQuery,
              onChange: handleSearchChange,
              "aria-label": "Search policies",
              className: "w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: appFilter,
              onChange: (event) => setAppFilter(event.target.value),
              "aria-label": "Filter by app",
              className: "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "All assets" }),
                appOptions.map((app) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: app, children: harnessDisplayName(app) }, app))
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: familyFilter,
              onChange: (event) => setFamilyFilter(event.target.value),
              "aria-label": "Filter by action type",
              className: "rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "All action types" }),
                [...familyCounts.entries()].map(([family, count]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: family, children: [
                  resolveFamilyFilterLabel(family),
                  " (",
                  count,
                  ")"
                ] }, family))
              ]
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyRememberedLocalRules,
        {
          policies: localRules,
          cloudControlsUrl,
          onClearPolicy
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyRememberedCloudRules, { policies: cloudRules, cloudControlsUrl })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyRememberedRulesRightRail, { snapshot, onOpenCloudExceptions })
  ] });
}
const STRICT_CONFIG_ACTION_OPTIONS = [
  { value: "allow", label: "Allow without asking" },
  { value: "warn", label: "Warn only" },
  { value: "review", label: "Ask me first" },
  { value: "require-reapproval", label: "Ask every time" },
  { value: "sandbox-required", label: "Run in sandbox" },
  { value: "block", label: "Block" }
];
const STRICT_POLICY_EVALUATION_ORDER = [
  "Local remembered rule",
  "Guard Cloud policy",
  "Cloud exception",
  "Strict fallback",
  "Ask or block"
];
function fingerprintLocalPolicySettings(settings) {
  const payload = JSON.stringify({
    mode: settings.mode,
    security_level: settings.security_level,
    default_action: settings.default_action,
    changed_hash_action: settings.changed_hash_action,
    new_network_domain_action: settings.new_network_domain_action,
    subprocess_action: settings.subprocess_action,
    destructive_shell: settings.risk_actions?.destructive_shell ?? null
  });
  let hash = 5381;
  for (let index = 0; index < payload.length; index += 1) {
    hash = (hash << 5) + hash ^ payload.charCodeAt(index);
  }
  return `local-${(hash >>> 0).toString(16).padStart(8, "0")}`;
}
function resolveStrictFileWriteAction(settings) {
  return settings.risk_actions?.destructive_shell ?? settings.default_action;
}
function simulateStrictPolicyOutcome(input) {
  const path = [];
  if (input.rememberedRuleAction !== "none") {
    path.push(`Local remembered rule → ${input.rememberedRuleAction}`);
    return {
      outcome: input.rememberedRuleAction,
      winningStep: "Local remembered rule",
      path
    };
  }
  path.push("Local remembered rule → none");
  if (input.cloudPolicyAction !== "none") {
    path.push(`Guard Cloud policy → ${input.cloudPolicyAction}`);
    return {
      outcome: input.cloudPolicyAction,
      winningStep: "Guard Cloud policy",
      path
    };
  }
  path.push("Guard Cloud policy → none");
  if (input.cloudExceptionActive) {
    path.push("Cloud exception → allow");
    return {
      outcome: "allow",
      winningStep: "Cloud exception",
      path
    };
  }
  path.push("Cloud exception → none");
  path.push(`Strict fallback → ${input.fallbackAction}`);
  if (input.fallbackAction === "allow" || input.fallbackAction === "warn") {
    return {
      outcome: input.fallbackAction,
      winningStep: "Strict fallback",
      path
    };
  }
  path.push(`Ask or block → ${input.fallbackAction}`);
  return {
    outcome: input.fallbackAction,
    winningStep: "Ask or block",
    path
  };
}
const PRIMARY_STRICT_ACTIONS = [
  { value: "allow", label: "Allow" },
  { value: "warn", label: "Warn" },
  { value: "review", label: "Review" },
  { value: "block", label: "Block" }
];
const PRIMARY_STRICT_ACTION_VALUES = new Set(PRIMARY_STRICT_ACTIONS.map((item) => item.value));
function StrictConfigActionSegmented({
  label,
  value,
  settingKey,
  onSettingChange,
  disabled = false,
  help
}) {
  const handleSelect = reactExports.useCallback(
    (nextValue) => {
      onSettingChange(settingKey, nextValue);
    },
    [onSettingChange, settingKey]
  );
  const showAdvanced = !PRIMARY_STRICT_ACTION_VALUES.has(value);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3 py-4 first:pt-0 last:pb-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: label }),
      help ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: help }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "inline-flex flex-wrap gap-1 rounded-xl border border-slate-200 bg-slate-50/80 p-1",
        role: "group",
        "aria-label": label,
        children: PRIMARY_STRICT_ACTIONS.map((option) => {
          const selected = value === option.value;
          return /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled,
              "aria-pressed": selected,
              onClick: () => handleSelect(option.value),
              className: `rounded-lg px-3 py-1.5 text-sm font-medium transition ${selected ? "bg-white text-brand-dark shadow-sm ring-1 ring-slate-200" : "text-slate-600 hover:bg-white/70 hover:text-brand-dark disabled:opacity-50"}`,
              children: option.label
            },
            option.value
          );
        })
      }
    ),
    showAdvanced ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Advanced fallback" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          value,
          disabled,
          onChange: (event) => handleSelect(event.target.value),
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark disabled:cursor-not-allowed disabled:bg-slate-50",
          children: STRICT_CONFIG_ACTION_OPTIONS.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value))
        }
      )
    ] }) : null
  ] });
}
function resolveStrictConfigPatch(settings, key, value) {
  if (key === "destructive_shell") {
    return {
      risk_actions: {
        ...settings.risk_actions,
        destructive_shell: value
      }
    };
  }
  return { [key]: value };
}
function applyStrictConfigPatch(settings, key, value) {
  if (key === "destructive_shell") {
    return {
      ...settings,
      risk_actions: {
        ...settings.risk_actions,
        destructive_shell: value
      }
    };
  }
  return {
    ...settings,
    [key]: value
  };
}
const EVALUATION_STEPS = [
  { label: "Local rule", icon: HiMiniQueueList, tone: "purple" },
  { label: "Cloud policy", icon: HiMiniCloud, tone: "blue" },
  { label: "Cloud exception", icon: HiMiniCloud, tone: "blue" },
  { label: "Strict fallback", icon: HiMiniShieldCheck, tone: "amber" },
  { label: "Ask or block", icon: HiMiniNoSymbol, tone: "red" }
];
const WHAT_CHANGES_BULLETS = [
  "First-time actions follow your default strict action.",
  "Changed tool hashes trigger your configured review path.",
  "New network domains and subprocesses use strict fallback rules.",
  "Cloud exceptions and remembered rules still win when they match."
];
const TEST_SCENARIOS = [
  {
    id: "first-time",
    label: "New tool contacting unknown domain",
    remembered: "none",
    cloudPolicy: "none",
    cloudException: false
  },
  {
    id: "remembered-allow",
    label: "Remembered allow wins",
    remembered: "allow",
    cloudPolicy: "block",
    cloudException: false
  },
  {
    id: "cloud-exception",
    label: "Active Cloud exception",
    remembered: "block",
    cloudPolicy: "block",
    cloudException: true
  }
];
function resolveExpectedActionTone(action) {
  if (action === "block") {
    return "destructive";
  }
  if (action === "allow") {
    return "success";
  }
  if (action === "warn" || action === "review" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}
function PolicyStrictConfigTab({
  snapshot,
  onOpenSettings,
  onOpenInbox,
  onReloadPolicy,
  reloadingPolicy = false
}) {
  const [loadState, setLoadState] = reactExports.useState("loading");
  const [loadError, setLoadError] = reactExports.useState(null);
  const [settings, setSettings] = reactExports.useState(null);
  const [saveError, setSaveError] = reactExports.useState(null);
  const [savingKey, setSavingKey] = reactExports.useState(null);
  const [simRemembered, setSimRemembered] = reactExports.useState("none");
  const [simCloudPolicy, setSimCloudPolicy] = reactExports.useState("none");
  const [simCloudException, setSimCloudException] = reactExports.useState(false);
  const [scenarioId, setScenarioId] = reactExports.useState(TEST_SCENARIOS[0].id);
  const [simulationVisible, setSimulationVisible] = reactExports.useState(false);
  const isStrict = settings?.security_level === "strict";
  const cloudBundleCopy = resolveCloudPolicyBundleCopy(snapshot);
  const pendingInboxCount = snapshot.queue_summary?.remaining_pending_count ?? snapshot.pending_count ?? 0;
  reactExports.useEffect(() => {
    let cancelled = false;
    setLoadState("loading");
    setLoadError(null);
    void fetchSettings().then((payload) => {
      if (cancelled) {
        return;
      }
      setSettings(payload.settings);
      setLoadState("ready");
    }).catch((error) => {
      if (cancelled) {
        return;
      }
      setLoadState("error");
      setLoadError(error instanceof Error ? error.message : "Unable to load strict config.");
    });
    return () => {
      cancelled = true;
    };
  }, []);
  const localPolicyHash = reactExports.useMemo(
    () => settings ? fingerprintLocalPolicySettings(settings) : null,
    [settings]
  );
  const simulation = reactExports.useMemo(() => {
    if (!settings) {
      return null;
    }
    return simulateStrictPolicyOutcome({
      rememberedRuleAction: simRemembered,
      cloudPolicyAction: simCloudPolicy,
      cloudExceptionActive: simCloudException,
      fallbackAction: settings.default_action
    });
  }, [settings, simRemembered, simCloudPolicy, simCloudException]);
  const persistSetting = reactExports.useCallback(async (key, value) => {
    if (!settings) {
      return;
    }
    const previousSettings = settings;
    const updatedSettings = applyStrictConfigPatch(settings, key, value);
    setSettings(updatedSettings);
    setSavingKey(key);
    setSaveError(null);
    const nextSettings = resolveStrictConfigPatch(settings, key, value);
    try {
      const payload = await updateSettings(nextSettings);
      setSettings(payload.settings);
    } catch (error) {
      setSettings(previousSettings);
      setSaveError(error instanceof Error ? error.message : "Unable to save strict config.");
    } finally {
      setSavingKey(null);
    }
  }, [settings]);
  const handleStrictConfigChange = reactExports.useCallback(
    (key, value) => {
      void persistSetting(key, value);
    },
    [persistSetting]
  );
  const handleRunSimulation = reactExports.useCallback(() => {
    setSimulationVisible(true);
  }, []);
  const handleScenarioChange = reactExports.useCallback((event) => {
    const nextId = event.target.value;
    setScenarioId(nextId);
    setSimulationVisible(false);
    const scenario = TEST_SCENARIOS.find((item) => item.id === nextId);
    if (!scenario) {
      return;
    }
    setSimRemembered(scenario.remembered);
    setSimCloudPolicy(scenario.cloudPolicy);
    setSimCloudException(scenario.cloudException);
  }, []);
  if (loadState === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", "aria-busy": "true", children: [0, 1, 2].map((index) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-24 animate-pulse rounded-2xl border border-slate-200 bg-slate-100" }, index)) });
  }
  if (loadState === "error" || !settings) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "Could not load strict config",
        body: loadError ?? "Try again from Settings if the daemon is unavailable."
      }
    );
  }
  const fileWriteAction = resolveStrictFileWriteAction(settings);
  const controlsDisabled = savingKey !== null;
  const lastReloadAt = snapshot.runtime_state?.started_at ?? null;
  const daemonAckLabel = cloudBundleCopy?.label ?? "Pending";
  const expectedAction = simulation?.outcome ?? settings.default_action;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px] lg:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-5 w-5", "aria-hidden": "true" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: "Strict mode" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStrict ? "green" : "slate", children: isStrict ? "Enabled" : "Disabled" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Local enforcement tuning." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Guard asks before risky actions that are not already allowed by policy." })
            ] })
          ] }),
          !isStrict && onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Enable in Settings" }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2 lg:grid-cols-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Strict mode" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1.5 text-sm font-medium text-brand-dark", children: isStrict ? "Enabled" : "Disabled" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Policy hash" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1.5 flex items-center gap-1.5 font-mono text-sm text-brand-dark", children: localPolicyHash })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Daemon ack" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5 flex items-center gap-1.5 text-sm text-brand-dark", children: [
              cloudBundleCopy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-emerald-600", "aria-hidden": "true" }) : null,
              daemonAckLabel
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Last reload" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1.5 text-sm text-brand-dark", children: lastReloadAt ? formatRelativeTime(lastReloadAt) : "Unavailable" })
          ] })
        ] }),
        onReloadPolicy ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex justify-end border-t border-slate-100 pt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onReloadPolicy, disabled: reloadingPolicy, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: `mr-1.5 h-4 w-4 ${reloadingPolicy ? "animate-spin" : ""}`, "aria-hidden": "true" }),
          "Reload policy"
        ] }) }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-start justify-between gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local strict policy" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Fallback controls when no remembered rule, Cloud policy, or Cloud exception matches." })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 divide-y divide-slate-100", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            StrictConfigActionSegmented,
            {
              label: "Default action",
              help: "First-time actions with no prior decision.",
              value: settings.default_action,
              settingKey: "default_action",
              onSettingChange: handleStrictConfigChange,
              disabled: controlsDisabled
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            StrictConfigActionSegmented,
            {
              label: "Changed tool hash action",
              value: settings.changed_hash_action,
              settingKey: "changed_hash_action",
              onSettingChange: handleStrictConfigChange,
              disabled: controlsDisabled
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            StrictConfigActionSegmented,
            {
              label: "New network domain action",
              value: settings.new_network_domain_action,
              settingKey: "new_network_domain_action",
              onSettingChange: handleStrictConfigChange,
              disabled: controlsDisabled
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            StrictConfigActionSegmented,
            {
              label: "Subprocess action",
              value: settings.subprocess_action,
              settingKey: "subprocess_action",
              onSettingChange: handleStrictConfigChange,
              disabled: controlsDisabled
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            StrictConfigActionSegmented,
            {
              label: "File write action",
              help: "Backed by the destructive shell risk control.",
              value: fileWriteAction,
              settingKey: "destructive_shell",
              onSettingChange: handleStrictConfigChange,
              disabled: controlsDisabled
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs text-slate-500", children: "These settings apply only when no remembered rule, Cloud policy, or Cloud exception covers the action." }),
        saveError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-red-600", children: saveError }) : null,
        savingKey ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-sm text-slate-500", children: [
          "Saving ",
          savingKey.replace(/_/g, " "),
          "…"
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local enforcement preview" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Evaluation order when Guard decides what to do next." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex flex-wrap items-center gap-2", children: EVALUATION_STEPS.map((step, index) => {
          const Icon = step.icon;
          return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-medium text-brand-dark", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4 text-brand-blue", "aria-hidden": "true" }),
              step.label
            ] }),
            index < EVALUATION_STEPS.length - 1 ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) : null
          ] }, step.label);
        }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-xs text-slate-500", children: [
          "Evaluation order: ",
          STRICT_POLICY_EVALUATION_ORDER.join(" → "),
          ". Tune fallback behavior locally; team policy still syncs from Guard Cloud."
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "space-y-4 lg:sticky lg:top-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What this changes" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 space-y-2 text-sm text-slate-600", children: WHAT_CHANGES_BULLETS.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-emerald-600", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: item })
        ] }, item)) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Affected pending Inbox items" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-4xl font-semibold tabular-nums text-brand-dark", children: pendingInboxCount }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm text-slate-600", children: [
          "Pending review item",
          pendingInboxCount === 1 ? "" : "s",
          " may be affected by stricter fallback controls."
        ] }),
        onOpenInbox && pendingInboxCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onOpenInbox, children: [
          "Open Inbox",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "ml-1.5 h-4 w-4", "aria-hidden": "true" })
        ] }) }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: "Cloud exceptions still apply" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 leading-relaxed", children: "Signed Cloud exceptions still require bundle acknowledgement before they apply locally." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBeaker, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-blue", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Test policy" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Simulate how Guard will respond." })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block space-y-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Scenario" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "select",
            {
              value: scenarioId,
              onChange: handleScenarioChange,
              className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
              children: TEST_SCENARIOS.map((scenario) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: scenario.id, children: scenario.label }, scenario.id))
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Expected action" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: resolveExpectedActionTone(expectedAction), children: policyActionLabel(expectedAction) }) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: handleRunSimulation, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlay, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
            "Run simulation"
          ] })
        ] }),
        simulationVisible && simulation ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-xl border border-slate-100 bg-white p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
            "Policy simulator outcome: ",
            policyActionLabel(simulation.outcome),
            " (",
            simulation.winningStep,
            ")"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1 text-xs text-slate-600", children: simulation.path.map((step) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: step }, step)) })
        ] }) : null
      ] })
    ] })
  ] });
}
function resolvePolicyViewLabel(view) {
  if (view === "rules") {
    return "Remembered rules";
  }
  if (view === "exceptions") {
    return "Cloud exceptions";
  }
  return "Strict config";
}
function PolicyWorkspace$1({
  activeView,
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox,
  onOpenCloudExceptions,
  exceptionRequestOpen = false,
  onExceptionRequestOpenChange,
  onReloadPolicy,
  reloadingPolicy = false
}) {
  if (activeView === "rules") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "policy-panel-rules", role: "tabpanel", "aria-labelledby": "policy-tab-rules", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyRememberedRulesTab,
      {
        policies,
        snapshot,
        cloudControlsUrl: resolveCloudPolicyControlsUrl(snapshot),
        onClearPolicy,
        onOpenCloudExceptions: onOpenCloudExceptions ?? (() => void 0)
      }
    ) });
  }
  if (activeView === "exceptions") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "policy-panel-exceptions", role: "tabpanel", "aria-labelledby": "policy-tab-exceptions", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyCloudExceptionsTab,
      {
        snapshot,
        requestOpen: exceptionRequestOpen,
        onRequestOpenChange: onExceptionRequestOpenChange
      }
    ) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "policy-panel-strict", role: "tabpanel", "aria-labelledby": "policy-tab-strict", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
    PolicyStrictConfigTab,
    {
      snapshot,
      onOpenSettings,
      onOpenInbox,
      onReloadPolicy,
      reloadingPolicy
    }
  ) });
}
const policyWorkspace = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  PolicyWorkspace: PolicyWorkspace$1,
  groupPoliciesByHarness,
  resolveCloudPolicyBundleCopy,
  resolvePolicyViewLabel,
  resolveSecurityModeCopy
}, Symbol.toStringTag, { value: "Module" }));
const POLICY_VIEWS = ["rules", "exceptions", "strict"];
function PolicyUnderlineTabBar({ activeView, onViewChange }) {
  const handleKeyDown = reactExports.useCallback(
    (event, view) => {
      const index = POLICY_VIEWS.indexOf(view);
      if (index < 0) {
        return;
      }
      let nextView;
      if (event.key === "ArrowRight") {
        nextView = POLICY_VIEWS[(index + 1) % POLICY_VIEWS.length];
      } else if (event.key === "ArrowLeft") {
        nextView = POLICY_VIEWS[(index - 1 + POLICY_VIEWS.length) % POLICY_VIEWS.length];
      }
      if (nextView) {
        event.preventDefault();
        onViewChange(nextView);
        document.getElementById(`policy-tab-${nextView}`)?.focus();
      }
    },
    [onViewChange]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "flex flex-wrap gap-6 border-b border-slate-200",
      role: "tablist",
      "aria-label": "Policy sections",
      children: POLICY_VIEWS.map((view) => {
        const selected = activeView === view;
        return /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            role: "tab",
            id: `policy-tab-${view}`,
            "aria-controls": `policy-panel-${view}`,
            "aria-selected": selected,
            tabIndex: selected ? 0 : -1,
            onClick: () => onViewChange(view),
            onKeyDown: (event) => handleKeyDown(event, view),
            className: `-mb-px border-b-2 px-1 pb-3 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${selected ? "border-brand-blue text-brand-blue" : "border-transparent text-slate-500 hover:border-slate-300 hover:text-brand-dark"}`,
            children: resolvePolicyViewLabel(view)
          },
          view
        );
      })
    }
  );
}
function resolveHealthTone(snapshot) {
  if (snapshot.headline_state === "protected" || snapshot.headline_state === "connected") {
    return "success";
  }
  if (snapshot.headline_state === "blocked" || snapshot.headline_state === "setup") {
    return "attention";
  }
  return "default";
}
function PolicyPageToolbar({ snapshot, onReloadPolicy, reloading = false }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-end gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: resolveHealthTone(snapshot), children: snapshot.headline_label }),
    onReloadPolicy ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onReloadPolicy, disabled: reloading, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: `mr-1.5 h-4 w-4 ${reloading ? "animate-spin" : ""}`, "aria-hidden": "true" }),
      "Reload policy"
    ] }) : null
  ] });
}
function PolicyExceptionsToolbar({
  cloudConnected,
  cloudControlsUrl,
  connectUrl,
  onRequestException
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-end gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: onRequestException, disabled: !cloudConnected, children: "+ Request cloud exception" }),
    cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
      "Open Guard Cloud"
    ] }) : null,
    !cloudConnected && connectUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: connectUrl, variant: "secondary", children: "Connect Guard Cloud" }) : null
  ] });
}
const PolicyWorkspace = reactExports.lazy(
  () => __vitePreload(() => Promise.resolve().then(() => policyWorkspace), true ? void 0 : void 0).then((module) => ({ default: module.PolicyWorkspace }))
);
function PolicyFallback() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-40 w-full rounded-2xl", "aria-busy": "true", "aria-live": "polite" });
}
function PolicyWorkspacePage(props) {
  const [activeView, setActiveView] = reactExports.useState("rules");
  const [reloading, setReloading] = reactExports.useState(false);
  const [exceptionRequestOpen, setExceptionRequestOpen] = reactExports.useState(false);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(props.snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(props.snapshot);
  const handleOpenSettings = reactExports.useCallback(() => props.onOpenSettings(), [props]);
  const handleOpenInbox = reactExports.useCallback(() => props.onOpenInbox(), [props]);
  const handleViewChange = reactExports.useCallback((view) => setActiveView(view), []);
  const handleReloadPolicy = reactExports.useCallback(() => {
    setReloading(true);
    try {
      props.onRefreshPolicies();
    } finally {
      window.setTimeout(() => setReloading(false), 600);
    }
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "Policy",
        title: "Remembered rules and exceptions",
        description: "See what Guard will do next time, in plain language. Remove local rules or add custom exceptions here.",
        actions: activeView === "exceptions" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicyExceptionsToolbar,
          {
            cloudConnected,
            cloudControlsUrl,
            connectUrl: props.snapshot.connect_url?.trim() || null,
            onRequestException: () => setExceptionRequestOpen(true)
          }
        ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicyPageToolbar,
          {
            snapshot: props.snapshot,
            onReloadPolicy: handleReloadPolicy,
            reloading
          }
        )
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyUnderlineTabBar, { activeView, onViewChange: handleViewChange }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyWorkspace,
      {
        activeView,
        policies: props.policies,
        snapshot: props.snapshot,
        onClearPolicy: props.onClearPolicy,
        onOpenSettings: handleOpenSettings,
        onOpenInbox: handleOpenInbox,
        onOpenCloudExceptions: () => setActiveView("exceptions"),
        exceptionRequestOpen,
        onExceptionRequestOpenChange: setExceptionRequestOpen,
        onReloadPolicy: handleReloadPolicy,
        reloadingPolicy: reloading
      }
    ) })
  ] });
}
export {
  PolicyWorkspacePage
};
