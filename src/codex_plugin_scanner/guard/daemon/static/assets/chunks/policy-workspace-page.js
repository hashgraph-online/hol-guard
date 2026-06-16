import { j as jsxRuntimeExports, S as SectionLabel, o as HiMiniXMark, B as Badge, ac as Tag, aA as HiMiniCommandLine, w as HiMiniExclamationTriangle, b0 as scopeLabel, h as harnessDisplayName, A as ActionButton, b1 as guardAwareHref, m as formatRelativeTime, b2 as HiMiniDocumentText, d as HiMiniCheckCircle, b3 as HiMiniCloudArrowUp, b4 as HiMiniCheck, b5 as HiMiniCodeBracket, b6 as HiMiniClipboardDocument, b7 as HiMiniUsers, aG as HiMiniBeaker, b8 as HiMiniFolder, b9 as HiMiniInformationCircle, O as HiMiniLockClosed, l as HiMiniShieldCheck, r as reactExports, ba as createCloudExceptionRequest, b as EmptyState, ad as HiMiniMagnifyingGlass, p as HiMiniChevronUp, q as HiMiniChevronDown, y as HiMiniChevronRight, bb as HiMiniPuzzlePiece, bc as HiMiniGlobeAlt, aE as HiMiniClock, bd as policyActionLabel, be as fetchCloudExceptions, bf as fetchCloudExceptionRequests, bg as downloadBlob, bh as PaginationControls, bi as HiMiniNoSymbol, aM as HiMiniArrowTopRightOnSquare, bj as HiMiniCube, aw as HiMiniArrowPath, t as HiMiniCloud, T as HiMiniAdjustmentsHorizontal, bk as HiMiniArrowDownTray, Y as fetchSettings, _ as updateSettings, x as HiMiniBolt, bl as HiMiniQueueList, bm as HiMiniArrowRight, bn as HiMiniPlay, a_ as WorkspacePageHeader, a$ as __vitePreload } from "../guard-dashboard.js";
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
function resolveCloudExceptionSubtitle(item) {
  if (item.scope === "artifact" && item.artifact_id?.trim()) {
    return "Exact action fingerprint";
  }
  if (item.scope === "publisher") {
    return "Publisher-scoped exception";
  }
  if (item.scope === "workspace") {
    return "Project-scoped exception";
  }
  if (item.scope === "harness" && item.harness) {
    return `${item.harness} harness actions`;
  }
  if (item.scope === "global") {
    return "Team policy override";
  }
  return "Cloud risk acceptance";
}
function resolveRequestScopeBlastRadius(scope) {
  if (scope === "artifact") {
    return { label: "Very low", detail: "Only this exact command + context.", tone: "narrow" };
  }
  if (scope === "publisher") {
    return { label: "Low", detail: "Any matching action in your current folder.", tone: "narrow" };
  }
  if (scope === "workspace") {
    return { label: "Medium", detail: "Any matching action in this project repository.", tone: "medium" };
  }
  if (scope === "harness") {
    return { label: "High", detail: "Any matching action for this harness.", tone: "wide" };
  }
  return { label: "Very high", detail: "Make this an allow rule for your whole team.", tone: "wide" };
}
function resolveCloudExceptionEvidenceUrl(item) {
  const receiptId = item.source_receipt_id?.trim();
  if (!receiptId) {
    return null;
  }
  return `/evidence?search=${encodeURIComponent(receiptId)}`;
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
function PersonBlock({
  label,
  value,
  role
}) {
  const display = resolvePersonDisplayLabel(value);
  const initials = resolvePersonInitials(value);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-center gap-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "span",
        {
          "aria-hidden": "true",
          className: "inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-xs font-semibold text-brand-blue",
          children: initials
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: display }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: role })
      ] })
    ] })
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
    return { label: "Offline", detail: "This device was offline when the signed bundle was issued." };
  }
  return { label: "Unknown", detail: "Local acknowledgement status is unavailable." };
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
  const subtitle = resolveCloudExceptionSubtitle(exception);
  const blast = resolveCloudExceptionBlastRadius(exception.scope);
  const whyCopy = resolveCloudExceptionWhyCopy(exception);
  const isActive = isCloudExceptionActive(exception);
  const isEnforcedLocally = exception.ack_status === "synced";
  const evidenceUrl = resolveCloudExceptionEvidenceUrl(exception);
  const scopePath = resolveCloudExceptionScopePath(exception);
  const effectLabel = resolveCloudExceptionEffectLabel(exception.effect);
  const atRisk = isCloudExceptionExpiringSoon(exception) || isCloudExceptionAckFailure(exception);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "aside",
    {
      className: "min-w-0 rounded-2xl border border-slate-200 bg-white shadow-sm lg:sticky lg:top-4",
      "aria-label": "Cloud exception details",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-5 py-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Temporary cloud exception" }),
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
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-2", children: [
            isActive ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Active" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Expired" }),
            isEnforcedLocally ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Enforced locally" }) : null,
            !isEnforcedLocally ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: ackCopy.label }) : null
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-start gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCommandLine, { className: "h-5 w-5", "aria-hidden": "true" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "break-words text-lg font-semibold text-brand-dark", children: headline }),
                atRisk ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "purple", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mr-1 inline h-3.5 w-3.5", "aria-hidden": "true" }),
                  "At risk"
                ] }) : null
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: subtitle }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: effectLabel })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 px-5 py-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Why this exists" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-brand-dark", children: whyCopy })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 sm:grid-cols-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Blast radius" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: blastRadiusBadgeTone(blast.tone), children: blast.label }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-relaxed text-slate-600", children: blast.detail })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Scope (exact)" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: scopeLabel(exception.scope, "policy") }) }),
              exception.harness ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-medium text-brand-dark", children: harnessDisplayName(exception.harness) }) : null,
              scopePath ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-all text-xs text-slate-500", children: scopePath }) : null
            ] })
          ] }),
          evidenceUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Source review item" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: exception.artifact_id?.trim() || exception.source_receipt_id?.trim() || "Linked approval record" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-500", children: [
              exception.harness ? harnessDisplayName(exception.harness) : "Guard review",
              " · receipt linked"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: guardAwareHref(evidenceUrl), variant: "secondary", children: "Open in Review" }) })
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(PersonBlock, { label: "Owner", value: exception.owner, role: "Repository member" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(PersonBlock, { label: "Approved by", value: exception.approver, role: "Security team" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Expires" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: expiryTimestamp ? expiryTimestamp.toLocaleDateString() : "Not set" }),
              expiryValue ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: formatRelativeTime(expiryValue) }) : null
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Last used" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: exception.last_used_at ? formatRelativeTime(exception.last_used_at) : "Not yet used" })
            ] })
          ] }),
          exception.bundle_hash ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Signed bundle entry" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-start gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-xs text-brand-dark", children: exception.bundle_hash }),
                exception.source_receipt_id ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-all text-xs text-slate-500", children: exception.source_receipt_id }) : null
              ] })
            ] })
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Local daemon ack" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-center gap-2", children: [
              exception.ack_status === "synced" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-emerald-600", "aria-hidden": "true" }) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: ackCopy.label })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: ackCopy.detail })
          ] })
        ] }),
        cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 px-5 py-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Open Guard Cloud to revoke or renew this exception." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
            "Open in Guard Cloud"
          ] }) })
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
const SCOPE_ICONS = {
  artifact: HiMiniCodeBracket,
  publisher: HiMiniFolder,
  workspace: HiMiniFolder,
  harness: HiMiniBeaker,
  "team-policy": HiMiniUsers
};
function ScopeCardGrid({ options, value, onChange }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "-mx-1 flex gap-2 overflow-x-auto px-1 pb-1", role: "radiogroup", "aria-label": "Exception scope", children: options.map((option) => {
    const blast = resolveRequestScopeBlastRadius(option.value);
    const selected = value === option.value;
    const Icon = SCOPE_ICONS[option.value];
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        role: "radio",
        "aria-checked": selected,
        disabled: option.disabled,
        onClick: () => onChange(option.value),
        className: `min-w-[148px] shrink-0 rounded-xl border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${selected ? `${SCOPE_CARD_TONES[blast.tone]} ring-2 ring-brand-blue/30` : `${SCOPE_CARD_TONES[blast.tone]} opacity-95`}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4 text-slate-500", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: option.label })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: option.description }),
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
const SAFETY_ITEMS = [
  {
    icon: HiMiniInformationCircle,
    title: "Requires Cloud approval",
    detail: "Your request will be reviewed and approved in Guard Cloud."
  },
  {
    icon: HiMiniLockClosed,
    title: "Requires MFA for this scope",
    detail: "Broad scopes require step-up authentication."
  },
  {
    icon: HiMiniShieldCheck,
    title: "Signed bundle enforcement",
    detail: "Local daemon will enforce only after receiving signed bundle ack."
  }
];
function resolveSafetyScopeTarget(scope, artifactId, publisher, harness, workingDirectory) {
  if (scope === "artifact") {
    return artifactId || "Selected artifact";
  }
  if (scope === "publisher") {
    return publisher || "Publisher";
  }
  if (scope === "harness") {
    return harness;
  }
  if (scope === "workspace") {
    return workingDirectory || "Project folder";
  }
  return "Team policy";
}
function resolveResultActionLabel(scope) {
  if (scope === "artifact") {
    return "this exact action";
  }
  if (scope === "workspace") {
    return "matching actions in this project";
  }
  const scopeForLabel = scope === "team-policy" ? "global" : scope;
  return scopeLabel(scopeForLabel, "policy");
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
  const blast = resolveRequestScopeBlastRadius(scope);
  const scopeTarget = resolveSafetyScopeTarget(scope, artifactId, publisher, harness, workingDirectory);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-slate-50/80 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Safety preview" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Blast radius" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-semibold text-brand-dark", children: blast.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: scopeTarget })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 space-y-3", children: SAFETY_ITEMS.map((item) => {
      const Icon = item.icon;
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: item.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-600", children: item.detail })
        ] })
      ] }, item.title);
    }) }),
    reason.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-xs leading-relaxed text-slate-500", children: [
      "Reason: ",
      reason.trim().slice(0, 120),
      reason.trim().length > 120 ? "…" : ""
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-xs text-slate-500", children: [
      "Expires ",
      expiresLabel
    ] })
  ] });
}
function SourceReceiptSummary({ receipt }) {
  const evidenceHref = `/evidence?search=${encodeURIComponent(receipt.receipt_id)}`;
  const artifactLabel = receipt.artifact_name ?? receipt.artifact_id;
  const handleCopyArtifact = () => {
    if (!receipt.artifact_id || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(receipt.artifact_id);
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-slate-50/80 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Source: approval record" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-200/80 text-slate-600", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCodeBracket, { className: "h-4 w-4", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: artifactLabel }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
          harnessDisplayName(receipt.harness),
          " · Reviewed recently"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Artifact ID" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex items-center gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate font-mono text-xs text-brand-dark", children: receipt.artifact_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: handleCopyArtifact,
              className: "rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark",
              "aria-label": "Copy artifact ID",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Evidence receipt" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "a",
          {
            href: guardAwareHref(evidenceHref),
            className: "mt-1 inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
              receipt.receipt_id
            ]
          }
        )
      ] })
    ] })
  ] });
}
function ResultPreview({ scope, harness, expiresLabel }) {
  const showHarness = (scope === "artifact" || scope === "harness") && harness.trim();
  const actionLabel = resolveResultActionLabel(scope);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-white p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Result preview" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-sm leading-relaxed text-brand-dark", children: [
      "If approved in Guard Cloud, Guard will allow ",
      actionLabel,
      showHarness ? ` for ${harnessDisplayName(harness)}` : "",
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
const DRAFT_STORAGE_KEY = "hol-guard:cloud-exception-request-draft";
const SCOPE_OPTIONS = [
  {
    value: "artifact",
    label: "Exact action",
    description: "Only this exact command + context."
  },
  {
    value: "publisher",
    label: "This cwd",
    description: "Any matching action in your current folder."
  },
  {
    value: "workspace",
    label: "This project",
    description: "Any matching action in this project repository."
  },
  {
    value: "harness",
    label: "This harness",
    description: "Any matching action for this harness."
  },
  {
    value: "team-policy",
    label: "Team policy",
    description: "Make this an allow rule for your whole team.",
    disabled: true
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
  const [scope, setScope] = reactExports.useState("workspace");
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
      if (scope === "team-policy") {
        setError("Team policy exceptions must be created directly in Guard Cloud.");
        setSubmitting(false);
        return;
      }
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
  const canAdvanceFromScope = scope !== "team-policy" && (scope !== "artifact" || artifactId.trim()) && (scope !== "publisher" || publisher.trim()) && (scope !== "workspace" || workingDirectory.trim()) && (scope === "harness" || scope === "artifact" ? harness.trim() : true) && reason.trim().length > 0 && owner.trim().length > 0 && requestedExpiresAt.trim().length > 0;
  const canAdvanceFromGuardrails = requestedBy.trim().length > 0;
  const canSubmit = canAdvanceFromSource && canAdvanceFromScope && canAdvanceFromGuardrails;
  const handleSaveDraft = reactExports.useCallback(() => {
    const draft = {
      scope,
      harness,
      artifactId,
      publisher,
      workingDirectory,
      sourceReceiptId,
      requestedBy,
      owner,
      reason,
      requestedExpiresAt,
      linkedTicket,
      maxUses
    };
    try {
      localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
    } catch {
    }
  }, [
    artifactId,
    harness,
    linkedTicket,
    maxUses,
    owner,
    publisher,
    reason,
    requestedBy,
    requestedExpiresAt,
    scope,
    sourceReceiptId,
    workingDirectory
  ]);
  reactExports.useEffect(() => {
    try {
      const saved = localStorage.getItem(DRAFT_STORAGE_KEY);
      if (!saved) {
        return;
      }
      const draft = JSON.parse(saved);
      if (draft.scope) {
        setScope(draft.scope);
      }
      if (draft.harness) {
        setHarness(draft.harness);
      }
      if (draft.artifactId) {
        setArtifactId(draft.artifactId);
      }
      if (draft.publisher) {
        setPublisher(draft.publisher);
      }
      if (draft.workingDirectory) {
        setWorkingDirectory(draft.workingDirectory);
      }
      if (draft.sourceReceiptId) {
        setSourceReceiptId(draft.sourceReceiptId);
      }
      if (draft.requestedBy) {
        setRequestedBy(draft.requestedBy);
      }
      if (draft.owner) {
        setOwner(draft.owner);
      }
      if (draft.reason) {
        setReason(draft.reason);
      }
      if (draft.requestedExpiresAt) {
        setRequestedExpiresAt(draft.requestedExpiresAt);
      }
      if (draft.linkedTicket) {
        setLinkedTicket(draft.linkedTicket);
      }
      if (draft.maxUses) {
        setMaxUses(draft.maxUses);
      }
    } catch {
    }
  }, []);
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
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          activeStep === "Scope" || activeStep === "Guardrails" || activeStep === "Submit" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: handleSaveDraft, disabled: submitting, children: "Save draft locally" }) : null,
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
                      type: "number",
                      min: 1,
                      step: 1,
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
              scope === "harness" || scope === "workspace" || scope === "team-policy" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80", children: "Broad scopes require step-up authentication and Cloud approval." }) : null
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
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 truncate text-xs text-slate-500", children: resolveCloudExceptionSubtitle(item) }),
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "list", children })
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
const SUMMARY_VALUE_CLASSES = {
  green: "text-emerald-700",
  purple: "text-violet-700",
  amber: "text-amber-700",
  red: "text-rose-700"
};
const SUMMARY_ICON_CLASSES = {
  green: "bg-emerald-50 text-emerald-600",
  purple: "bg-violet-50 text-violet-600",
  amber: "bg-amber-50 text-amber-600",
  red: "bg-rose-50 text-rose-600"
};
function SummaryCard({
  label,
  value,
  detail,
  tone,
  icon
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-slate-200/70 bg-white p-4 shadow-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-2 text-3xl font-semibold tabular-nums ${SUMMARY_VALUE_CLASSES[tone]}`, children: value }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: detail })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: `flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${SUMMARY_ICON_CLASSES[tone]}`,
        "aria-hidden": "true",
        children: icon
      }
    )
  ] }) });
}
function SummarySkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 gap-3 md:grid-cols-4", children: [0, 1, 2, 3].map((index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "h-[96px] animate-pulse rounded-xl border border-slate-200/70 bg-slate-100",
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
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SummaryCard,
          {
            label: "Active synced",
            value: activeCount,
            detail: "Enforced locally",
            tone: "green",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-5 w-5" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SummaryCard,
          {
            label: "Pending approval",
            value: pendingCount,
            detail: "Awaiting decision",
            tone: "purple",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "h-5 w-5" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SummaryCard,
          {
            label: "Expiring soon",
            value: expiringSoonCount,
            detail: "Within 7 days",
            tone: "amber",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "h-5 w-5" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SummaryCard,
          {
            label: "Local ack failures",
            value: ackFailureCount,
            detail: "Needs attention",
            tone: "red",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-5 w-5" })
          }
        )
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
const SCANNER_GENERATED_LABEL_MARKERS = [
  "credential-looking",
  "credential looking",
  "secret-looking",
  "suspicious output",
  "looking output",
  "scanner flagged"
];
function isScannerGeneratedPolicyLabel(value) {
  if (!value?.trim()) {
    return true;
  }
  const lowered = value.trim().toLowerCase();
  return SCANNER_GENERATED_LABEL_MARKERS.some((marker) => lowered.includes(marker));
}
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
function resolvePolicySourceLabel(source) {
  if (isCloudManagedPolicy(source)) {
    return "Guard Cloud";
  }
  if (source === "manual" || source === "local") {
    return "Local";
  }
  return source.replace(/_/g, " ");
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
  if (remembered && !isScannerGeneratedPolicyLabel(remembered)) {
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
  if (rememberedCommand && !isScannerGeneratedPolicyLabel(rememberedCommand)) {
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
  if (reason && !isGenericReason(reason) && !isScannerGeneratedPolicyLabel(reason)) {
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
function resolvePolicyRowFolder(policy) {
  const pathLine = formatPolicyScopePath(policy.source_scope_path);
  if (pathLine) {
    return pathLine;
  }
  const label = policy.workspace_label?.trim();
  if (label) {
    return label;
  }
  const workspace = policy.workspace?.trim();
  if (!workspace || workspace.startsWith("workspace:")) {
    return null;
  }
  return formatPolicyScopePath(workspace) ?? resolveWorkspaceLabel(workspace);
}
function resolvePolicyRowTitle(policy, display) {
  const rememberedCommand = policy.remembered_command?.trim();
  if (rememberedCommand && !isScannerGeneratedPolicyLabel(rememberedCommand)) {
    return rememberedCommand;
  }
  const reason = policy.reason?.trim();
  if (reason && !isGenericReason(reason) && !isScannerGeneratedPolicyLabel(reason)) {
    return reason;
  }
  const artifactId = policy.artifact_id?.trim();
  if (artifactId && !artifactId.startsWith("family:") && !artifactId.includes(":")) {
    const slashIndex = artifactId.lastIndexOf("/");
    const candidate = slashIndex >= 0 && slashIndex < artifactId.length - 1 ? artifactId.slice(slashIndex + 1) : artifactId;
    if (candidate.length <= 64 && !isScannerGeneratedPolicyLabel(candidate)) {
      return candidate;
    }
  }
  const headline = display.headline.trim();
  const verb = policyActionLabel(policy.action);
  if (headline.toLowerCase().startsWith(verb.toLowerCase())) {
    return headline.slice(verb.length).trim() || headline;
  }
  return headline;
}
function resolvePolicyRowSourceLabel(policy) {
  return resolvePolicySourceLabel(policy.source);
}
function sortPolicyDecisions(policies, sort) {
  if (!sort) {
    return policies;
  }
  const direction = sort.direction === "asc" ? 1 : -1;
  const sorted = [...policies];
  sorted.sort((left, right) => {
    const compareText = (a, b) => direction * a.localeCompare(b, void 0, { sensitivity: "base" });
    switch (sort.key) {
      case "action":
        return compareText(left.action, right.action);
      case "rule": {
        const leftTitle = resolvePolicyRowTitle(left, resolvePolicyDisplay(left));
        const rightTitle = resolvePolicyRowTitle(right, resolvePolicyDisplay(right));
        return compareText(leftTitle, rightTitle);
      }
      case "source":
        return compareText(resolvePolicyRowSourceLabel(left), resolvePolicyRowSourceLabel(right));
      case "scope":
        return compareText(scopeLabel(left.scope, "policy"), scopeLabel(right.scope, "policy"));
      case "app":
        return compareText(harnessDisplayName(left.harness), harnessDisplayName(right.harness));
      case "updated": {
        const leftTime = left.updated_at ? new Date(left.updated_at).getTime() : 0;
        const rightTime = right.updated_at ? new Date(right.updated_at).getTime() : 0;
        const leftVal = Number.isNaN(leftTime) ? 0 : leftTime;
        const rightVal = Number.isNaN(rightTime) ? 0 : rightTime;
        return direction * (leftVal - rightVal);
      }
      case "approval":
        return compareText(
          resolvePolicyApprovalRecordLabel(left),
          resolvePolicyApprovalRecordLabel(right)
        );
      default:
        return 0;
    }
  });
  return sorted;
}
function formatPolicyDateTime(timestamp) {
  if (!timestamp?.trim()) {
    return null;
  }
  try {
    return new Intl.DateTimeFormat(void 0, {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit"
    }).format(new Date(timestamp));
  } catch {
    return null;
  }
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
  params.set("view", "actions");
  if (policy.harness?.trim()) {
    params.set("harness", policy.harness.trim());
  }
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
    if (/^receipt[_-]/i.test(receiptId) && receiptId.endsWith(".json")) {
      return receiptId.length <= 28 ? receiptId : `receipt_${receiptId.slice(8, 16)}.json`;
    }
    const normalized = receiptId.replace(/^receipt[-_]?/i, "").replace(/\.json$/i, "");
    const shortId = normalized.length <= 8 ? normalized : normalized.slice(0, 8);
    return `receipt_${shortId}.json`;
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
  const firstActiveId = groups.active[0]?.id ?? null;
  reactExports.useEffect(() => {
    if (loadState !== "ready" || !firstActiveId) {
      return;
    }
    setSelectedExceptionId((current) => current ?? firstActiveId);
  }, [firstActiveId, loadState]);
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
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px] xl:items-start", children: [
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
function PolicyActiveModeCard({ snapshot }) {
  const modeCopy = resolveSecurityModeCopy(snapshot.security_level);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200/70 bg-white p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active mode" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-5 w-5", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: modeCopy.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-slate-600", children: modeCopy.description })
      ] })
    ] })
  ] });
}
function escapeCsvCell(value) {
  const str = value ?? "";
  if (/[",\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}
function policyExportRow(policy) {
  const display = resolvePolicyDisplay(policy);
  return [
    policyActionLabel(policy.action),
    resolvePolicyRowTitle(policy, display),
    display.kindLine ?? "",
    resolvePolicyRowSourceLabel(policy),
    scopeLabel(policy.scope, "policy"),
    harnessDisplayName(policy.harness),
    policy.updated_at ?? "",
    policy.source_receipt_id ?? "",
    resolvePolicyApprovalRecordLabel(policy)
  ];
}
const CSV_HEADERS = [
  "Action",
  "Rule",
  "Kind",
  "Source",
  "Scope",
  "App",
  "Updated",
  "Receipt ID",
  "Approval record"
];
function exportPoliciesCsv(policies) {
  const lines = [
    CSV_HEADERS.map(escapeCsvCell).join(","),
    ...policies.map((policy) => policyExportRow(policy).map(escapeCsvCell).join(","))
  ];
  const today = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
  return {
    blob: new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" }),
    filename: `hol-guard-policy-rules-${today}.csv`
  };
}
function exportPoliciesJson(policies) {
  const payload = policies.map((policy) => {
    const display = resolvePolicyDisplay(policy);
    return {
      action: policy.action,
      rule: resolvePolicyRowTitle(policy, display),
      kind: display.kindLine,
      source: resolvePolicyRowSourceLabel(policy),
      scope: scopeLabel(policy.scope, "policy"),
      app: policy.harness,
      updated_at: policy.updated_at,
      receipt_id: policy.source_receipt_id,
      approval_record: resolvePolicyApprovalRecordLabel(policy),
      artifact_id: policy.artifact_id,
      workspace: policy.workspace
    };
  });
  const today = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
  return {
    blob: new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
    filename: `hol-guard-policy-rules-${today}.json`
  };
}
function downloadPolicies(format, policies) {
  const result = format === "csv" ? exportPoliciesCsv(policies) : exportPoliciesJson(policies);
  downloadBlob(result.blob, result.filename);
}
function formatCloudBundleHashDisplay(hash) {
  if (!hash?.trim()) {
    return "Unavailable";
  }
  const value = hash.trim();
  const isSha256 = value.toLowerCase().startsWith("sha256:");
  const normalized = isSha256 ? value.slice(7) : value;
  if (isSha256) {
    return normalized.length <= 4 ? value : `sha256:${normalized.slice(0, 4)}…`;
  }
  return normalized.length <= 8 ? normalized : `${normalized.slice(0, 8)}…`;
}
function resolveCloudBundleStatusSubtitle(copy) {
  if (copy.tone === "green") {
    return "All policies up to date";
  }
  if (copy.tone === "attention") {
    return "Latest sync needs attention";
  }
  return copy.label;
}
function PolicyGuardCloudBundleCard({ snapshot }) {
  const cloudBundleCopy = resolveCloudPolicyBundleCopy(snapshot);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const lastAckAt = snapshot.cloud_policy_last_ack_at?.trim() ?? snapshot.runtime_state?.last_heartbeat_at?.trim() ?? snapshot.generated_at?.trim() ?? null;
  const policyHash = cloudBundleCopy?.hash?.trim() ?? null;
  const policyHashDisplay = formatCloudBundleHashDisplay(policyHash);
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim() ?? null;
  const handleCopyHash = reactExports.useCallback(() => {
    if (!policyHash || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(policyHash);
  }, [policyHash]);
  if (!cloudBundleCopy) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200/70 bg-white p-4 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
      cloudConnected ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-medium text-brand-dark", children: snapshot.cloud_state_label?.trim() || "Connected to Guard Cloud" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-brand-dark/75", children: snapshot.cloud_state_detail?.trim() || "Guard Cloud is connected. Policy bundle details will appear after the next successful sync." })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-brand-dark/75", children: "Guard Cloud is not connected. Remembered Cloud rules appear when Guard Cloud syncs a bundle." }),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
        "Open Guard Cloud"
      ] }) }) : null
    ] });
  }
  const synced = cloudBundleCopy.tone === "green";
  const statusSubtitle = resolveCloudBundleStatusSubtitle(cloudBundleCopy);
  const showDetail = !synced;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200/70 bg-white p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid min-w-0 flex-1 grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Status" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-1.5", children: [
                synced ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-emerald-600", "aria-hidden": "true" }) : null,
                /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: synced ? "green" : "amber", children: synced ? "Synced" : cloudBundleCopy.label })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-500", children: statusSubtitle })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Bundle hash" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5 flex min-w-0 items-center gap-1.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate font-mono text-sm text-brand-dark", title: policyHash ?? void 0, children: policyHashDisplay }),
              policyHash ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  onClick: handleCopyHash,
                  className: "shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark",
                  "aria-label": "Copy bundle hash",
                  children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { className: "h-4 w-4", "aria-hidden": "true" })
                }
              ) : null
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 sm:col-span-2 xl:col-span-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Last ack" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-1.5", children: [
                lastAckAt && synced ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-emerald-600", "aria-hidden": "true" }) : null,
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: lastAckAt ? formatRelativeTime(lastAckAt) : "Not yet" })
              ] }),
              bundleVersion ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 truncate text-xs text-slate-500", title: bundleVersion, children: bundleVersion }) : null
            ] })
          ] })
        ] }),
        cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "w-full shrink-0 sm:w-auto lg:pt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Open Guard Cloud"
        ] }) }) : null
      ] }),
      showDetail ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-xl border border-amber-200/80 bg-amber-50/60 px-3 py-2 text-sm leading-relaxed text-slate-700", children: cloudBundleCopy.detail }) : null
    ] })
  ] });
}
function EvidenceTable({ children, label, tableClassName = "" }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-slate-100 bg-white overflow-hidden shadow-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsx("table", { className: `w-full text-sm ${tableClassName}`, "aria-label": label, children }) }) });
}
function EvidenceTableHead({ children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("tr", { className: "border-b border-slate-100 bg-slate-50/80", children }) });
}
function EvidenceTableHeader({ children, className = "" }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "th",
    {
      scope: "col",
      className: `px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 ${className}`,
      children
    }
  );
}
function EvidenceTableBody({ children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children });
}
function EvidenceTableRow({ children, onClick, isSelected }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "tr",
    {
      onClick,
      className: `border-b border-slate-100 last:border-0 transition-colors ${isSelected ? "bg-brand-blue/[0.04]" : onClick ? "hover:bg-slate-50 cursor-pointer" : ""}`,
      children
    }
  );
}
function EvidenceTableCell({ children, className = "" }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: `px-3 py-2.5 ${className}`, children });
}
const PAGE_SIZE = 10;
const TABLE_MIN_WIDTH_CLASS = "min-w-[1040px]";
function PolicyActionBadge({ action }) {
  if (action === "allow") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 rounded-full border border-emerald-300 bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
      "Allow"
    ] });
  }
  if (action === "block") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 rounded-full border border-rose-300 bg-rose-50 px-2.5 py-0.5 text-xs font-semibold text-rose-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniNoSymbol, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
      "Block"
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex items-center gap-1 rounded-full border border-amber-300 bg-amber-50 px-2.5 py-0.5 text-xs font-semibold text-amber-900", children: policyActionLabel(action) });
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
function PolicySortHeader({
  label,
  sortKey,
  sort,
  onSortChange,
  className = ""
}) {
  const active = sort?.key === sortKey;
  const ascending = active && sort?.direction === "asc";
  const handleClick = reactExports.useCallback(() => {
    if (!active) {
      onSortChange({ key: sortKey, direction: sortKey === "updated" ? "desc" : "asc" });
      return;
    }
    onSortChange({ key: sortKey, direction: ascending ? "desc" : "asc" });
  }, [active, ascending, onSortChange, sortKey]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableHeader, { className, children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleClick,
      className: "inline-flex items-center gap-1 transition-colors hover:text-brand-dark",
      "aria-label": `Sort by ${label}${active ? ascending ? ", ascending" : ", descending" : ""}`,
      children: [
        label,
        active ? ascending ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-3 w-3", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-3 w-3", "aria-hidden": "true" }) : null
      ]
    }
  ) });
}
function PolicyEvidenceLink({
  policy,
  onNavigate
}) {
  const href = resolvePolicyEvidenceHref(policy);
  const label = resolvePolicyApprovalRecordLabel(policy);
  const handleClick = reactExports.useCallback(
    (event) => {
      if (!onNavigate) {
        return;
      }
      event.preventDefault();
      onNavigate(href);
    },
    [href, onNavigate]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "a",
    {
      href: guardAwareHref(href),
      onClick: handleClick,
      className: "inline-flex max-w-full items-center gap-1 font-mono text-xs font-medium text-brand-blue hover:underline",
      title: `Open ${label} in Evidence`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3.5 w-3.5 shrink-0", "aria-hidden": "true" })
      ]
    }
  );
}
function PolicyRuleRow({ policy, cloudControlsUrl, onClear, onNavigate, cloudVariant = false }) {
  const handleClear = reactExports.useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = cloudVariant || isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== void 0 && !cloudManaged;
  const family = resolvePolicyMatcherFamily(policy);
  const Icon = resolveFamilyIcon(family);
  const title = resolvePolicyRowTitle(policy, display);
  const kindLine = display.kindLine;
  const scopeTag = scopeLabel(policy.scope, "policy");
  const folder = resolvePolicyRowFolder(policy);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(EvidenceTableRow, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "w-10", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "w-[88px] whitespace-nowrap", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyActionBadge, { action: policy.action }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(EvidenceTableCell, { className: "min-w-[220px] max-w-[320px]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate font-semibold leading-snug text-brand-dark", title, children: title }),
      kindLine ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 truncate text-xs leading-relaxed text-slate-500", title: kindLine, children: kindLine }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 space-y-1 text-xs text-slate-600 lg:hidden", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-slate-700", children: "Source:" }),
          " ",
          resolvePolicyRowSourceLabel(policy)
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-slate-700", children: "Scope:" }),
          " ",
          scopeTag
        ] }),
        folder ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-slate-700", children: "Folder:" }),
          " ",
          folder
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-slate-700", children: "App:" }),
          " ",
          harnessDisplayName(policy.harness)
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "hidden w-[88px] lg:table-cell", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark", children: resolvePolicyRowSourceLabel(policy) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "hidden w-[104px] lg:table-cell", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-blue", children: scopeTag }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "hidden w-[96px] lg:table-cell", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-blue", children: harnessDisplayName(policy.harness) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "hidden w-[104px] whitespace-nowrap text-xs text-slate-500 lg:table-cell", children: policy.updated_at ? formatRelativeTime(policy.updated_at) : "—" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(EvidenceTableCell, { className: "hidden min-w-[132px] lg:table-cell", children: [
      !cloudManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyEvidenceLink, { policy, onNavigate }) : null,
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
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "hidden w-[108px] text-right lg:table-cell", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-end gap-2", children: [
      cloudManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Read-only" }) : null,
      canClear ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: handleClear,
          className: "inline-flex items-center gap-1 text-xs font-medium text-rose-600 hover:text-rose-700",
          children: "Remove rule"
        }
      ) : null
    ] }) })
  ] });
}
function PolicyRuleTable({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  emptyTitle,
  emptyBody,
  cloudVariant = false,
  sort,
  onSortChange
}) {
  const [page, setPage] = reactExports.useState(1);
  const sortedPolicies = reactExports.useMemo(() => sortPolicyDecisions(policies, sort), [policies, sort]);
  reactExports.useEffect(() => {
    setPage(1);
  }, [policies, sort]);
  const totalPages = Math.max(1, Math.ceil(sortedPolicies.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageStart = (safePage - 1) * PAGE_SIZE;
  const visiblePolicies = sortedPolicies.slice(pageStart, pageStart + PAGE_SIZE);
  const handlePrevious = reactExports.useCallback(() => {
    setPage((current) => Math.max(1, current - 1));
  }, []);
  const handleNext = reactExports.useCallback(() => {
    setPage((current) => Math.min(totalPages, current + 1));
  }, [totalPages]);
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: emptyTitle, body: emptyBody, tone: "teach" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(EvidenceTable, { label: cloudVariant ? "Cloud policy rules" : "Remembered policy rules", tableClassName: TABLE_MIN_WIDTH_CLASS, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(EvidenceTableHead, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableHeader, { className: "w-10" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(PolicySortHeader, { label: "Action", sortKey: "action", sort, onSortChange, className: "w-[88px]" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(PolicySortHeader, { label: "Rule", sortKey: "rule", sort, onSortChange, className: "min-w-[220px]" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicySortHeader,
          {
            label: "Source",
            sortKey: "source",
            sort,
            onSortChange,
            className: "hidden lg:table-cell"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicySortHeader,
          {
            label: "Scope",
            sortKey: "scope",
            sort,
            onSortChange,
            className: "hidden lg:table-cell"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicySortHeader,
          {
            label: cloudVariant ? "Applies to" : "App",
            sortKey: "app",
            sort,
            onSortChange,
            className: "hidden lg:table-cell"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicySortHeader,
          {
            label: "Updated",
            sortKey: "updated",
            sort,
            onSortChange,
            className: "hidden lg:table-cell"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicySortHeader,
          {
            label: cloudVariant ? "Policy" : "Approval record",
            sortKey: "approval",
            sort,
            onSortChange,
            className: "hidden lg:table-cell"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableHeader, { className: "hidden text-right lg:table-cell", children: cloudVariant ? "" : "Actions" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableBody, { children: visiblePolicies.map((policy) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyRuleRow,
        {
          policy,
          cloudControlsUrl,
          onClear: onClearPolicy,
          onNavigate,
          cloudVariant
        },
        `${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`
      )) })
    ] }),
    sortedPolicies.length > PAGE_SIZE ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PaginationControls,
      {
        page: safePage,
        totalPages,
        totalItems: sortedPolicies.length,
        pageSize: PAGE_SIZE,
        onPrevious: handlePrevious,
        onNext: handleNext
      }
    ) : null
  ] });
}
function GroupedPolicySection({
  title,
  badge,
  description,
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  emptyTitle,
  emptyBody,
  defaultOpen = true,
  cloudVariant = false,
  sort,
  onSortChange
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
        onNavigate,
        emptyTitle,
        emptyBody,
        cloudVariant,
        sort,
        onSortChange
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
  cloudControlsUrl,
  sort,
  onSortChange
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
      sort,
      onSortChange
    }
  );
}
function PolicyRememberedLocalRules({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  sort,
  onSortChange
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
      onNavigate,
      emptyTitle: "No local remembered rules yet",
      emptyBody: "Approve or block in Inbox and Guard remembers the decision here in plain language.",
      defaultOpen: true,
      sort,
      onSortChange
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
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "space-y-4 lg:sticky lg:top-4", children: [
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
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 text-sm text-slate-600 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "h-5 w-5", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: "Cloud exceptions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-slate-600", children: "Governed risk acceptances override team policy when approved in Guard Cloud. They sync as signed bundle entries on this device." })
        ] })
      ] }),
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
  onOpenCloudExceptions,
  onNavigate
}) {
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [appFilter, setAppFilter] = reactExports.useState("");
  const [familyFilter, setFamilyFilter] = reactExports.useState("");
  const [showFilters, setShowFilters] = reactExports.useState(false);
  const [sort, setSort] = reactExports.useState({ key: "updated", direction: "desc" });
  const searchInputRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    const handleKeyDown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);
  const handleSearchChange = reactExports.useCallback((event) => {
    setSearchQuery(event.target.value);
  }, []);
  const handleToggleFilters = reactExports.useCallback(() => {
    setShowFilters((current) => !current);
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
    () => filteredPolicies.filter((policy) => policy.action === "allow" || policy.action === "block"),
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
  const handleExportCsv = reactExports.useCallback(() => {
    downloadPolicies("csv", rememberedRules);
  }, [rememberedRules]);
  const handleExportJson = reactExports.useCallback(() => {
    downloadPolicies("json", rememberedRules);
  }, [rememberedRules]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyGuardCloudBundleCard, { snapshot }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyActiveModeCard, { snapshot })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 lg:flex-row lg:items-center", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                ref: searchInputRef,
                type: "search",
                placeholder: "Search by app, action, or reason…",
                value: searchQuery,
                onChange: handleSearchChange,
                "aria-label": "Search policies",
                className: "w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx("kbd", { className: "hidden shrink-0 rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 sm:inline", children: "⌘K" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "button",
              {
                type: "button",
                onClick: handleToggleFilters,
                "aria-expanded": showFilters,
                className: `inline-flex min-h-10 items-center gap-1.5 rounded-xl border px-3 py-2 text-sm font-medium transition-colors ${showFilters ? "border-brand-blue/30 bg-brand-blue/[0.04] text-brand-dark" : "border-slate-200 bg-white text-brand-dark hover:border-brand-blue/20"}`,
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "h-4 w-4 text-slate-500", "aria-hidden": "true" }),
                  "Filters"
                ]
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: handleExportCsv, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowDownTray, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
              "Export CSV"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: handleExportJson, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowDownTray, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
              "Export JSON"
            ] })
          ] })
        ] }),
        showFilters ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
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
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyRememberedLocalRules,
        {
          policies: localRules,
          cloudControlsUrl,
          onClearPolicy,
          onNavigate,
          sort,
          onSortChange: setSort
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyRememberedCloudRules,
        {
          policies: cloudRules,
          cloudControlsUrl,
          sort,
          onSortChange: setSort
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyRememberedRulesRightRail, { onOpenCloudExceptions, snapshot })
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
const STRICT_POLICY_DEFAULTS = {
  default_action: "block",
  changed_hash_action: "review",
  new_network_domain_action: "review",
  subprocess_action: "review",
  destructive_shell: "block"
};
function resolveStrictScenarioOutcome(scenarioId, settings) {
  if (scenarioId === "remembered-allow") {
    return {
      outcome: "allow",
      reasoning: "Because a remembered allow rule matches before Cloud policy."
    };
  }
  if (scenarioId === "cloud-exception") {
    return {
      outcome: "allow",
      reasoning: "Because an active Cloud exception overrides team policy."
    };
  }
  const outcome = settings.new_network_domain_action;
  return {
    outcome,
    reasoning: `Because New network domain action is set to ${policyActionLabel(outcome)}.`
  };
}
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
  help,
  icon: Icon
}) {
  const handleSelect = reactExports.useCallback(
    (nextValue) => {
      onSettingChange(settingKey, nextValue);
    },
    [onSettingChange, settingKey]
  );
  const showAdvanced = !PRIMARY_STRICT_ACTION_VALUES.has(value);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 py-4 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-start gap-3 sm:max-w-[45%]", children: [
      Icon ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }) }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: label }),
        help ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-relaxed text-slate-500", children: help }) : null
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sm:shrink-0", children: [
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
                className: `rounded-lg px-3 py-1.5 text-sm font-medium transition ${selected ? "bg-brand-blue text-white shadow-sm" : "text-slate-600 hover:bg-white/70 hover:text-brand-dark disabled:opacity-50"}`,
                children: option.label
              },
              option.value
            );
          })
        }
      ),
      showAdvanced ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-2 block space-y-1", children: [
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
    ] })
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
  {
    label: "Local rule",
    description: "Remembered decisions on this device.",
    icon: HiMiniQueueList,
    surfaceClass: "bg-violet-50 text-violet-700 border-violet-200"
  },
  {
    label: "Cloud policy",
    description: "Team rules from Guard Cloud.",
    icon: HiMiniCloud,
    surfaceClass: "bg-sky-50 text-sky-700 border-sky-200"
  },
  {
    label: "Cloud exception",
    description: "Signed risk acceptances.",
    icon: HiMiniCloud,
    surfaceClass: "bg-sky-50 text-sky-700 border-sky-200"
  },
  {
    label: "Strict fallback",
    description: "Local strict policy settings.",
    icon: HiMiniShieldCheck,
    surfaceClass: "bg-amber-50 text-amber-800 border-amber-200"
  },
  {
    label: "Ask or block",
    description: "Final prompt or block.",
    icon: HiMiniNoSymbol,
    surfaceClass: "bg-rose-50 text-rose-700 border-rose-200"
  }
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
  const [scenarioId, setScenarioId] = reactExports.useState("first-time");
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
  const scenarioOutcome = reactExports.useMemo(() => {
    if (!settings) {
      return null;
    }
    return resolveStrictScenarioOutcome(scenarioId, settings);
  }, [scenarioId, settings]);
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
  const persistSecurityLevel = reactExports.useCallback(async (enabled) => {
    if (!settings) {
      return;
    }
    const nextLevel = enabled ? "strict" : "balanced";
    const previousSettings = settings;
    setSettings({ ...settings, security_level: nextLevel });
    setSaveError(null);
    try {
      const payload = await updateSettings({ security_level: nextLevel });
      setSettings(payload.settings);
    } catch (error) {
      setSettings(previousSettings);
      setSaveError(error instanceof Error ? error.message : "Unable to update strict mode.");
    }
  }, [settings]);
  const handleStrictToggle = reactExports.useCallback(() => {
    void persistSecurityLevel(!isStrict);
  }, [isStrict, persistSecurityLevel]);
  const handleStrictConfigChange = reactExports.useCallback(
    (key, value) => {
      void persistSetting(key, value);
    },
    [persistSetting]
  );
  const handleResetDefaults = reactExports.useCallback(() => {
    if (!settings) {
      return;
    }
    void (async () => {
      setSaveError(null);
      try {
        const payload = await updateSettings({
          default_action: STRICT_POLICY_DEFAULTS.default_action,
          changed_hash_action: STRICT_POLICY_DEFAULTS.changed_hash_action,
          new_network_domain_action: STRICT_POLICY_DEFAULTS.new_network_domain_action,
          subprocess_action: STRICT_POLICY_DEFAULTS.subprocess_action,
          risk_actions: {
            ...settings.risk_actions,
            destructive_shell: STRICT_POLICY_DEFAULTS.destructive_shell
          }
        });
        setSettings(payload.settings);
      } catch (error) {
        setSaveError(error instanceof Error ? error.message : "Unable to reset strict defaults.");
      }
    })();
  }, [settings]);
  const handleCopyHash = reactExports.useCallback(() => {
    if (!localPolicyHash || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(localPolicyHash);
  }, [localPolicyHash]);
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
  const lastReloadAt = snapshot.runtime_state?.started_at ?? snapshot.generated_at ?? null;
  const lastReloadFormatted = formatPolicyDateTime(lastReloadAt);
  const lastAckAt = snapshot.cloud_policy_last_ack_at?.trim() ?? null;
  const daemonAckLabel = cloudBundleCopy?.tone === "green" ? "Acknowledged" : cloudBundleCopy?.label ?? "Pending";
  const expectedAction = scenarioOutcome?.outcome ?? settings?.new_network_domain_action ?? "review";
  const expectedReasoning = scenarioOutcome?.reasoning ?? "";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px] lg:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-5 w-5", "aria-hidden": "true" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: "Strict mode" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Local enforcement tuning when no other rule matches." })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: isStrict ? "Enabled" : "Disabled" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                role: "switch",
                "aria-checked": isStrict,
                "aria-label": "Toggle strict mode",
                disabled: controlsDisabled,
                onClick: handleStrictToggle,
                className: `relative h-7 w-12 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 ${isStrict ? "bg-brand-blue" : "bg-slate-200"} ${controlsDisabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`,
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "span",
                  {
                    className: `absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow-sm transition-transform ${isStrict ? "translate-x-5" : "translate-x-0"}`
                  }
                )
              }
            )
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2 lg:grid-cols-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Strict mode" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1.5 text-sm font-medium text-brand-dark", children: isStrict ? "Enabled" : "Disabled" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Policy hash" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5 flex items-center gap-1.5 font-mono text-sm text-brand-dark", children: [
              localPolicyHash,
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  onClick: handleCopyHash,
                  className: "rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark",
                  "aria-label": "Copy policy hash",
                  children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { className: "h-4 w-4", "aria-hidden": "true" })
                }
              )
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Daemon ack" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5 flex items-center gap-1.5 text-sm text-brand-dark", children: [
              cloudBundleCopy?.tone === "green" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-emerald-600", "aria-hidden": "true" }) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                daemonAckLabel,
                lastAckAt ? ` · ${formatRelativeTime(lastAckAt)}` : ""
              ] })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Last reload" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1.5 text-sm text-brand-dark", children: lastReloadFormatted ?? (lastReloadAt ? formatRelativeTime(lastReloadAt) : "Unavailable") }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-emerald-700", children: "Auto-reload on" })
          ] })
        ] }),
        !isStrict && onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 border-t border-slate-100 pt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Enable in Settings" }) }) : null,
        onReloadPolicy ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex justify-end border-t border-slate-100 pt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onReloadPolicy, disabled: reloadingPolicy, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: `mr-1.5 h-4 w-4 ${reloadingPolicy ? "animate-spin" : ""}`, "aria-hidden": "true" }),
          "Reload policy"
        ] }) }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local strict policy" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Fallback controls when no remembered rule, Cloud policy, or Cloud exception matches." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: handleResetDefaults,
              disabled: controlsDisabled,
              className: "text-sm font-medium text-brand-blue hover:underline disabled:opacity-50",
              children: "Reset to defaults"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 divide-y divide-slate-100", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            StrictConfigActionSegmented,
            {
              label: "Default action",
              help: "For any action not explicitly allowed.",
              icon: HiMiniBolt,
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
              help: "When a tool or script hash is new.",
              icon: HiMiniCodeBracket,
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
              help: "When a process tries to contact a new domain.",
              icon: HiMiniGlobeAlt,
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
              help: "When a process tries to launch another program.",
              icon: HiMiniCommandLine,
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
              help: "When a process writes to disk.",
              icon: HiMiniDocumentText,
              value: fileWriteAction,
              settingKey: "destructive_shell",
              onSettingChange: handleStrictConfigChange,
              disabled: controlsDisabled
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 flex items-start gap-2 text-xs text-slate-500", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }),
          "These settings apply only when no local or Cloud rules cover the action."
        ] }),
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5", children: EVALUATION_STEPS.map((step, index) => {
          const Icon = step.icon;
          return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-xl border p-3 ${step.surfaceClass}`, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-8 w-8 items-center justify-center rounded-lg bg-white/70", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: step.label }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: step.description })
            ] }),
            index < EVALUATION_STEPS.length - 1 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              HiMiniArrowRight,
              {
                className: "absolute top-1/2 -right-3 hidden h-4 w-4 -translate-y-1/2 text-slate-300 xl:block",
                "aria-hidden": "true"
              }
            ) : null
          ] }, step.label);
        }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-xs text-slate-500", children: [
          "Evaluation order: ",
          STRICT_POLICY_EVALUATION_ORDER.join(" → "),
          ". Team-wide exceptions are managed in Guard Cloud."
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
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-3xl font-semibold tabular-nums text-brand-dark", children: [
          pendingInboxCount,
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1 text-base font-medium text-slate-500", children: "items" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Pending review items may be affected by stricter fallback controls." }),
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
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Expected action" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: resolveExpectedActionTone(expectedAction), children: policyActionLabel(expectedAction) }),
          expectedReasoning ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: expectedReasoning }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: handleRunSimulation, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlay, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Run simulation"
        ] }) }),
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
  onNavigate,
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
        onOpenCloudExceptions: onOpenCloudExceptions ?? (() => void 0),
        onNavigate
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
        reloadingPolicy: reloading,
        onNavigate: props.onNavigate
      }
    ) })
  ] });
}
export {
  PolicyWorkspacePage
};
