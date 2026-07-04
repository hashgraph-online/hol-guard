import { j as jsxRuntimeExports, S as SectionLabel, o as HiMiniXMark, B as Badge, ad as Tag, aB as HiMiniCommandLine, x as HiMiniExclamationTriangle, b6 as scopeLabel, h as harnessDisplayName, A as ActionButton, b7 as guardAwareHref, m as formatRelativeTime$1, b8 as HiMiniDocumentText, d as HiMiniCheckCircle, b9 as HiMiniCloudArrowUp, ba as HiMiniCheck, bb as HiMiniCodeBracket, bc as HiMiniClipboardDocument, bd as HiMiniUsers, aL as HiMiniBeaker, be as HiMiniFolder, R as HiMiniLockClosed, l as HiMiniShieldCheck, bf as HiMiniInformationCircle, aT as HiMiniCloudArrowDown, aS as HiMiniArrowTopRightOnSquare, bg as HiMiniIdentification, bh as policyActionLabel, r as reactExports, bi as createCloudExceptionRequest, bj as HiMiniArrowRight, b as EmptyState, ae as HiMiniMagnifyingGlass, p as HiMiniChevronUp, q as HiMiniChevronDown, z as HiMiniChevronRight, bk as HiMiniPuzzlePiece, bl as HiMiniGlobeAlt, aJ as HiMiniClock, bm as fetchCloudExceptions, bn as fetchCloudExceptionRequests, bo as downloadBlob, bp as PolicyStatField, bq as PaginationControls, br as HiMiniNoSymbol, bs as HiMiniCube, ax as HiMiniArrowPath, t as HiMiniCloud, U as HiMiniAdjustmentsHorizontal, bt as HiMiniArrowDownTray, bu as HiMiniQueueList, y as HiMiniBolt, bv as HiMiniPlay, Z as fetchSettings, $ as updateSettings, b4 as WorkspacePageHeader, b5 as __vitePreload } from "../guard-dashboard.js";
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
              expiryValue ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: formatRelativeTime$1(expiryValue) }) : null
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Last used" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: exception.last_used_at ? formatRelativeTime$1(exception.last_used_at) : "Not yet used" })
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
const DRAFT_STORAGE_KEY = "hol-guard:cloud-exception-request-draft";
const WIZARD_STEPS = ["Source", "Scope", "Guardrails", "Review"];
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
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toISOString();
}
function resolveDefaultWorkingDirectory(snapshot) {
  const install = snapshot.managed_installs?.find((entry) => entry.workspace?.trim());
  return install?.workspace?.trim() ?? "";
}
function resolveResolvedApprovals(snapshot) {
  return (snapshot.items ?? []).filter(
    (item) => Boolean(item.resolved_at?.trim()) || Boolean(item.resolution_action?.trim())
  );
}
function resolveApprovalById(snapshot, requestId) {
  const trimmed = requestId.trim();
  if (!trimmed) {
    return null;
  }
  return (snapshot.items ?? []).find((item) => item.request_id === trimmed) ?? null;
}
function createDefaultDraft(snapshot) {
  const receipts = snapshot.latest_receipts ?? [];
  const approvals = resolveResolvedApprovals(snapshot);
  const firstReceipt = receipts[0];
  const firstApproval = approvals[0];
  const hasApproval = Boolean(firstApproval);
  const sourceMode = hasApproval ? "approval" : receipts.length > 0 ? "receipt" : "receipt";
  return {
    sourceMode,
    sourceReceiptId: hasApproval ? "" : firstReceipt?.receipt_id ?? "",
    sourceReviewItemId: hasApproval ? firstApproval?.request_id ?? "" : "",
    pastedRequestId: "",
    scope: "workspace",
    harness: firstReceipt?.harness ?? firstApproval?.harness ?? "codex",
    artifactId: firstReceipt?.artifact_id ?? firstApproval?.artifact_id ?? "",
    publisher: firstApproval?.publisher?.trim() ?? "",
    workingDirectory: firstApproval?.workspace?.trim() || resolveDefaultWorkingDirectory(snapshot) || firstReceipt?.source_scope?.trim() || "",
    owner: "",
    requestedBy: "",
    reason: "",
    requestedExpiresAt: defaultExpiryIso(),
    linkedTicket: "",
    maxUses: "",
    stepIndex: 0
  };
}
function isDraftRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function loadDraftFromStorage() {
  try {
    const saved = localStorage.getItem(DRAFT_STORAGE_KEY);
    if (!saved) {
      return null;
    }
    const parsed = JSON.parse(saved);
    return isDraftRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
function saveDraftToStorage(draft) {
  try {
    localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
  } catch {
  }
}
function mergeDraft(base, saved) {
  if (!saved) {
    return base;
  }
  return {
    ...base,
    ...saved,
    stepIndex: typeof saved.stepIndex === "number" ? saved.stepIndex : base.stepIndex
  };
}
function hasValidSourceAnchor(draft) {
  if (draft.sourceMode === "receipt") {
    return Boolean(draft.sourceReceiptId.trim());
  }
  if (draft.sourceMode === "approval") {
    return Boolean(draft.sourceReviewItemId.trim());
  }
  if (draft.sourceMode === "paste-id") {
    return Boolean(draft.pastedRequestId.trim());
  }
  return false;
}
function isReasonValid(reason) {
  const trimmed = reason.trim();
  return trimmed.length >= 24 && trimmed.length <= 280;
}
function isExpiryValid(requestedExpiresAt) {
  const date = new Date(requestedExpiresAt);
  if (Number.isNaN(date.getTime())) {
    return false;
  }
  return date.getTime() > Date.now();
}
function canAdvanceFromScope(draft) {
  if (draft.scope === "team-policy") {
    return false;
  }
  if (draft.scope === "artifact" && !draft.artifactId.trim()) {
    return false;
  }
  if (draft.scope === "publisher" && !draft.publisher.trim()) {
    return false;
  }
  if (draft.scope === "workspace" && !draft.workingDirectory.trim()) {
    return false;
  }
  if ((draft.scope === "harness" || draft.scope === "artifact") && !draft.harness.trim()) {
    return false;
  }
  return true;
}
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function isEmailValid(value) {
  return EMAIL_REGEX.test(value.trim());
}
function canAdvanceFromGuardrails(draft) {
  return isEmailValid(draft.owner) && isEmailValid(draft.requestedBy) && isReasonValid(draft.reason) && isExpiryValid(draft.requestedExpiresAt);
}
function canSubmitDraft(draft) {
  return hasValidSourceAnchor(draft) && canAdvanceFromScope(draft) && canAdvanceFromGuardrails(draft);
}
function buildReasonForSubmit(draft) {
  const parts = [draft.reason.trim()];
  if (draft.linkedTicket.trim()) {
    parts.push(`Ticket: ${draft.linkedTicket.trim()}`);
  }
  if (draft.maxUses.trim()) {
    parts.push(`Max uses: ${draft.maxUses.trim()}`);
  }
  return parts.filter(Boolean).join("\n");
}
function buildSubmitPayload(draft) {
  if (draft.scope === "team-policy") {
    throw new Error("Team policy exceptions must be created directly in Guard Cloud.");
  }
  const payload = {
    scope: draft.scope,
    requestedBy: draft.requestedBy.trim(),
    owner: draft.owner.trim(),
    reason: buildReasonForSubmit(draft),
    requestedExpiresAt: draft.requestedExpiresAt,
    sourceReceiptId: null,
    sourceReviewItemId: null
  };
  if (draft.sourceMode === "receipt") {
    payload.sourceReceiptId = draft.sourceReceiptId.trim() || null;
  } else if (draft.sourceMode === "approval") {
    payload.sourceReviewItemId = draft.sourceReviewItemId.trim() || null;
  } else if (draft.sourceMode === "paste-id") {
    payload.sourceReviewItemId = draft.pastedRequestId.trim() || null;
  }
  if (draft.scope === "artifact") {
    payload.harness = draft.harness.trim() || null;
    payload.artifactId = draft.artifactId.trim() || null;
  } else if (draft.scope === "publisher") {
    payload.publisher = draft.publisher.trim() || null;
  } else if (draft.scope === "harness") {
    payload.harness = draft.harness.trim() || null;
  } else if (draft.scope === "workspace") {
    payload.workingDirectory = draft.workingDirectory.trim() || null;
  }
  return payload;
}
function resolveSelectedReceipt(receipts, draft) {
  if (draft.sourceMode === "receipt" && draft.sourceReceiptId.trim()) {
    return receipts.find((entry) => entry.receipt_id === draft.sourceReceiptId) ?? null;
  }
  return null;
}
function resolveSelectedApproval(snapshot, draft) {
  if (draft.sourceMode === "approval" && draft.sourceReviewItemId.trim()) {
    return resolveApprovalById(snapshot, draft.sourceReviewItemId);
  }
  if (draft.sourceMode === "paste-id" && draft.pastedRequestId.trim()) {
    return resolveApprovalById(snapshot, draft.pastedRequestId);
  }
  return null;
}
function resolvePublisherFromSource(snapshot, draft, receipts) {
  const approval = resolveSelectedApproval(snapshot, draft);
  if (approval?.publisher?.trim()) {
    return approval.publisher.trim();
  }
  const receipt = resolveSelectedReceipt(receipts, draft);
  if (receipt?.source_scope?.trim()) {
    return receipt.source_scope.trim();
  }
  return null;
}
function formatRelativeTime(value) {
  if (!value?.trim()) {
    return null;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  const diffMs = Date.now() - date.getTime();
  const diffDays = Math.round(diffMs / (24 * 60 * 60 * 1e3));
  if (diffDays <= 0) {
    return "Today";
  }
  if (diffDays === 1) {
    return "1 day ago";
  }
  return `${diffDays} days ago`;
}
function RequestStepper({ activeStep }) {
  const visibleSteps = WIZARD_STEPS;
  const activeIndex = activeStep === "Submitted" ? visibleSteps.length : visibleSteps.indexOf(activeStep);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "flex flex-wrap gap-2", "aria-label": "Request steps", children: visibleSteps.map((step, index) => {
    const complete = activeStep === "Submitted" || index < activeIndex;
    const active = activeStep !== "Submitted" && index === activeIndex;
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
const RAIL_STEPS = [
  { key: "Source", label: "Source" },
  { key: "Scope", label: "Scope" },
  { key: "Guardrails", label: "Guardrails" },
  { key: "Review", label: "Review" }
];
function resolveRailStatus(step, activeStep, flags) {
  if (activeStep === "Submitted") {
    return "Complete";
  }
  const activeIndex = WIZARD_STEPS.indexOf(activeStep);
  const stepIndex = WIZARD_STEPS.indexOf(step);
  if (stepIndex < activeIndex) {
    return "Complete";
  }
  if (stepIndex > activeIndex) {
    if (step === "Scope" && !flags.sourceComplete) {
      return "Not chosen";
    }
    if (step === "Guardrails" && !flags.scopeComplete) {
      return "Not set";
    }
    if (step === "Review") {
      return "Pending";
    }
    return step === "Scope" ? "Not chosen" : "Not set";
  }
  if (step === "Source") {
    return flags.sourceComplete ? "Selected" : "Not chosen";
  }
  if (step === "Scope") {
    return flags.scopeComplete ? "Selected" : "Not chosen";
  }
  if (step === "Guardrails") {
    return flags.guardrailsComplete ? "Set" : "Not set";
  }
  return "Pending";
}
function RequestSummaryRail({
  activeStep,
  sourceComplete,
  scopeComplete,
  guardrailsComplete
}) {
  const flags = { sourceComplete, scopeComplete, guardrailsComplete };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "rounded-xl border border-slate-200 bg-slate-50/60 p-4", "aria-label": "Request progress", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "space-y-3", children: RAIL_STEPS.map((step, index) => {
      const status = resolveRailStatus(step.key, activeStep, flags);
      const active = activeStep === step.key;
      const complete = activeStep === "Submitted" || WIZARD_STEPS.indexOf(activeStep) > index || step.key === "Source" && sourceComplete && activeStep !== "Source";
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "li",
        {
          className: `flex items-start justify-between gap-2 rounded-lg px-2 py-1.5 text-sm ${active ? "bg-brand-blue/8" : ""}`,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "span",
                {
                  className: `inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${complete ? "bg-emerald-600 text-white" : active ? "bg-brand-blue text-white" : "bg-slate-200 text-slate-600"}`,
                  children: complete ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { className: "h-3 w-3", "aria-hidden": "true" }) : index + 1
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-dark", children: step.label })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-500", children: status })
          ]
        },
        step.key
      );
    }) }),
    activeStep !== "Submitted" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 border-t border-slate-200 pt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "What's next?" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-relaxed text-slate-600", children: activeStep === "Source" ? "Choose scope, add guardrails, then submit to Guard Cloud." : activeStep === "Scope" ? "Set guardrails like reason and expiry, then send the request to Guard Cloud." : activeStep === "Guardrails" ? "Review the exact request before submitting to Guard Cloud." : "Submit when the summary looks correct." })
    ] }) : null
  ] });
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
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", role: "radiogroup", "aria-label": "Exception scope", children: options.map((option) => {
    const blast = resolveRequestScopeBlastRadius(option.value);
    const selected = value === option.value;
    const Icon = SCOPE_ICONS[option.value];
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        role: "radio",
        "aria-checked": selected,
        disabled: option.disabled,
        onClick: () => onChange(option.value),
        className: `w-full rounded-xl border p-4 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${selected ? `${SCOPE_CARD_TONES[blast.tone]} ring-2 ring-brand-blue/30` : `${SCOPE_CARD_TONES[blast.tone]} opacity-95`}`,
        children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "span",
            {
              className: `mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${selected ? "border-brand-blue bg-brand-blue" : "border-slate-300 bg-white"}`,
              "aria-hidden": "true",
              children: selected ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-white" }) : null
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4 text-slate-500", "aria-hidden": "true" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: option.label })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: option.description }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-[11px] font-medium uppercase tracking-wide text-slate-500", children: [
              "Blast radius · ",
              blast.label
            ] }),
            option.disabled && option.disabledReason ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 flex items-center gap-1 text-[11px] text-slate-500", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "h-3 w-3", "aria-hidden": "true" }),
              option.disabledReason
            ] }) : null
          ] })
        ] })
      },
      option.value
    );
  }) });
}
const SAFETY_ITEMS = [
  {
    icon: HiMiniShieldCheck,
    title: "Cloud approval required",
    detail: "Your request will be reviewed and approved in Guard Cloud."
  },
  {
    icon: HiMiniLockClosed,
    title: "MFA may be required",
    detail: "Broad scopes may require step-up authentication."
  },
  {
    icon: HiMiniDocumentText,
    title: "Signed bundle enforcement",
    detail: "This exception is enforced only after it appears in a signed policy bundle."
  },
  {
    icon: HiMiniCheck,
    title: "Local daemon ack required",
    detail: "Your machine will acknowledge the updated bundle before enforcement."
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
  expiresLabel,
  compact = false
}) {
  const blast = resolveRequestScopeBlastRadius(scope);
  const scopeTarget = resolveSafetyScopeTarget(scope, artifactId, publisher, harness, workingDirectory);
  const actionLabel = resolveResultActionLabel(scope);
  const showHarness = (scope === "artifact" || scope === "harness") && harness.trim();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-slate-50/80 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Safety & enforcement" }),
    !compact ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Blast radius" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-semibold text-brand-dark", children: blast.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: scopeTarget })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: `space-y-3 ${compact ? "mt-3" : "mt-4"}`, children: SAFETY_ITEMS.map((item) => {
      const Icon = item.icon;
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: item.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-600", children: item.detail })
        ] })
      ] }, item.title);
    }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-lg border border-slate-200 bg-white p-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Preview" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs leading-relaxed text-brand-dark", children: [
        "If approved, Guard will allow ",
        actionLabel,
        showHarness ? ` for ${harnessDisplayName(harness)}` : "",
        " until ",
        expiresLabel,
        "."
      ] })
    ] }),
    !compact && reason.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-xs leading-relaxed text-slate-500", children: [
      "Reason: ",
      reason.trim().slice(0, 120),
      reason.trim().length > 120 ? "…" : ""
    ] }) : null
  ] });
}
function SourceReceiptSummary({ receipt, compact = false }) {
  const evidenceHref = `/evidence?search=${encodeURIComponent(receipt.receipt_id)}`;
  const artifactLabel = receipt.artifact_name ?? receipt.artifact_id;
  const handleCopyArtifact = () => {
    if (!receipt.artifact_id || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(receipt.artifact_id);
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-xl border border-slate-200 bg-slate-50/80 ${compact ? "p-3" : "p-4"}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: compact ? "Source" : "Selected source preview" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-200/80 text-slate-600", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCodeBracket, { className: "h-4 w-4", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: artifactLabel }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
          harnessDisplayName(receipt.harness),
          receipt.timestamp ? ` · ${receipt.timestamp}` : ""
        ] })
      ] })
    ] }),
    !compact ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 space-y-3", children: [
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
            className: "mt-1 inline-flex items-center gap-1 break-all text-xs font-medium text-brand-blue hover:underline",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-3.5 w-3.5 shrink-0", "aria-hidden": "true" }),
              receipt.receipt_id
            ]
          }
        )
      ] })
    ] }) : null
  ] });
}
function ResultPreview({
  scope,
  harness,
  expiresLabel,
  actionLabel,
  scopeLabelText
}) {
  const showHarness = (scope === "artifact" || scope === "harness") && harness.trim();
  const resolvedAction = actionLabel ?? resolveResultActionLabel(scope);
  const resolvedScope = scopeLabelText ?? scopeLabel(scope === "team-policy" ? "global" : scope, "policy");
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm leading-relaxed text-brand-dark", children: [
      "If approved in Guard Cloud, Guard will allow ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: resolvedAction }),
      showHarness ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        " ",
        "for ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: harnessDisplayName(harness) })
      ] }) : null,
      " ",
      "in ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: resolvedScope }),
      " until ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: expiresLabel }),
      "."
    ] })
  ] }) });
}
function RequestModalShell({
  title,
  subtitle,
  stepper,
  children,
  footer,
  summaryRail,
  onCancel,
  preventClose = false
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-900/45 p-3 sm:items-center sm:p-4",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "cloud-exception-request-title",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "my-auto w-full max-w-5xl rounded-2xl border border-slate-200 bg-white shadow-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3 border-b border-slate-100 px-4 py-4 sm:px-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cloud-exception-request-title", className: "text-lg font-semibold text-brand-dark", children: title }),
            subtitle ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: subtitle }) : null,
            stepper
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: onCancel,
              disabled: preventClose,
              className: "rounded-lg px-2 py-1 text-sm font-medium text-slate-500 hover:bg-slate-100 hover:text-brand-dark disabled:cursor-not-allowed disabled:opacity-50",
              "aria-label": "Close",
              children: "Close"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-4 sm:px-5 sm:py-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: summaryRail ? "grid gap-4 lg:grid-cols-[minmax(0,1fr)_240px] lg:items-start" : "", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "min-w-0", children }),
          summaryRail ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "min-w-0 lg:sticky lg:top-0", children: summaryRail }) : null
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-4 py-4 sm:px-5", children: footer })
      ] })
    }
  );
}
const SOURCE_MODE_OPTIONS = [
  {
    mode: "approval",
    label: "Recent approval",
    description: "Use a recent Review approval already recorded on this device.",
    icon: HiMiniDocumentText,
    recommended: true
  },
  {
    mode: "receipt",
    label: "Evidence receipt",
    description: "Use an evidence record such as policy-eval, token-scan, or runtime event.",
    icon: HiMiniShieldCheck
  },
  {
    mode: "paste-id",
    label: "Paste request id",
    description: "Paste a request or action id recorded by Guard on this machine.",
    icon: HiMiniIdentification
  }
];
function CloudExceptionSourceStep({
  snapshot,
  draft,
  receipts,
  onDraftChange
}) {
  const approvals = resolveResolvedApprovals(snapshot);
  const hasApprovals = approvals.length > 0;
  const hasReceipts = receipts.length > 0;
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const handleModeChange = (mode) => {
    if (mode === "approval" && !hasApprovals) {
      return;
    }
    if (mode === "receipt" && !hasReceipts) {
      return;
    }
    const patch = { sourceMode: mode };
    if (mode === "approval" && approvals[0]) {
      patch.sourceReviewItemId = approvals[0].request_id;
      patch.sourceReceiptId = "";
      patch.pastedRequestId = "";
      patch.harness = approvals[0].harness;
      patch.artifactId = approvals[0].artifact_id;
      if (approvals[0].workspace?.trim()) {
        patch.workingDirectory = approvals[0].workspace.trim();
      }
      if (approvals[0].publisher?.trim()) {
        patch.publisher = approvals[0].publisher.trim();
      }
    } else if (mode === "receipt" && receipts[0]) {
      patch.sourceReceiptId = receipts[0].receipt_id;
      patch.sourceReviewItemId = "";
      patch.pastedRequestId = "";
      patch.harness = receipts[0].harness;
      patch.artifactId = receipts[0].artifact_id;
    } else if (mode === "paste-id") {
      patch.pastedRequestId = "";
      patch.sourceReceiptId = "";
      patch.sourceReviewItemId = "";
    }
    onDraftChange(patch);
  };
  const handleReceiptSelect = (event) => {
    const receiptId = event.target.value;
    const receipt = receipts.find((entry) => entry.receipt_id === receiptId);
    onDraftChange({
      sourceReceiptId: receiptId,
      harness: receipt?.harness ?? draft.harness,
      artifactId: receipt?.artifact_id ?? draft.artifactId
    });
  };
  const handleApprovalSelect = (event) => {
    const requestId = event.target.value;
    const approval = approvals.find((entry) => entry.request_id === requestId);
    onDraftChange({
      sourceReviewItemId: requestId,
      harness: approval?.harness ?? draft.harness,
      artifactId: approval?.artifact_id ?? draft.artifactId,
      workingDirectory: approval?.workspace?.trim() || draft.workingDirectory,
      publisher: approval?.publisher?.trim() || draft.publisher
    });
  };
  const handlePasteIdChange = (event) => {
    const pastedRequestId = event.target.value;
    const approval = snapshot.items?.find((item) => item.request_id === pastedRequestId.trim());
    onDraftChange({
      pastedRequestId,
      sourceReviewItemId: pastedRequestId.trim(),
      harness: approval?.harness ?? draft.harness,
      artifactId: approval?.artifact_id ?? draft.artifactId,
      workingDirectory: approval?.workspace?.trim() || draft.workingDirectory,
      publisher: approval?.publisher?.trim() || draft.publisher
    });
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What should this exception be based on?" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Choose the record that best represents the action or request you want to allow with a policy override." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2 sm:grid-cols-3", role: "radiogroup", "aria-label": "Source type", children: SOURCE_MODE_OPTIONS.map((option) => {
      const disabled = option.mode === "approval" && !hasApprovals || option.mode === "receipt" && !hasReceipts;
      const selected = draft.sourceMode === option.mode;
      const Icon = option.icon;
      return /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          role: "radio",
          "aria-checked": selected,
          disabled,
          onClick: () => handleModeChange(option.mode),
          className: `rounded-xl border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${selected ? "border-brand-blue bg-brand-blue/5 ring-2 ring-brand-blue/25" : "border-slate-200 bg-white hover:border-slate-300"}`,
          children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "span",
              {
                className: `mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${selected ? "border-brand-blue bg-brand-blue" : "border-slate-300 bg-white"}`,
                "aria-hidden": "true",
                children: selected ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-white" }) : null
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4 text-slate-500", "aria-hidden": "true" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: option.label }),
                option.recommended && hasApprovals ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-brand-blue/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-brand-blue", children: "Recommended" }) : null
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: option.description }),
              disabled ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-[11px] text-slate-500", children: option.mode === "approval" ? "No resolved Review approvals on this device yet." : "No evidence receipts on this device yet." }) : null
            ] })
          ] })
        },
        option.mode
      );
    }) }),
    draft.sourceMode === "receipt" && hasReceipts ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Choose evidence receipt" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
          value: draft.sourceReceiptId,
          onChange: handleReceiptSelect,
          required: true,
          children: receipts.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: receipt.receipt_id, children: [
            harnessDisplayName(receipt.harness),
            " · ",
            receipt.artifact_name ?? receipt.artifact_id
          ] }, receipt.receipt_id))
        }
      )
    ] }) : null,
    draft.sourceMode === "approval" && hasApprovals ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Choose approval record" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
          value: draft.sourceReviewItemId,
          onChange: handleApprovalSelect,
          required: true,
          children: approvals.map((approval) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: approval.request_id, children: [
            harnessDisplayName(approval.harness),
            " · ",
            approval.artifact_name || approval.artifact_id
          ] }, approval.request_id))
        }
      )
    ] }) : null,
    draft.sourceMode === "paste-id" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Request or action id" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
          value: draft.pastedRequestId,
          onChange: handlePasteIdChange,
          placeholder: "Paste a Guard request id from this device",
          required: true
        }
      ),
      draft.pastedRequestId.trim() && !selectedApproval ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-700", role: "alert", children: "No matching request found on this device. Guard only accepts ids recorded locally." }) : null
    ] }) : null,
    selectedReceipt ? /* @__PURE__ */ jsxRuntimeExports.jsx(SourceReceiptSummary, { receipt: selectedReceipt }) : null,
    !selectedReceipt && selectedApproval ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-slate-50/80 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-wide text-slate-500", children: "Selected source preview" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-200/80 text-slate-600", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCodeBracket, { className: "h-4 w-4", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: selectedApproval.artifact_name || selectedApproval.artifact_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
            harnessDisplayName(selectedApproval.harness),
            selectedApproval.resolved_at ? ` · ${formatRelativeTime(selectedApproval.resolved_at) ?? selectedApproval.resolved_at}` : ""
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 break-all font-mono text-xs text-slate-500", children: selectedApproval.request_id })
        ] })
      ] })
    ] }) : null
  ] });
}
function CloudExceptionScopeStep({
  snapshot,
  draft,
  receipts,
  harnessOptions,
  publisherAvailable,
  onDraftChange
}) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const sourceLabel = selectedApproval?.artifact_name || selectedApproval?.artifact_id || selectedReceipt?.artifact_name || selectedReceipt?.artifact_id;
  const scopeOptions = [
    {
      value: "artifact",
      label: "Exact action",
      description: "Only this exact command and context."
    },
    {
      value: "publisher",
      label: "This cwd",
      description: "Any matching action in this working directory.",
      disabled: !publisherAvailable,
      disabledReason: publisherAvailable ? void 0 : "Publisher not available from the selected source."
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
      disabled: true,
      disabledReason: "Create team policy exceptions in Guard Cloud."
    }
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    (selectedReceipt || selectedApproval) && sourceLabel ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-slate-50/70 p-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Source (from review)" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCodeBracket, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-500", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: sourceLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-600", children: [
            harnessDisplayName(selectedApproval?.harness ?? selectedReceipt?.harness ?? draft.harness),
            selectedReceipt ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
              " · ",
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "a",
                {
                  href: guardAwareHref(`/evidence?search=${encodeURIComponent(selectedReceipt.receipt_id)}`),
                  className: "text-brand-blue hover:underline",
                  children: selectedReceipt.receipt_id
                }
              )
            ] }) : selectedApproval ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
              " · ",
              selectedApproval.request_id
            ] }) : null
          ] })
        ] })
      ] })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Where should this cloud exception apply?" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Choose the narrowest scope that solves the problem." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ScopeCardGrid,
      {
        options: scopeOptions,
        value: draft.scope,
        onChange: (scope) => onDraftChange({ scope })
      }
    ),
    draft.scope === "artifact" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Artifact fingerprint" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
          value: draft.artifactId,
          onChange: (event) => onDraftChange({ artifactId: event.target.value }),
          required: true
        }
      )
    ] }) : null,
    draft.scope === "publisher" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Publisher / cwd" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
          value: draft.publisher,
          onChange: (event) => onDraftChange({ publisher: event.target.value }),
          required: true
        }
      )
    ] }) : null,
    (draft.scope === "harness" || draft.scope === "artifact") && /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "App" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
          value: draft.harness,
          onChange: (event) => onDraftChange({ harness: event.target.value }),
          required: true,
          children: harnessOptions.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option, children: harnessDisplayName(option) }, option))
        }
      )
    ] }),
    draft.scope === "workspace" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Project folder" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
          value: draft.workingDirectory,
          onChange: (event) => onDraftChange({ workingDirectory: event.target.value }),
          required: true
        }
      )
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80", children: "Broader scopes may require additional verification and approvals in Guard Cloud." })
  ] });
}
function CloudExceptionGuardrailsStep({
  draft,
  snapshot,
  receipts,
  expiryLabel,
  onDraftChange
}) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const sourceLabel = selectedApproval?.artifact_name || selectedApproval?.artifact_id || selectedReceipt?.artifact_name || selectedReceipt?.artifact_id;
  const blast = resolveRequestScopeBlastRadius(draft.scope);
  const reasonTooShort = draft.reason.trim().length > 0 && !isReasonValid(draft.reason);
  const expiryInvalid = draft.requestedExpiresAt.trim().length > 0 && !isExpiryValid(draft.requestedExpiresAt);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,280px)] lg:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 rounded-xl border border-slate-200 bg-slate-50/60 p-3 sm:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Source" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: sourceLabel || "Not set" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Scope" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: draft.scope === "workspace" ? "This project" : draft.scope === "publisher" ? "This cwd" : draft.scope === "artifact" ? "Exact action" : draft.scope === "harness" ? "This harness" : "Team policy" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Blast radius" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: blast.label })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Risk owner (required)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
            type: "email",
            value: draft.owner,
            onChange: (event) => onDraftChange({ owner: event.target.value }),
            placeholder: "owner@example.com",
            required: true,
            "aria-invalid": !draft.owner.trim()
          }
        ),
        !draft.owner.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-red-600", children: "Choose an owner." }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Requested by (required)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
            type: "email",
            value: draft.requestedBy,
            onChange: (event) => onDraftChange({ requestedBy: event.target.value }),
            placeholder: "requester@example.com",
            required: true,
            "aria-invalid": !draft.requestedBy.trim()
          }
        ),
        !draft.requestedBy.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: "Enter the email Guard Cloud should associate with this request." }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Reason (required)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "textarea",
          {
            className: `min-h-24 w-full rounded-xl border bg-white px-3 py-2 text-sm ${reasonTooShort ? "border-red-300" : "border-slate-200"}`,
            value: draft.reason,
            onChange: (event) => onDraftChange({ reason: event.target.value }),
            placeholder: "Explain why this exception is needed.",
            maxLength: 280,
            required: true,
            "aria-invalid": reasonTooShort || !draft.reason.trim()
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
          draft.reason.trim().length,
          "/280 (minimum 24)"
        ] }),
        !draft.reason.trim() ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-red-600", children: "Reason is required." }) : reasonTooShort ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-red-600", children: "Reason must be at least 24 characters." }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1 md:max-w-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Requested expiry (required)" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            className: `w-full rounded-xl border bg-white px-3 py-2 text-sm ${expiryInvalid ? "border-red-300" : "border-slate-200"}`,
            type: "datetime-local",
            value: toDatetimeLocalValue(draft.requestedExpiresAt),
            onChange: (event) => onDraftChange({ requestedExpiresAt: fromDatetimeLocalValue(event.target.value) }),
            required: true,
            "aria-invalid": expiryInvalid
          }
        ),
        expiryInvalid ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-red-600", children: "Expiry must be in the future." }) : null
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
              value: draft.maxUses,
              onChange: (event) => onDraftChange({ maxUses: event.target.value }),
              placeholder: "e.g. 50"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Appended to reason for reviewers. Not enforced locally." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Linked ticket (optional)" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm",
              value: draft.linkedTicket,
              onChange: (event) => onDraftChange({ linkedTicket: event.target.value }),
              placeholder: "ENG-123 or URL"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Appended to reason for reviewers." })
        ] })
      ] }),
      (draft.scope === "harness" || draft.scope === "workspace") && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80", children: "Broad scopes may require step-up authentication during Cloud review." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SafetyPreview,
      {
        scope: draft.scope,
        harness: draft.harness,
        artifactId: draft.artifactId,
        publisher: draft.publisher,
        workingDirectory: draft.workingDirectory,
        reason: draft.reason,
        expiresLabel: expiryLabel,
        compact: true
      }
    )
  ] });
}
function CloudExceptionReviewStep({
  draft,
  snapshot,
  receipts,
  expiryLabel,
  actionLabel,
  error,
  onEditStep
}) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const blast = resolveRequestScopeBlastRadius(draft.scope);
  const sourceDetail = selectedReceipt ? `Evidence receipt · ${selectedReceipt.receipt_id}` : selectedApproval ? `Approval record · ${selectedApproval.request_id}` : draft.pastedRequestId.trim();
  const rows = [
    {
      label: "Source",
      value: selectedApproval?.artifact_name || selectedApproval?.artifact_id || selectedReceipt?.artifact_name || selectedReceipt?.artifact_id || "—",
      detail: sourceDetail,
      stepIndex: 0
    },
    {
      label: "Scope",
      value: draft.scope === "workspace" ? "This project" : draft.scope === "publisher" ? "This cwd" : draft.scope === "artifact" ? "Exact action" : draft.scope === "harness" ? "This harness" : "Team policy",
      detail: draft.workingDirectory || draft.publisher || draft.artifactId || draft.harness,
      stepIndex: 1
    },
    { label: "Owner", value: draft.owner.trim() || "—", stepIndex: 2 },
    { label: "Requested by", value: draft.requestedBy.trim() || "—", stepIndex: 2 },
    { label: "Reason", value: draft.reason.trim() || "—", stepIndex: 2 },
    { label: "Expiry", value: expiryLabel, stepIndex: 2 }
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ResultPreview,
      {
        scope: draft.scope,
        harness: draft.harness,
        expiresLabel: expiryLabel,
        actionLabel
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white", children: [
      rows.map((row) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs uppercase tracking-wide text-slate-500", children: row.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm font-medium text-brand-dark", children: row.value }),
          row.detail ? /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 break-all text-xs text-slate-500", children: row.detail }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => onEditStep(row.stepIndex),
            className: "shrink-0 text-xs font-medium text-brand-blue hover:underline",
            children: "Edit"
          }
        )
      ] }, row.label)),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs uppercase tracking-wide text-slate-500", children: "Blast radius" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm font-medium text-brand-dark", children: blast.label })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "rounded-xl border border-slate-200 bg-slate-50/50 p-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-medium text-brand-dark", children: "Technical details" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 space-y-2 text-xs text-slate-600", children: [
        draft.artifactId ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Artifact ID" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "break-all font-mono", children: draft.artifactId })
        ] }) : null,
        selectedReceipt ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Receipt ID" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "break-all font-mono", children: selectedReceipt.receipt_id })
        ] }) : null,
        selectedApproval ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Request ID" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "break-all font-mono", children: selectedApproval.request_id })
        ] }) : null
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-amber-200 bg-amber-50/70 p-3 text-sm text-amber-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium", children: "This does not change local remembered approvals." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed", children: "Review still handles normal reusable decisions. This request is only for a Cloud exception override." })
    ] }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-red-600", role: "alert", children: error }) : null
  ] });
}
function CloudExceptionSubmittedStep({
  draft,
  snapshot,
  receipts,
  submitted,
  expiryLabel,
  cloudControlsUrl,
  onViewPending,
  onDone
}) {
  const selectedReceipt = resolveSelectedReceipt(receipts, draft);
  const selectedApproval = resolveSelectedApproval(snapshot, draft);
  const blast = resolveRequestScopeBlastRadius(draft.scope);
  const submittedLabel = new Date(submitted.submittedAt).toLocaleString();
  const handleCopyRequestId = () => {
    if (!submitted.requestId || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(submitted.requestId);
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-5 text-center sm:text-left", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-center sm:items-start", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 text-emerald-700", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-7 w-7", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-4 text-xl font-semibold text-brand-dark", children: "Exception request sent" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Guard Cloud will review it before local enforcement changes." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 rounded-xl border border-slate-200 bg-slate-50/60 p-4 sm:grid-cols-2 lg:grid-cols-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Request id" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex items-center gap-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-sm text-brand-dark", children: submitted.requestId }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: handleCopyRequestId,
              className: "rounded-md p-1 text-slate-400 hover:bg-slate-100",
              "aria-label": "Copy request id",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Status" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800", children: "Pending Guard Cloud review" }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Submitted" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-brand-dark", children: submittedLabel })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Request type" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-brand-dark", children: "Cloud exception" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 rounded-xl border border-slate-200 p-4 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Source" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: selectedApproval?.artifact_name || selectedApproval?.artifact_id || selectedReceipt?.artifact_name || selectedReceipt?.artifact_id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Scope" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: scopeLabel(draft.scope === "team-policy" ? "global" : draft.scope, "policy") }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: draft.workingDirectory || draft.publisher })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Blast radius" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: blast.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Requested expiry" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: expiryLabel })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 p-4 text-left", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniUsers, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: "Cloud reviewer decides" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-600", children: "A teammate reviews and approves or rejects your request." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 p-4 text-left", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowDown, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: "Signed bundle syncs to this machine" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-600", children: "If approved, Guard Cloud adds the exception to the signed policy bundle." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 p-4 text-left", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-5 w-5 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: "Local daemon acknowledges before enforcement" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-600", children: "Guard applies the exception after local daemon ack." })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2 text-xs text-brand-dark/80", children: "Until approved, Guard keeps using existing local remembered rules and strict config." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-center gap-2 sm:justify-start", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: onViewPending, children: "View pending request" }),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", href: cloudControlsUrl, target: "_blank", rel: "noreferrer", children: [
        "Open Guard Cloud",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "ml-1 inline h-3.5 w-3.5", "aria-hidden": "true" })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", type: "button", onClick: onDone, children: "Done" })
    ] })
  ] });
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
const STEP_SUBTITLES = {
  Source: "Start from a real approval or evidence record.",
  Scope: "Choose the narrowest scope that solves the problem.",
  Guardrails: "Set owner, reason, and expiry before Cloud reviews it.",
  Review: "Review before sending to Guard Cloud.",
  Submitted: "Guard Cloud will review it before local enforcement changes."
};
function PolicyCloudExceptionRequestPanel({
  snapshot,
  onSubmitted,
  onCancel
}) {
  const openerRef = reactExports.useRef(
    typeof document !== "undefined" ? document.activeElement : null
  );
  const receiptOptions = snapshot.latest_receipts ?? [];
  const harnessOptions = reactExports.useMemo(() => {
    const fromReceipts = receiptOptions.map((receipt) => receipt.harness).filter(Boolean);
    const fromInstalls = (snapshot.managed_installs ?? []).map((entry) => entry.harness).filter(Boolean);
    return [.../* @__PURE__ */ new Set([...fromReceipts, ...fromInstalls, "codex", "cursor"])].sort();
  }, [receiptOptions, snapshot.managed_installs]);
  const [draft, setDraft] = reactExports.useState(
    () => mergeDraft(createDefaultDraft(snapshot), loadDraftFromStorage())
  );
  const [submitting, setSubmitting] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [submitted, setSubmitted] = reactExports.useState(null);
  const activeStep = submitted ? "Submitted" : WIZARD_STEPS[draft.stepIndex] ?? "Source";
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const publisherFromSource = reactExports.useMemo(
    () => resolvePublisherFromSource(snapshot, draft, receiptOptions),
    [draft, receiptOptions, snapshot]
  );
  const publisherAvailable = Boolean(publisherFromSource || draft.publisher.trim());
  reactExports.useEffect(() => {
    if (publisherFromSource && draft.scope === "publisher" && !draft.publisher.trim()) {
      setDraft((current) => ({ ...current, publisher: publisherFromSource }));
    }
  }, [draft.scope, draft.publisher, publisherFromSource]);
  const expiryLabel = reactExports.useMemo(() => {
    const date = new Date(draft.requestedExpiresAt);
    return Number.isNaN(date.getTime()) ? "Not set" : date.toLocaleString();
  }, [draft.requestedExpiresAt]);
  const actionLabel = reactExports.useMemo(() => {
    const approval = snapshot.items?.find(
      (item) => item.request_id === draft.sourceReviewItemId || item.request_id === draft.pastedRequestId
    );
    const receipt = receiptOptions.find((entry) => entry.receipt_id === draft.sourceReceiptId);
    return approval?.artifact_name || approval?.artifact_id || receipt?.artifact_name || receipt?.artifact_id || "this action";
  }, [draft.pastedRequestId, draft.sourceReceiptId, draft.sourceReviewItemId, receiptOptions, snapshot.items]);
  const patchDraft = reactExports.useCallback((patch) => {
    setDraft((current) => ({ ...current, ...patch }));
  }, []);
  const handleSaveDraft = reactExports.useCallback(() => {
    saveDraftToStorage(draft);
  }, [draft]);
  const handleBack = reactExports.useCallback(() => {
    setDraft((current) => ({ ...current, stepIndex: Math.max(0, current.stepIndex - 1) }));
    setError(null);
  }, []);
  const handleNext = reactExports.useCallback(() => {
    setDraft((current) => ({
      ...current,
      stepIndex: Math.min(WIZARD_STEPS.length - 1, current.stepIndex + 1)
    }));
    setError(null);
  }, []);
  const handleEditStep = reactExports.useCallback((stepIndex) => {
    setDraft((current) => ({ ...current, stepIndex }));
    setError(null);
  }, []);
  const handleSubmit = reactExports.useCallback(
    async (event) => {
      event.preventDefault();
      if (!canSubmitDraft(draft)) {
        return;
      }
      setSubmitting(true);
      setError(null);
      try {
        const payload = buildSubmitPayload(draft);
        const response = await createCloudExceptionRequest(payload);
        const created = response.items.find((item) => item.status === "pending") ?? response.items[0];
        if (!created?.requestId) {
          throw new Error("Guard Cloud did not return a request id.");
        }
        setSubmitted({
          requestId: created.requestId,
          submittedAt: created.requestedAt || (/* @__PURE__ */ new Date()).toISOString(),
          status: "pending"
        });
      } catch (submitError) {
        const message = submitError instanceof Error && submitError.message.trim() ? submitError.message : "Unable to submit the Cloud exception request.";
        setError(message);
      } finally {
        setSubmitting(false);
      }
    },
    [draft]
  );
  const handleDone = reactExports.useCallback(() => {
    onSubmitted(submitted?.requestId);
  }, [onSubmitted, submitted?.requestId]);
  const handleViewPending = reactExports.useCallback(() => {
    onSubmitted(submitted?.requestId);
  }, [onSubmitted, submitted?.requestId]);
  const handleCancel = reactExports.useCallback(() => {
    onCancel();
  }, [onCancel]);
  reactExports.useEffect(() => {
    return () => {
      openerRef.current?.focus?.();
    };
  }, []);
  reactExports.useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && !submitting) {
        event.preventDefault();
        handleCancel();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleCancel, submitting]);
  const sourceComplete = hasValidSourceAnchor(draft);
  const scopeComplete = canAdvanceFromScope(draft);
  const guardrailsComplete = canAdvanceFromGuardrails(draft);
  const showSaveDraft = activeStep !== "Source" && activeStep !== "Submitted" && (sourceComplete || scopeComplete || guardrailsComplete);
  const canContinue = activeStep === "Source" && sourceComplete || activeStep === "Scope" && scopeComplete || activeStep === "Guardrails" && guardrailsComplete;
  if (receiptOptions.length === 0 && (snapshot.items ?? []).length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs(
      RequestModalShell,
      {
        title: "Request cloud exception",
        subtitle: "Start from a real approval or evidence record.",
        stepper: /* @__PURE__ */ jsxRuntimeExports.jsx(RequestStepper, { activeStep: "Source" }),
        onCancel: handleCancel,
        footer: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: handleCancel, children: "Close" }),
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "No source records yet" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Guard needs at least one Review approval or evidence receipt on this device to anchor a Cloud exception request. Run a protected action first, then return here from Evidence or Inbox." })
        ]
      }
    );
  }
  if (submitted) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      RequestModalShell,
      {
        title: "Request cloud exception",
        subtitle: STEP_SUBTITLES.Submitted,
        onCancel: handleCancel,
        preventClose: submitting,
        footer: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: handleCancel, children: "Close" }),
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          CloudExceptionSubmittedStep,
          {
            draft,
            snapshot,
            receipts: receiptOptions,
            submitted,
            expiryLabel,
            cloudControlsUrl,
            onViewPending: handleViewPending,
            onDone: handleDone
          }
        )
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    RequestModalShell,
    {
      title: "Request cloud exception",
      subtitle: STEP_SUBTITLES[activeStep],
      stepper: /* @__PURE__ */ jsxRuntimeExports.jsx(RequestStepper, { activeStep }),
      summaryRail: /* @__PURE__ */ jsxRuntimeExports.jsx(
        RequestSummaryRail,
        {
          activeStep,
          sourceComplete,
          scopeComplete,
          guardrailsComplete
        }
      ),
      onCancel: handleCancel,
      preventClose: submitting,
      footer: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] px-3 py-2 text-xs text-brand-dark/80", children: "Exceptions are approved in Guard Cloud, then enforced locally as signed policy bundle entries." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: handleCancel, disabled: submitting, children: "Cancel" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            showSaveDraft ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: handleSaveDraft, disabled: submitting, children: "Save draft locally" }) : null,
            draft.stepIndex > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: handleBack, disabled: submitting, children: "Back" }) : null,
            activeStep === "Review" ? /* @__PURE__ */ jsxRuntimeExports.jsx("form", { onSubmit: handleSubmit, children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", type: "submit", disabled: submitting || !canSubmitDraft(draft), children: submitting ? "Submitting…" : "Submit request" }) }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(
              ActionButton,
              {
                variant: "primary",
                type: "button",
                onClick: handleNext,
                disabled: submitting || !canContinue,
                children: [
                  "Continue",
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "ml-1 inline h-4 w-4", "aria-hidden": "true" })
                ]
              }
            )
          ] })
        ] }),
        activeStep === "Guardrails" && !canContinue ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-center text-xs text-slate-500 sm:text-right", children: "Complete required fields to continue." }) : null
      ] }),
      children: [
        activeStep === "Source" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          CloudExceptionSourceStep,
          {
            snapshot,
            draft,
            receipts: receiptOptions,
            onDraftChange: patchDraft
          }
        ) : null,
        activeStep === "Scope" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          CloudExceptionScopeStep,
          {
            snapshot,
            draft,
            receipts: receiptOptions,
            harnessOptions,
            publisherAvailable,
            onDraftChange: patchDraft
          }
        ) : null,
        activeStep === "Guardrails" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          CloudExceptionGuardrailsStep,
          {
            draft,
            snapshot,
            receipts: receiptOptions,
            expiryLabel,
            onDraftChange: patchDraft
          }
        ) : null,
        activeStep === "Review" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          CloudExceptionReviewStep,
          {
            draft,
            snapshot,
            receipts: receiptOptions,
            expiryLabel,
            actionLabel,
            error,
            onEditStep: handleEditStep
          }
        ) : null
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden whitespace-nowrap text-xs text-slate-500 md:col-start-7 md:block", children: expiryValue ? formatRelativeTime$1(expiryValue) : "—" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "hidden whitespace-nowrap text-xs text-slate-500 md:col-start-8 md:block", children: item.last_used_at ? formatRelativeTime$1(item.last_used_at) : "—" }),
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
        formatRelativeTime$1(item.requestedExpiresAt)
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
  const handleRequestSubmitted = reactExports.useCallback((requestId) => {
    setRequestOpen(false);
    setReloadToken((current) => current + 1);
    if (requestId?.trim()) {
      setScopeFilter("all");
      setActionFilter("all");
      setSelectedExceptionId(null);
    }
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
const POLICY_SUMMARY_CARD_CLASS = "rounded-2xl border border-slate-200/80 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04),0_8px_20px_rgba(15,23,42,0.04)]";
function PolicyActiveModeCard({ snapshot }) {
  const modeCopy = resolveSecurityModeCopy(snapshot.security_level);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_SUMMARY_CARD_CLASS} self-start p-4`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active mode" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-start gap-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: modeCopy.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 line-clamp-3 text-sm leading-snug text-slate-600", children: modeCopy.description })
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
    if (normalized.length <= 12) {
      return value;
    }
    return `sha256:${normalized.slice(0, 6)}…${normalized.slice(-4)}`;
  }
  if (normalized.length <= 16) {
    return normalized;
  }
  return `${normalized.slice(0, 8)}…${normalized.slice(-4)}`;
}
function resolveCloudBundleStatusSubtitle(copy) {
  if (copy.tone === "green") {
    return "All policies up to date";
  }
  if (copy.tone === "attention") {
    return "Sync needs attention";
  }
  return copy.label;
}
function CloudBundleHeader({ cloudControlsUrl }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-x-3 gap-y-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
    cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
      "Open Guard Cloud"
    ] }) : null
  ] });
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
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_SUMMARY_CARD_CLASS} self-start p-4`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(CloudBundleHeader, { cloudControlsUrl }),
      cloudConnected ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-medium text-brand-dark", children: snapshot.cloud_state_label?.trim() || "Connected to Guard Cloud" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-brand-dark/75", children: snapshot.cloud_state_detail?.trim() || "Guard Cloud is connected. Policy bundle details will appear after the next successful sync." })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-brand-dark/75", children: "Guard Cloud is not connected. Remembered Cloud rules appear when Guard Cloud syncs a bundle." })
    ] });
  }
  const synced = cloudBundleCopy.tone === "green";
  const statusSubtitle = resolveCloudBundleStatusSubtitle(cloudBundleCopy);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_SUMMARY_CARD_CLASS} self-start p-4`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(CloudBundleHeader, { cloudControlsUrl }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-start sm:gap-x-8 sm:gap-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyStatField, { label: "Status", className: "sm:min-w-[7.5rem] sm:max-w-[9rem]", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5", children: [
        synced ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 shrink-0 text-emerald-600", "aria-hidden": "true" }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: synced ? "green" : "amber", children: synced ? "Synced" : cloudBundleCopy.label })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyStatField, { label: "Bundle hash", className: "min-w-0 flex-1 sm:min-w-[10rem]", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: "min-w-0 font-mono text-sm text-brand-dark break-all sm:break-normal sm:truncate",
            title: policyHash ?? void 0,
            children: policyHashDisplay
          }
        ),
        policyHash ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: handleCopyHash,
            className: "shrink-0 rounded-md p-0.5 text-slate-400 hover:bg-slate-100 hover:text-brand-dark",
            "aria-label": "Copy bundle hash",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
          }
        ) : null
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(PolicyStatField, { label: "Last ack", className: "sm:min-w-[6.5rem] sm:max-w-[9rem]", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: lastAckAt ? formatRelativeTime$1(lastAckAt) : "Not yet" }),
        bundleVersion ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 truncate text-xs text-slate-500", title: bundleVersion, children: bundleVersion }) : null
      ] })
    ] }),
    synced ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-slate-500", children: statusSubtitle }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 rounded-xl border border-amber-200/80 bg-amber-50/60 px-3 py-2 text-sm leading-snug text-slate-700", children: cloudBundleCopy.detail })
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
    /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceTableCell, { className: "hidden w-[104px] whitespace-nowrap text-xs text-slate-500 lg:table-cell", children: policy.updated_at ? formatRelativeTime$1(policy.updated_at) : "—" }),
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
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1.55fr)_minmax(10rem,1fr)] lg:items-start", children: [
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
const POLICY_PANEL_CARD_CLASS = "rounded-2xl border border-slate-200/80 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04),0_10px_28px_rgba(15,23,42,0.05)]";
const STRICT_CONFIG_EVALUATION_STEPS = [
  {
    label: "Local rule",
    description: "If a remembered local rule matches, apply it.",
    icon: HiMiniQueueList,
    surfaceClass: "border-violet-200 bg-violet-50",
    iconClass: "text-violet-600"
  },
  {
    label: "Cloud policy",
    description: "Then apply the signed Cloud policy bundle.",
    icon: HiMiniCloud,
    surfaceClass: "border-sky-200 bg-sky-50",
    iconClass: "text-sky-600"
  },
  {
    label: "Cloud exception",
    description: "Matching Cloud exception allows the action.",
    icon: HiMiniCloud,
    surfaceClass: "border-cyan-200 bg-cyan-50",
    iconClass: "text-cyan-700"
  },
  {
    label: "Strict fallback",
    description: "If nothing allows it, this strict config is used.",
    icon: HiMiniShieldCheck,
    surfaceClass: "border-amber-200 bg-amber-50",
    iconClass: "text-amber-700"
  },
  {
    label: "Ask or block",
    description: "Guard asks (or blocks) according to your choice.",
    icon: HiMiniNoSymbol,
    surfaceClass: "border-rose-200 bg-rose-50",
    iconClass: "text-rose-600"
  }
];
const STRICT_CONFIG_WHAT_CHANGES = [
  "First-time actions follow your default strict action.",
  "Changed tool hashes trigger your configured review path.",
  "New network domains and subprocesses use strict fallback rules."
];
const STRICT_CONFIG_SCENARIOS = [
  { id: "first-time", label: "New tool contacting unknown domain" },
  { id: "remembered-allow", label: "Remembered allow wins" },
  { id: "cloud-exception", label: "Active Cloud exception" }
];
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
function resolveStrictScenarioSimulation(settings, scenarioId) {
  const fallbackAction = settings.new_network_domain_action ?? settings.default_action ?? "review";
  if (scenarioId === "remembered-allow") {
    return simulateStrictPolicyOutcome({
      rememberedRuleAction: "allow",
      cloudPolicyAction: "none",
      cloudExceptionActive: false,
      fallbackAction
    });
  }
  if (scenarioId === "cloud-exception") {
    return simulateStrictPolicyOutcome({
      rememberedRuleAction: "none",
      cloudPolicyAction: "none",
      cloudExceptionActive: true,
      fallbackAction
    });
  }
  return simulateStrictPolicyOutcome({
    rememberedRuleAction: "none",
    cloudPolicyAction: "none",
    cloudExceptionActive: false,
    fallbackAction
  });
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
function PolicyEnforcementPreviewCard({ cloudControlsUrl }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_PANEL_CARD_CLASS} p-4`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local enforcement preview" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-sm leading-relaxed text-slate-600", children: "Evaluation order when Guard decides what to do next." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 -mx-1 overflow-x-auto px-1 pb-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-w-[52rem] items-stretch", children: STRICT_CONFIG_EVALUATION_STEPS.map((step, index) => {
      const Icon = step.icon;
      const isLast = index === STRICT_CONFIG_EVALUATION_STEPS.length - 1;
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(reactExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex min-w-[9.75rem] flex-1 flex-col rounded-xl border p-3 ${step.surfaceClass}`, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `flex h-8 w-8 items-center justify-center rounded-lg bg-white/80 ${step.iconClass}`, children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: step.label }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: step.description })
        ] }),
        !isLast ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex w-7 shrink-0 items-center justify-center", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "h-4 w-4 text-slate-300" }) }) : null
      ] }, step.label);
    }) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-col gap-3 border-t border-slate-100 pt-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "max-w-xl text-xs leading-relaxed text-slate-500", children: [
        "Evaluation order: ",
        STRICT_POLICY_EVALUATION_ORDER.join(" → "),
        ". Team-wide exceptions are managed in Guard Cloud."
      ] }),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
        "Open Guard Cloud",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "ml-1.5 h-4 w-4", "aria-hidden": "true" })
      ] }) }) : null
    ] })
  ] });
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 py-4 first:pt-0 last:pb-0 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center lg:gap-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-start gap-3", children: [
      Icon ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }) }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: label }),
        help ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-relaxed text-slate-500", children: help }) : null
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full max-w-[17.5rem] lg:justify-self-end", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "div",
        {
          className: "flex w-full flex-wrap gap-0.5 rounded-xl border border-slate-200 bg-slate-100/80 p-0.5",
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
                className: `rounded-lg px-2.5 py-1 text-xs font-medium transition ${selected ? "bg-brand-blue text-white shadow-sm" : "text-slate-600 hover:bg-white/70 hover:text-brand-dark disabled:opacity-50"}`,
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
function PolicyInfoBanner({ children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-slate-200/80 bg-slate-50 px-3 py-2.5 text-xs leading-relaxed text-slate-600", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children })
  ] });
}
function PolicyLocalStrictPolicyCard({
  settings,
  controlsDisabled,
  saveError,
  savingKey,
  onResetDefaults,
  onSettingChange
}) {
  const fileWriteAction = resolveStrictFileWriteAction(settings);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_PANEL_CARD_CLASS} p-4`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local strict policy" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: onResetDefaults,
          disabled: controlsDisabled,
          className: "inline-flex shrink-0 items-center gap-1.5 text-sm font-medium text-brand-blue hover:underline disabled:opacity-50",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "h-4 w-4", "aria-hidden": "true" }),
            "Reset to defaults"
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 divide-y divide-slate-100", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        StrictConfigActionSegmented,
        {
          label: "Default action",
          help: "For any action not explicitly allowed.",
          icon: HiMiniBolt,
          value: settings.default_action,
          settingKey: "default_action",
          onSettingChange,
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
          onSettingChange,
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
          onSettingChange,
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
          onSettingChange,
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
          onSettingChange,
          disabled: controlsDisabled
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyInfoBanner, { children: "These settings apply only when no local or Cloud rules cover the action." }) }),
    saveError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-red-600", children: saveError }) : null,
    savingKey ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-sm text-slate-500", children: [
      "Saving ",
      savingKey.replace(/_/g, " "),
      "…"
    ] }) : null
  ] });
}
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
function PolicyStrictConfigRightRail({
  pendingInboxCount,
  cloudControlsUrl,
  scenarioId,
  expectedAction,
  expectedReasoning,
  simulationVisible,
  simulation,
  onOpenInbox,
  onScenarioChange,
  onRunSimulation
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "min-w-0 space-y-4 xl:sticky xl:top-6 xl:self-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_PANEL_CARD_CLASS} p-4`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What this changes" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 space-y-2.5 text-sm leading-relaxed text-slate-600", children: STRICT_CONFIG_WHAT_CHANGES.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-emerald-600", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: item })
      ] }, item)) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_PANEL_CARD_CLASS} p-4`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Affected pending Inbox items" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-4xl font-semibold tabular-nums text-brand-blue", children: [
        pendingInboxCount,
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1.5 text-lg font-medium text-brand-blue/75", children: "Items" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-slate-600", children: "Pending review items may be affected by stricter fallback controls." }),
      onOpenInbox && pendingInboxCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onOpenInbox, children: [
        "Open Inbox",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "ml-1.5 h-4 w-4", "aria-hidden": "true" })
      ] }) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_PANEL_CARD_CLASS} p-4 text-sm leading-relaxed text-slate-600`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: "Cloud exceptions still apply" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: "Signed Cloud exceptions still require bundle acknowledgement before they apply locally." }),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: cloudControlsUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline",
          children: [
            "Learn more",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
          ]
        }
      ) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_PANEL_CARD_CLASS} border-brand-blue/15 bg-brand-blue/[0.03] p-4`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBeaker, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Test policy" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-slate-600", children: "Simulate how Guard will respond." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 block space-y-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Scenario" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "select",
          {
            value: scenarioId,
            onChange: onScenarioChange,
            className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
            children: STRICT_CONFIG_SCENARIOS.map((scenario) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: scenario.id, children: scenario.label }, scenario.id))
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 space-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Expected action" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: resolveExpectedActionTone(expectedAction), children: policyActionLabel(expectedAction) }),
        expectedReasoning ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-relaxed text-slate-600", children: expectedReasoning }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onRunSimulation, children: [
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
  ] });
}
function PolicyStrictModeCard({
  isStrict,
  controlsDisabled,
  localPolicyHash,
  daemonAckSynced,
  daemonAckLabel,
  lastAckAt,
  lastReloadFormatted,
  lastReloadAt,
  reloadingPolicy,
  onStrictToggle,
  onCopyHash,
  onOpenSettings,
  onReloadPolicy
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${POLICY_PANEL_CARD_CLASS} p-4`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: "Strict mode" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-600", children: "Local enforcement tuning" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: isStrict ? "Enabled" : "Disabled" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            role: "switch",
            "aria-checked": isStrict,
            "aria-label": "Toggle strict mode",
            disabled: controlsDisabled,
            onClick: onStrictToggle,
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
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-3 border-t border-slate-100 pt-3 sm:grid-cols-2 lg:grid-cols-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Strict mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1.5 text-sm font-medium text-brand-dark", children: isStrict ? "Enabled" : "Disabled" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Policy hash" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5 flex min-w-0 items-center gap-1.5 font-mono text-sm text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", title: localPolicyHash ?? void 0, children: localPolicyHash }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: onCopyHash,
              className: "shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark",
              "aria-label": "Copy policy hash",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { className: "h-4 w-4", "aria-hidden": "true" })
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Daemon ack" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1.5 flex items-center gap-1.5 text-sm text-brand-dark", children: [
          daemonAckSynced ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-emerald-600", "aria-hidden": "true" }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            daemonAckLabel,
            lastAckAt ? ` · ${formatRelativeTime$1(lastAckAt)}` : ""
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-wider text-slate-500", children: "Last reload" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1.5 text-sm text-brand-dark", children: lastReloadFormatted ?? (lastReloadAt ? formatRelativeTime$1(lastReloadAt) : "Unavailable") }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 flex items-center gap-1 text-xs text-emerald-700", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 shrink-0", "aria-hidden": "true" }),
          "Auto-reload on"
        ] })
      ] })
    ] }),
    !isStrict && onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 border-t border-slate-100 pt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Enable in Settings" }) }) : null,
    onReloadPolicy ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex justify-end border-t border-slate-100 pt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onReloadPolicy, disabled: reloadingPolicy, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: `mr-1.5 h-4 w-4 ${reloadingPolicy ? "animate-spin" : ""}`, "aria-hidden": "true" }),
      "Reload policy"
    ] }) }) : null
  ] });
}
function isUnauthorizedError(error) {
  return /HTTP Error 401|unauthorized/i.test(error.trim());
}
function humanizeStrictConfigError(error) {
  if (isUnauthorizedError(error)) {
    return {
      title: "Guard Cloud authorization expired",
      body: "Local remembered rules and strict config still apply on this device. Run connect again to refresh signed access."
    };
  }
  return {
    title: "Could not load strict config",
    body: error || "Try again from Settings if the daemon is unavailable."
  };
}
function PolicyStrictConfigTab({
  snapshot,
  cloudControlsUrl = null,
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
    if (!settings || !simulationVisible) {
      return null;
    }
    return resolveStrictScenarioSimulation(settings, scenarioId);
  }, [settings, scenarioId, simulationVisible]);
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
    setScenarioId(event.target.value);
    setSimulationVisible(false);
  }, []);
  if (loadState === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", "aria-busy": "true", children: [0, 1, 2].map((index) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-24 animate-pulse rounded-2xl border border-slate-200 bg-slate-100" }, index)) });
  }
  if (loadState === "error" || !settings) {
    const is401 = loadError !== null && isUnauthorizedError(loadError);
    const humanized = loadError !== null ? humanizeStrictConfigError(loadError) : { title: "Could not load strict config", body: "Try again from Settings if the daemon is unavailable." };
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: humanized.title,
        body: humanized.body,
        action: is401 && cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "a",
          {
            href: cloudControlsUrl,
            className: "inline-flex items-center gap-2 rounded-xl bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90 focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
            children: "Connect Guard Cloud"
          }
        ) : void 0
      }
    );
  }
  const controlsDisabled = savingKey !== null;
  const lastReloadAt = snapshot.runtime_state?.started_at ?? snapshot.generated_at ?? null;
  const lastReloadFormatted = formatPolicyDateTime(lastReloadAt);
  const lastAckAt = snapshot.cloud_policy_last_ack_at?.trim() ?? null;
  const daemonAckSynced = cloudBundleCopy?.tone === "green";
  const daemonAckLabel = daemonAckSynced ? "Acknowledged" : cloudBundleCopy?.label ?? "Needs attention";
  const expectedAction = scenarioOutcome?.outcome ?? settings.new_network_domain_action ?? "review";
  const expectedReasoning = scenarioOutcome?.reasoning ?? "";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 xl:grid-cols-[minmax(0,1fr)_280px] xl:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyStrictModeCard,
        {
          isStrict,
          controlsDisabled,
          localPolicyHash,
          daemonAckSynced,
          daemonAckLabel,
          lastAckAt,
          lastReloadFormatted,
          lastReloadAt,
          reloadingPolicy,
          onStrictToggle: handleStrictToggle,
          onCopyHash: handleCopyHash,
          onOpenSettings,
          onReloadPolicy
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyLocalStrictPolicyCard,
        {
          settings,
          controlsDisabled,
          saveError,
          savingKey,
          onResetDefaults: handleResetDefaults,
          onSettingChange: handleStrictConfigChange
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyEnforcementPreviewCard, { cloudControlsUrl })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyStrictConfigRightRail,
      {
        pendingInboxCount,
        cloudControlsUrl,
        scenarioId,
        expectedAction,
        expectedReasoning,
        simulationVisible,
        simulation,
        onOpenInbox,
        onScenarioChange: handleScenarioChange,
        onRunSimulation: handleRunSimulation
      }
    )
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
      cloudControlsUrl: resolveCloudPolicyControlsUrl(snapshot),
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
