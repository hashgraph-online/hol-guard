import { j as jsxRuntimeExports, S as SectionLabel, o as HiMiniXMark, B as Badge, bd as scopeLabel, m as formatRelativeTime, b6 as HiMiniCloudArrowUp, r as reactExports, be as createCloudExceptionRequest, A as ActionButton, h as harnessDisplayName, b as EmptyState, p as HiMiniChevronUp, q as HiMiniChevronDown, ac as Tag, bf as fetchCloudExceptions, bg as fetchCloudExceptionRequests, Y as fetchSettings, _ as updateSettings, bh as policyActionLabel } from "../guard-dashboard.js";
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
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: display })
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
    return { label: "Synced", detail: "This device acknowledged the signed policy bundle." };
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
function PolicyCloudExceptionDetailPanel({
  exception,
  cloudControlsUrl,
  onClose
}) {
  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(exception);
  const expiryValue = resolveCloudExceptionExpiryValue(exception);
  const ackCopy = resolveAckCopy(exception);
  const headline = resolveCloudExceptionHeadline(exception);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "aside",
    {
      className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm",
      "aria-label": "Cloud exception details",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Exception detail" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1 text-lg font-semibold text-brand-dark", children: headline })
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
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: exception.effect }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: scopeLabel(exception.scope) }),
          isCloudExceptionAckFailure(exception) ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: ackCopy.label }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(PersonRow, { label: "Owner", value: exception.owner }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(PersonRow, { label: "Approved by", value: exception.approver }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            DetailField,
            {
              label: "Expiry",
              value: expiryTimestamp && expiryValue ? `${expiryTimestamp.toLocaleString()} (${formatRelativeTime(expiryValue)})` : expiryValue
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DetailField, { label: "Harness", value: exception.harness }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DetailField, { label: "Source receipt", value: exception.source_receipt_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DetailField, { label: "Signed bundle hash", value: exception.bundle_hash }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            DetailField,
            {
              label: "Last used",
              value: exception.last_used_at ? formatRelativeTime(exception.last_used_at) : null
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Local daemon acknowledgement" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: ackCopy.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: ackCopy.detail }),
            isCloudExceptionAckFailure(exception) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-slate-500", children: "Run Guard sync to retry bundle acknowledgement." }) : null
          ] })
        ] }),
        cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "a",
          {
            href: cloudControlsUrl,
            target: "_blank",
            rel: "noopener noreferrer",
            className: "inline-flex items-center gap-1.5 text-sm font-medium text-brand-blue hover:underline",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-4 w-4", "aria-hidden": "true" }),
              "Open in Guard Cloud"
            ]
          }
        ) }) : null
      ]
    }
  );
}
const SCOPE_VALUES = ["artifact", "publisher", "harness", "workspace"];
const SCOPE_OPTIONS = [
  {
    value: "artifact",
    label: "One specific action",
    description: "Limit the exception to a single artifact fingerprint."
  },
  {
    value: "publisher",
    label: "Publisher",
    description: "Apply to packages or plugins from one publisher."
  },
  {
    value: "harness",
    label: "App",
    description: "Apply across one harness such as Codex or Cursor."
  },
  {
    value: "workspace",
    label: "Project",
    description: "Apply within the current project folder on this device."
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
function parseScopeValue(value) {
  if (SCOPE_VALUES.includes(value)) {
    return value;
  }
  return null;
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
  const [submitting, setSubmitting] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [successMessage, setSuccessMessage] = reactExports.useState(null);
  const handleScopeChange = reactExports.useCallback((event) => {
    const nextScope = parseScopeValue(event.target.value);
    if (nextScope) {
      setScope(nextScope);
    }
  }, []);
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
        reason: reason.trim(),
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
      harness,
      owner,
      publisher,
      reason,
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
  if (receiptOptions.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Request cloud exception" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Guard needs at least one receipt on this device to anchor a Cloud exception request. Run a protected action first, then return here from Evidence or Inbox." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onCancel, children: "Back" }) })
    ] });
  }
  if (successMessage) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-2xl border border-emerald-200 bg-emerald-50/60 p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Request submitted" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-emerald-800", children: successMessage }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: handleDone, children: "Done" })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { className: "space-y-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", onSubmit: handleSubmit, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Request cloud exception" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Submit a governed risk acceptance to Guard Cloud. This does not create a local remembered rule." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Source receipt" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
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
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Scope" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("select", { className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm", value: scope, onChange: handleScopeChange, children: SCOPE_OPTIONS.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: SCOPE_OPTIONS.find((option) => option.value === scope)?.description })
    ] }),
    scope === "artifact" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Artifact fingerprint" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
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
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
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
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
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
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: workingDirectory,
          onChange: handleWorkingDirectoryChange,
          required: true
        }
      )
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
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
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Risk owner" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          type: "email",
          value: owner,
          onChange: handleOwnerChange,
          required: true
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Reason" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "textarea",
        {
          className: "min-h-24 w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          value: reason,
          onChange: handleReasonChange,
          required: true
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Expires" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          className: "w-full rounded-xl border border-slate-200 px-3 py-2 text-sm",
          type: "datetime-local",
          value: toDatetimeLocalValue(requestedExpiresAt),
          onChange: handleExpiryChange,
          required: true
        }
      )
    ] }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-red-600", children: error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", type: "submit", disabled: submitting, children: submitting ? "Submitting…" : "Submit to Guard Cloud" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", type: "button", onClick: onCancel, disabled: submitting, children: "Cancel" })
    ] })
  ] });
}
function GroupSection({ title, description, defaultOpen = true, children }) {
  const [open, setOpen] = reactExports.useState(defaultOpen);
  const handleToggle = reactExports.useCallback(() => {
    setOpen((current) => !current);
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: handleToggle,
        className: "flex w-full items-start justify-between gap-3 px-4 py-3 text-left",
        "aria-expanded": open,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-500", children: description })
          ] }),
          open ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" })
        ]
      }
    ),
    open ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2 border-t border-slate-100 px-3 py-3", children }) : null
  ] });
}
function ExceptionCard({
  item,
  selected,
  onSelect
}) {
  const handleSelect = reactExports.useCallback(() => {
    onSelect(item);
  }, [item, onSelect]);
  const expiryTimestamp = resolveCloudExceptionExpiryTimestamp(item);
  const expiryValue = resolveCloudExceptionExpiryValue(item);
  const headline = resolveCloudExceptionHeadline(item);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleSelect,
      "aria-pressed": selected,
      className: `w-full rounded-xl border px-3.5 py-3 text-left transition ${selected ? "border-brand-blue/30 bg-brand-blue/[0.04] ring-1 ring-brand-blue/20" : "border-slate-100 bg-white hover:border-brand-blue/20 hover:bg-brand-blue/[0.02]"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: item.effect }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: scopeLabel(item.scope) }),
          isCloudExceptionAckFailure(item) ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: "Ack issue" }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: headline }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-500", children: [
          "Owner ",
          resolvePersonDisplayLabel(item.owner),
          expiryTimestamp && expiryValue ? ` · expires ${formatRelativeTime(expiryValue)}` : null
        ] })
      ]
    }
  );
}
function PendingRequestCard({ item }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-xl border border-amber-100 bg-amber-50/40 px-3.5 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "warning", children: "Pending" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: scopeLabel(item.scope) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-semibold text-brand-dark", children: item.reason }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
      "Requested by ",
      resolvePersonDisplayLabel(item.owner),
      " · expires",
      " ",
      formatRelativeTime(item.requestedExpiresAt)
    ] })
  ] });
}
function PolicyCloudExceptionsList({
  active,
  pending,
  expiringSoon,
  selectedExceptionId,
  onSelectException,
  cloudConnected
}) {
  const expiringSoonIds = reactExports.useMemo(() => new Set(expiringSoon.map((item) => item.id)), [expiringSoon]);
  const activeWithoutExpiringGroup = reactExports.useMemo(
    () => active.filter((item) => !expiringSoonIds.has(item.id)),
    [active, expiringSoonIds]
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", role: "list", "aria-label": "Cloud exception groups", children: [
    activeWithoutExpiringGroup.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      GroupSection,
      {
        title: "Active on this device",
        description: "Synced Cloud risk acceptances currently enforced locally.",
        defaultOpen: true,
        children: activeWithoutExpiringGroup.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ExceptionCard,
          {
            item,
            selected: selectedExceptionId === item.id,
            onSelect: onSelectException
          },
          item.id
        ))
      }
    ) : null,
    pending.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      GroupSection,
      {
        title: "Pending in Guard Cloud",
        description: "Requests waiting for Cloud approval before they can sync to this device.",
        defaultOpen: true,
        children: pending.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(PendingRequestCard, { item }, item.requestId))
      }
    ) : null,
    expiringSoon.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      GroupSection,
      {
        title: "Expiring soon",
        description: "Active acceptances nearing expiry. Renew or revoke them in Guard Cloud.",
        defaultOpen: true,
        children: expiringSoon.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ExceptionCard,
          {
            item,
            selected: selectedExceptionId === item.id,
            onSelect: onSelectException
          },
          `expiring-${item.id}`
        ))
      }
    ) : null
  ] });
}
const SUMMARY_TONE_CLASSES = {
  blue: "text-brand-blue",
  amber: "text-amber-700",
  attention: "text-brand-attention",
  slate: "text-brand-dark"
};
function SummaryCard({
  label,
  value,
  tone = "slate"
}) {
  const toneClass = SUMMARY_TONE_CLASSES[tone];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200/70 bg-white p-3 text-center shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `text-2xl font-semibold tabular-nums ${toneClass}`, children: value }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground", children: label })
  ] });
}
function SummarySkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 gap-3 md:grid-cols-4", children: [0, 1, 2, 3].map((index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "h-[72px] animate-pulse rounded-xl border border-slate-200/70 bg-slate-100",
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
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Active synced", value: activeCount, tone: "blue" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Pending approval", value: pendingCount, tone: "amber" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Expiring soon", value: expiringSoonCount, tone: "attention" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SummaryCard, { label: "Local ack failures", value: ackFailureCount, tone: "attention" })
      ]
    }
  );
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
      label: "Strict mode",
      description: "Guard asks before most actions including new network connections and file writes. Higher noise, maximum protection.",
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
  if (syncError) {
    return {
      label: `Cloud bundle ${bundleVersion}`,
      detail: `Guard Cloud Controls owns rollout and authoring. Latest sync issue: ${syncError}.`,
      tone: "attention"
    };
  }
  return {
    label: `Cloud bundle ${bundleVersion}`,
    detail: `Guard Cloud Controls owns authoring and rollout. This local workspace reflects rollout state ${rollout}.`,
    tone: "green"
  };
}
function resolveCloudExceptionsConnected(snapshot) {
  return snapshot.cloud_state === "paired_active" || snapshot.cloud_state === "paired_waiting";
}
function PolicyCloudExceptionsTab({
  snapshot
}) {
  const [requestOpen, setRequestOpen] = reactExports.useState(false);
  const [loadState, setLoadState] = reactExports.useState("loading");
  const [loadError, setLoadError] = reactExports.useState(null);
  const [exceptions, setExceptions] = reactExports.useState([]);
  const [pendingRequests, setPendingRequests] = reactExports.useState([]);
  const [selectedExceptionId, setSelectedExceptionId] = reactExports.useState(null);
  const [reloadToken, setReloadToken] = reactExports.useState(0);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const connectUrl = snapshot.connect_url?.trim() || null;
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
  const handleOpenRequestPanel = reactExports.useCallback(() => {
    setRequestOpen(true);
  }, []);
  const handleCloseRequestPanel = reactExports.useCallback(() => {
    setRequestOpen(false);
  }, []);
  const handleRequestSubmitted = reactExports.useCallback(() => {
    setRequestOpen(false);
    setReloadToken((current) => current + 1);
  }, []);
  const handleRetryLoad = reactExports.useCallback(() => {
    setReloadToken((current) => current + 1);
  }, []);
  const handleSelectException = reactExports.useCallback((exception) => {
    setSelectedExceptionId(exception.id);
  }, []);
  const handleCloseDetail = reactExports.useCallback(() => {
    setSelectedExceptionId(null);
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
  if (requestOpen) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyCloudExceptionRequestPanel,
      {
        snapshot,
        onSubmitted: handleRequestSubmitted,
        onCancel: handleCloseRequestPanel
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Cloud risk acceptances" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: "Cloud exceptions are governed risk acceptances with an owner, approver, reason, expiry, and signed bundle. They are managed in Guard Cloud and synced to this device after approval." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Fast remembered approvals from Review stay on the Remembered rules tab. They are separate from Cloud exceptions." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ActionButton,
        {
          variant: "primary",
          onClick: handleOpenRequestPanel,
          disabled: !cloudConnected,
          children: "Request cloud exception"
        }
      ),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: cloudControlsUrl, variant: "secondary", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
        "Open Guard Cloud"
      ] }) : null,
      !cloudConnected && connectUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: connectUrl, variant: "secondary", children: "Connect Guard Cloud" }) : null
    ] }),
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
        body: loadError ?? "Try again after Guard Cloud sync completes.",
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
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-start", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          PolicyCloudExceptionsList,
          {
            active: groups.active,
            pending: groups.pending,
            expiringSoon: groups.expiringSoon,
            selectedExceptionId,
            onSelectException: handleSelectException,
            cloudConnected
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
  ] });
}
const STRICT_POLICY_LAYER_OPTIONS = [
  { value: "none", label: "No match" },
  { value: "allow", label: "Allow" },
  { value: "block", label: "Block" }
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
  path.push("Ask or block → review/block");
  return {
    outcome: input.fallbackAction === "block" ? "block" : "review",
    winningStep: "Ask or block",
    path
  };
}
function StrictConfigSelect({ label, value, onChange, disabled = false, help }) {
  const handleChange = reactExports.useCallback(
    (event) => {
      onChange(event.target.value);
    },
    [onChange]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: label }),
    help ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-xs text-slate-500", children: help }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "select",
      {
        value,
        onChange: handleChange,
        disabled,
        className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark disabled:cursor-not-allowed disabled:bg-slate-50",
        children: STRICT_CONFIG_ACTION_OPTIONS.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value))
      }
    )
  ] });
}
function SimLayerSelect({ label, value, onChange }) {
  const handleChange = reactExports.useCallback(
    (event) => {
      const nextValue = event.target.value;
      if (nextValue === "allow" || nextValue === "block" || nextValue === "none") {
        onChange(nextValue);
      }
    },
    [onChange]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block space-y-1.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "select",
      {
        value,
        onChange: handleChange,
        className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark",
        children: STRICT_POLICY_LAYER_OPTIONS.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value))
      }
    )
  ] });
}
function PolicyStrictConfigTab({
  snapshot,
  onOpenSettings,
  onOpenInbox
}) {
  const [loadState, setLoadState] = reactExports.useState("loading");
  const [loadError, setLoadError] = reactExports.useState(null);
  const [settings, setSettings] = reactExports.useState(null);
  const [configPath, setConfigPath] = reactExports.useState(null);
  const [saveError, setSaveError] = reactExports.useState(null);
  const [savingKey, setSavingKey] = reactExports.useState(null);
  const [simRemembered, setSimRemembered] = reactExports.useState("none");
  const [simCloudPolicy, setSimCloudPolicy] = reactExports.useState("none");
  const [simCloudException, setSimCloudException] = reactExports.useState(false);
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
      setConfigPath(payload.config_path);
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
    setSavingKey(key);
    setSaveError(null);
    const nextSettings = key === "destructive_shell" ? {
      risk_actions: {
        ...settings.risk_actions,
        destructive_shell: value
      }
    } : { [key]: value };
    try {
      const payload = await updateSettings(nextSettings);
      setSettings(payload.settings);
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : "Unable to save strict config.");
    } finally {
      setSavingKey(null);
    }
  }, [settings]);
  const handleDefaultActionChange = reactExports.useCallback(
    (value) => {
      void persistSetting("default_action", value);
    },
    [persistSetting]
  );
  const handleChangedHashActionChange = reactExports.useCallback(
    (value) => {
      void persistSetting("changed_hash_action", value);
    },
    [persistSetting]
  );
  const handleNetworkActionChange = reactExports.useCallback(
    (value) => {
      void persistSetting("new_network_domain_action", value);
    },
    [persistSetting]
  );
  const handleSubprocessActionChange = reactExports.useCallback(
    (value) => {
      void persistSetting("subprocess_action", value);
    },
    [persistSetting]
  );
  const handleFileWriteActionChange = reactExports.useCallback(
    (value) => {
      void persistSetting("destructive_shell", value);
    },
    [persistSetting]
  );
  const handleSimCloudExceptionChange = reactExports.useCallback((event) => {
    setSimCloudException(event.target.checked);
  }, []);
  const handleSimRememberedChange = reactExports.useCallback((value) => {
    setSimRemembered(value);
  }, []);
  const handleSimCloudPolicyChange = reactExports.useCallback((value) => {
    setSimCloudPolicy(value);
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Strict mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStrict ? "green" : "slate", children: isStrict ? "Enabled" : "Disabled" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: "Strict config tunes local fallback enforcement only. Authentication, MFA, and general Guard settings stay in Settings." }),
      !isStrict && onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Enable strict mode in Settings" }) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local policy state" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 grid gap-3 text-sm sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Local policy hash" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 font-mono text-xs text-brand-dark", children: localPolicyHash })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Config file" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-all text-brand-dark", children: configPath ?? "Unavailable" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Daemon last reload" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-brand-dark", children: snapshot.runtime_state?.started_at ? formatRelativeTime(snapshot.runtime_state.started_at) : "Unavailable" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Daemon heartbeat" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-brand-dark", children: snapshot.runtime_state?.last_heartbeat_at ? formatRelativeTime(snapshot.runtime_state.last_heartbeat_at) : "Unavailable" })
        ] })
      ] }),
      cloudBundleCopy ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-xl border border-slate-100 bg-slate-50/80 p-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium uppercase tracking-wide text-slate-500", children: "Signed Cloud bundle ack" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: cloudBundleCopy.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: cloudBundleCopy.detail }),
        snapshot.cloud_policy_bundle_hash ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 break-all font-mono text-[11px] text-slate-500", children: snapshot.cloud_policy_bundle_hash }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-slate-500", children: "Cloud exceptions apply through signed bundle acknowledgement on this device." })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm text-slate-600", children: "No signed Cloud policy bundle is synced yet. Cloud exceptions still require bundle acknowledgement before they apply locally." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local fallback controls" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "These controls apply when no remembered rule, Cloud policy, or Cloud exception matches." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 grid gap-4 md:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          StrictConfigSelect,
          {
            label: "Default action",
            help: "First-time actions with no prior decision.",
            value: settings.default_action,
            onChange: handleDefaultActionChange,
            disabled: controlsDisabled
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          StrictConfigSelect,
          {
            label: "Changed tool hash action",
            value: settings.changed_hash_action,
            onChange: handleChangedHashActionChange,
            disabled: controlsDisabled
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          StrictConfigSelect,
          {
            label: "New network domain action",
            value: settings.new_network_domain_action,
            onChange: handleNetworkActionChange,
            disabled: controlsDisabled
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          StrictConfigSelect,
          {
            label: "Subprocess action",
            value: settings.subprocess_action,
            onChange: handleSubprocessActionChange,
            disabled: controlsDisabled
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          StrictConfigSelect,
          {
            label: "Destructive file write action",
            help: "Backed by the destructive shell risk control.",
            value: fileWriteAction,
            onChange: handleFileWriteActionChange,
            disabled: controlsDisabled
          }
        )
      ] }),
      saveError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-red-600", children: saveError }) : null,
      savingKey ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-sm text-slate-500", children: [
        "Saving ",
        savingKey.replace(/_/g, " "),
        "…"
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Pending Inbox impact" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-dark/75", children: pendingInboxCount > 0 ? `${pendingInboxCount} pending review item${pendingInboxCount === 1 ? "" : "s"} may be affected by stricter fallback controls.` : "No pending Inbox items are waiting for review right now." }),
      onOpenInbox && pendingInboxCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenInbox, children: "Open Inbox" }) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Evaluation order" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "mt-3 space-y-2 text-sm text-brand-dark/80", children: STRICT_POLICY_EVALUATION_ORDER.map((step, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-semibold text-brand-blue", children: [
          index + 1,
          "."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: step })
      ] }, step)) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Policy simulator" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: "Preview which layer wins for a hypothetical action without changing live policy." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 grid gap-3 md:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SimLayerSelect, { label: "Remembered rule", value: simRemembered, onChange: handleSimRememberedChange }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SimLayerSelect, { label: "Cloud policy", value: simCloudPolicy, onChange: handleSimCloudPolicyChange }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "checkbox", checked: simCloudException, onChange: handleSimCloudExceptionChange }),
          "Active Cloud exception"
        ] })
      ] }),
      simulation ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-xl border border-slate-100 bg-white p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
          "Outcome: ",
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
function resolvePolicyViewLabel(view) {
  if (view === "rules") {
    return "Remembered rules";
  }
  if (view === "exceptions") {
    return "Cloud exceptions";
  }
  return "Strict config";
}
function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox
}) {
  const [activeView, setActiveView] = reactExports.useState("rules");
  const handleViewChange = reactExports.useCallback((view) => {
    setActiveView(view);
  }, []);
  const handleOpenCloudExceptions = reactExports.useCallback(() => {
    setActiveView("exceptions");
  }, []);
  const modeCopy = reactExports.useMemo(() => resolveSecurityModeCopy(snapshot.security_level), [snapshot.security_level]);
  const cloudBundleCopy = reactExports.useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    cloudBundleCopy ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: resolveCloudBundleSurfaceClass(cloudBundleCopy.tone), children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: cloudBundleCopy.tone, children: cloudBundleCopy.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: cloudBundleCopy.detail })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: modeCopy.tone, children: modeCopy.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: modeCopy.description }),
      onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Open security settings" }) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2 border-b border-slate-100 pb-3", children: ["rules", "exceptions", "strict"].map((view) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: () => handleViewChange(view),
        "aria-pressed": activeView === view,
        className: `rounded-full px-4 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${activeView === view ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
        children: resolvePolicyViewLabel(view)
      },
      view
    )) }),
    activeView === "rules" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyRememberedRulesTab,
      {
        policies,
        cloudControlsUrl: resolveCloudPolicyControlsUrl(snapshot),
        onClearPolicy,
        onOpenCloudExceptions: handleOpenCloudExceptions
      }
    ) : null,
    activeView === "exceptions" ? /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyCloudExceptionsTab, { snapshot }) : null,
    activeView === "strict" ? /* @__PURE__ */ jsxRuntimeExports.jsx(PolicyStrictConfigTab, { snapshot, onOpenSettings, onOpenInbox }) : null
  ] });
}
export {
  PolicyWorkspace,
  groupPoliciesByHarness,
  resolveCloudPolicyBundleCopy,
  resolvePolicyViewLabel,
  resolveSecurityModeCopy
};
